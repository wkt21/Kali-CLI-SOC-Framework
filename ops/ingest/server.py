# Ingest Server — Auth Model & Trust Boundary

`ops/ingest/server.py` accepts endpoint/agent events at `POST /ingest`. Two
layers of auth apply, in order:

1. **API key** — `X-API-Key` header must match the `INGEST_API_KEY`
   environment variable, compared in constant time. An unset or empty
   `INGEST_API_KEY` is treated as "not configured" and rejects every
   request, rather than risking an empty key matching an empty header.

2. **mTLS (optional, `REQUIRE_MTLS=true`)** — the request must carry:

   ```
   X-SSL-Client-Verify: SUCCESS
   X-SSL-Client-S-DN: CN=<client-cn>,OU=...,O=...
   ```

   The CN is extracted from the subject DN and stored on each ingested
   event as `_client_identity`.

## ⚠️ Read this before enabling `REQUIRE_MTLS`

`X-SSL-Client-Verify` and `X-SSL-Client-S-DN` are **ordinary HTTP headers**.
This server does not terminate TLS or verify client certificates itself —
it trusts that something in front of it already did, and set these headers
from that real verification.

That trust is only valid if **both** of the following hold:

- A reverse proxy (e.g. nginx) terminates client-cert TLS and sets these
  headers unconditionally on every request it forwards:

  ```nginx
  proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
  proxy_set_header X-SSL-Client-S-DN    $ssl_client_s_dn;
  ```

  `proxy_set_header` always overwrites — it does not merge with or forward
  whatever the original client sent — so this is safe *as configured*.

- This process is **never reachable except through that proxy**. Bind it to
  `127.0.0.1` or a Unix socket, and firewall the port from anything else.

If either condition doesn't hold — most notably, if you're running the
"Local Setup" instructions from the top-level README (`uvicorn` directly
with `--ssl-certfile`/`--ssl-keyfile`, no nginx in front) — there is nothing
actually verifying client certificates, and anyone who can reach the port
can set `X-SSL-Client-Verify: SUCCESS` themselves and walk straight through
`REQUIRE_MTLS`.

### Defense in depth: `TRUSTED_PROXY_HOSTS`

An optional, **off by default**, source-address allowlist:

```bash
export TRUSTED_PROXY_HOSTS="10.0.0.5,10.0.0.6"
```

When set, a request claiming `REQUIRE_MTLS` success is also rejected
(`403`) unless it arrived from one of these hosts. This narrows the blast
radius if the network topology assumption above is ever violated, but it is
**not a substitute** for the two conditions above — it's the second layer,
not the first.

### Recommendation

Treat `TRUSTED_PROXY_HOSTS` as effectively mandatory whenever
`REQUIRE_MTLS=true` is used outside a fully trusted lab network, until the
"uvicorn directly, no proxy" deployment path is either removed or
explicitly documented as mTLS-incompatible.

## Other hardening in this implementation

- **Missing `return` statement (bug, now fixed)** — the version in the repo
  falls through its `try/except` on the happy path with no `return`,
  so FastAPI serializes the response as `null` instead of
  `{"received": N}`. This breaks `test_ingest_success_no_mtls`'s
  `data["received"] == 1` assertion outright. Fixed by adding
  `return {"received": len(payload)}`.
- **Read-modify-write race in `_atomic_append_json_list`** — the
  temp-file-then-`rename()` pattern is atomic for the write itself, but
  two concurrent requests could both read the same `existing` list before
  either writes, and the second writer's rename silently discards the
  first writer's event. Fixed with an `flock()`-based advisory lock on a
  sidecar `endpoint.json.lock` file, held for the whole
  read-modify-write, so concurrent agents don't lose events under load.
- **CN sanitization** (already present, worth calling out) — the extracted
  CN is passed through `re.sub(r"[^A-Za-z0-9_.-]", "_", cn)` before being
  stored, so a crafted certificate subject can't inject unexpected
  characters into stored event records. Good defensive habit, kept as-is.
- **`TRUSTED_PROXY_HOSTS`** (added, opt-in, off by default) — same
  defense-in-depth mechanism described above: when set, a request claiming
  `REQUIRE_MTLS` success is also rejected unless it arrived from an
  allow-listed source host.

## Testing note

This was validated by hand, line by line, against the actual
`ops/ingest/server.py` and `tests/ops/ingest/test_ingest.py` (header
casing, `CN=` extraction from the subject DN, `ENDPOINT_FILE` override via
`tmp_path`, env var timing via `monkeypatch`) — that review is what caught
the missing `return` statement above. It was **not executed**: the sandbox
this was written in has no network access to install `fastapi`/`httpx`/
`pytest`. Run the test suite locally before merging.



#!/usr/bin/env python3
"""
FastAPI ingestion server for endpoint agent events.

- API key required in X-API-Key header (value comes from INGEST_API_KEY env var)
- If REQUIRE_MTLS env var is "true", the server will enforce nginx-verified client certs
  by checking X-SSL-CLIENT-VERIFY header and will extract a sanitized client CN from
  X-SSL-CLIENT-S-DN (if present).
- Atomic writes to data/logs/endpoint.json to avoid partial writes.

CHANGES vs prior version:
  - Added the missing `return {"received": len(payload)}` on the happy path.
    Without it the endpoint returned `null`, which would fail
    tests/ops/ingest/test_ingest.py::test_ingest_success_no_mtls's
    `data["received"] == 1` assertion.
  - _atomic_append_json_list now takes an flock() over a sidecar .lock file
    around the read-modify-write. The temp-file+rename was already atomic
    for the write itself, but two concurrent requests could previously both
    read the same `existing` list and the second writer's rename would
    silently discard the first writer's event. The lock serializes the
    whole read-modify-write section so concurrent agents don't lose events.
  - Added optional TRUSTED_PROXY_HOSTS check (opt-in, off by default) as
    defense-in-depth for the REQUIRE_MTLS trust boundary: X-SSL-CLIENT-*
    are ordinary HTTP headers this process trusts at face value, which is
    only safe if a reverse proxy in front unconditionally overwrites them
    and this process is unreachable except through it. See
    docs/hardening/ingest.md.
"""
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Extra
from typing import List, Union, Optional, Any
from pathlib import Path
import os
import hmac
import json
import logging
import tempfile
import re
import fcntl
import contextlib

LOG_DIR = Path("data/logs")
ENDPOINT_FILE = LOG_DIR / "endpoint.json"
API_KEY_ENV = "INGEST_API_KEY"
REQUIRE_MTLS_ENV = "REQUIRE_MTLS"  # if "true", enforce header verification
TRUSTED_PROXY_HOSTS_ENV = "TRUSTED_PROXY_HOSTS"  # optional comma-separated allowlist

app = FastAPI(title="SOC Ingest API", version="0.3.1")
logger = logging.getLogger("uvicorn.error")


class Event(BaseModel, extra=Extra.allow):
    type: Optional[str] = None
    timestamp: Optional[str] = None
    pid: Optional[int] = None
    name: Optional[str] = None
    cmdline: Optional[Any] = None


def _get_expected_api_key() -> str:
    val = os.getenv(API_KEY_ENV)
    if not val:
        logger.warning("INGEST_API_KEY not set — server will reject requests without a matching key.")
        return ""
    return val


def _check_api_key(provided: str) -> bool:
    expected = _get_expected_api_key()
    if not expected:
        return False
    try:
        return hmac.compare_digest(provided.strip(), expected.strip())
    except Exception:
        return False


def _get_trusted_proxy_hosts() -> frozenset:
    raw = os.getenv(TRUSTED_PROXY_HOSTS_ENV, "")
    return frozenset(h.strip() for h in raw.split(",") if h.strip())


@contextlib.contextmanager
def _locked(lock_path: Path):
    """Advisory exclusive lock via flock() on a sidecar file, held for the
    duration of a read-modify-write against ENDPOINT_FILE. Blocks other
    ingest requests briefly rather than racing them."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _atomic_append_json_list(path: Path, items: List[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")

    with _locked(lock_path):
        existing = []
        if path.exists():
            try:
                existing = json.loads(path.read_text())
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []

        combined = existing + items
        with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent)) as tf:
            tf.write(json.dumps(combined, indent=2))
            temp_name = tf.name
        Path(temp_name).replace(path)


def _extract_cn_from_dn(dn: Optional[str]) -> Optional[str]:
    """
    Extract a sanitized Common Name (CN) from a DN string like:
    'CN=agent-01,OU=Agents,O=Example' -> 'agent-01'
    Returns None if no CN found.
    """
    if not dn:
        return None
    # match CN=... up to comma or end
    m = re.search(r"CN=([^,]+)", dn)
    if not m:
        return None
    cn = m.group(1).strip()
    # sanitize: allow alphanum, hyphen, underscore, dot
    cn = re.sub(r"[^A-Za-z0-9_.-]", "_", cn)
    return cn


@app.post("/ingest")
async def ingest(
    request: Request,
    events: Union[Event, List[Event]],
    x_api_key: Optional[str] = Header(None),
    x_ssl_client_verify: Optional[str] = Header(None),
    x_ssl_client_s_dn: Optional[str] = Header(None),
):
    # API key check
    if not x_api_key or not _check_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    # Optional mTLS enforcement
    require_mtls = os.getenv(REQUIRE_MTLS_ENV, "false").lower() in ("1", "true", "yes")
    client_identity = None
    if x_ssl_client_s_dn:
        client_identity = _extract_cn_from_dn(x_ssl_client_s_dn)

    if require_mtls:
        trusted_hosts = _get_trusted_proxy_hosts()
        if trusted_hosts:
            client_host = request.client.host if request.client else None
            if client_host not in trusted_hosts:
                logger.warning(
                    "mTLS required but request source %s is not in TRUSTED_PROXY_HOSTS", client_host
                )
                raise HTTPException(status_code=403, detail="request did not arrive via a trusted proxy")

        if (x_ssl_client_verify or "").upper() != "SUCCESS":
            logger.warning("mTLS required but client verification header not SUCCESS: %s", x_ssl_client_verify)
            raise HTTPException(status_code=403, detail="Client certificate verification required")
        if not client_identity:
            logger.warning("mTLS required but client DN not provided or not parsable: %s", x_ssl_client_s_dn)
            raise HTTPException(status_code=403, detail="Client certificate identity required")

    # normalize to list of dicts
    if isinstance(events, list):
        payload = [e.dict() for e in events]
    else:
        payload = [events.dict()]

    if not payload:
        raise HTTPException(status_code=400, detail="Empty payload")

    # augment events with client identity (if any)
    for ev in payload:
        if client_identity:
            ev["_client_identity"] = client_identity
        # preserve event ingestion time optionally
        # ev["_ingested_at"] = datetime.utcnow().isoformat()

    try:
        _atomic_append_json_list(ENDPOINT_FILE, payload)
        logger.info("Ingested %d events (client=%s)", len(payload), client_identity or "none")
    except Exception as e:
        logger.exception("Failed to persist events: %s", e)
        raise HTTPException(status_code=500, detail="Failed to persist events")

    return {"received": len(payload)}
