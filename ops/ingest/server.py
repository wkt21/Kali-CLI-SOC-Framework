#!/usr/bin/env python3
"""
FastAPI ingestion server for endpoint agent events.

- API key required in X-API-Key header (value comes from INGEST_API_KEY env var)
- If REQUIRE_MTLS env var is "true", the server will enforce nginx-verified client certs
  by checking X-SSL-CLIENT-VERIFY header and will extract a sanitized client CN from
  X-SSL-CLIENT-S-DN (if present).
- Atomic writes to data/logs/endpoint.json to avoid partial writes.
"""
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Extra
from typing import List, Union, Optional, Any
from pathlib import Path
import os
import hmac
import json
import logging
import tempfile
import re

LOG_DIR = Path("data/logs")
ENDPOINT_FILE = LOG_DIR / "endpoint.json"
API_KEY_ENV = "INGEST_API_KEY"
REQUIRE_MTLS_ENV = "REQUIRE_MTLS"  # if "true", enforce header verification

app = FastAPI(title="SOC Ingest API", version="0.3.0")
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


def _atomic_append_json_list(path: Path, items: List[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
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
    timestamp = None
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
