# Kali-SOC-Compliance-CLI-Framework-
<img width="1024" height="1024" alt="IMG_1936" src="https://github.com/user-attachments/assets/4e7a06ab-f531-4df6-8744-8dd0d97ffb58" />

Complete custom Kali CLI SOC Framework

🛡️ Kali SOC Compliance Framework — Custom Automated SOC Analyst Toolkit

A modular Bash + Python framework for ATT&CK simulations, log generation, lab automation, detection testing, and reporting. This repo supports lab exercises and the SOC Analyst Roadmap, enabling repeatable simulations and verification.

Features
- MITRE ATT&CK Integration — Simulate techniques mapped to roadmap labs.
- Log Generation & Analysis — Produce realistic execution, network, and auth events for SIEM/ELK practice.
- Lab Automation — Bootstrap environments tied to roadmap sections.
- Rich Reporting — Track progress across Core Skills → Advanced Blue Team.
- Extensible — Add new modules and plugins with a simple manifest format.
- Secure Ingest — TLS and optional mTLS support for endpoint ingestion.

Installation (lab)
1. Clone:
   git clone https://github.com/wkt21-0/Kali-CLI-SOC-Framework.git
   cd Kali-CLI-SOC-Framework

2. Make scripts executable and install:
   chmod +x scripts/*.sh
   # Install dependencies (create venv recommended)
   python3 -m venv venv
   venv/bin/pip install -r requirements.txt

3. Run server locally (lab):
   export INGEST_API_KEY="lab-secret"
   # Self-signed cert for lab: generate soc_cert.pem / soc_key.pem, then:
   uvicorn ops.ingest.server:app --host 0.0.0.0 --port 5514 --ssl-certfile ./soc_cert.pem --ssl-keyfile ./soc_key.pem

Usage (examples)
- soc --help
- soc attack simulate T1059
- soc logs generate execution
- soc report generate soc-operations
- python -m core.engine status

Project Structure (high-level)
- bin/ — Main CLI wrappers
- core/ — Engine, CLI router, module glue
- ops/ — Operational modules (ingest, threatintel, detection, alerts, dashboard)
- agent/ — Endpoint agent and transport code
- scripts/ — Helper scripts (cert generation, setup)
- config/ — Mappings & configuration (soc.yaml, rbac.yaml, compliance.yaml)
- system/ — systemd units, hardening scripts
- deployment/ — nginx/certbot snippets and deployment notes

Roadmap Alignment
Every command links back to roadmap lab sections and ATT&CK mappings to help SOC analysts progress through practical exercises.

Security & Notes
- Do NOT commit private keys or secrets to this repository.
- Use the scripts/generate_mtls_certs.sh script for local CA and cert creation, then distribute client certs securely.
- For production: use nginx + certbot + mTLS, and set REQUIRE_MTLS=true for the ingest server.
---
#!/usr/bin/env bash
set -euo pipefail

# create_and_commit_mtls_bundle.sh
# Usage:
#   ./create_and_commit_mtls_bundle.sh        # create files and commit locally
#   DO_PUSH=1 ./create_and_commit_mtls_bundle.sh   # also push to origin/main
#
# Review the files after running and before pushing if desired.

ROOT=$(pwd)
echo "[*] Creating mTLS tooling, tests, CI, and deployment files in: $ROOT"

# Helper to write files
write_file() {
  local path="$1"; shift
  local content="$@"
  mkdir -p "$(dirname "$path")"
  cat > "$path" <<'EOF'
'"$content"'
EOF
}

# We will use a different approach to ensure correct here-doc delimiting.
# Define files using cat <<'FILE' > path ... FILE blocks below.

###############################################################################
# core/engine.py
###############################################################################
mkdir -p core
cat > core/engine.py <<'PY' 
#!/usr/bin/env python3
"""
Minimal SOC engine CLI: loads config, registers core.modules.* commands,
parses args, and calls handler functions provided by modules.
"""
import argparse
import importlib
import logging
from pathlib import Path
import yaml

DEFAULT_CONFIG = Path("config/soc.yaml")

def load_config(path: Path = DEFAULT_CONFIG):
    if not path.exists():
        return {}
    try:
        with path.open() as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

def setup_logging(level_str: str = "INFO"):
    level = getattr(logging, level_str.upper(), logging.INFO)
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")

def discover_and_register_modules(subparsers):
    modules = [
        "mitre",
        "loggen",
        "sigma",
        "siem",
        "compliance",
        "reporting",
        "dashboard",
        "integrity",
        "plugins",
        "threatintel",
    ]
    for mod in modules:
        full = f"core.modules.{mod}"
        try:
            m = importlib.import_module(full)
            if hasattr(m, "register"):
                m.register(subparsers)
            else:
                logging.debug("module %s has no register()", full)
        except ModuleNotFoundError:
            logging.debug("module not found: %s", full)
        except Exception as e:
            logging.warning("error loading module %s: %s", full, e)

def main(argv=None):
    cfg = load_config()
    engine_cfg = cfg.get("engine", {})
    log_level = engine_cfg.get("log_level", "INFO")
    setup_logging(log_level)

    parser = argparse.ArgumentParser(prog="soc", description="Kali SOC Framework")
    sub = parser.add_subparsers(dest="command")

    discover_and_register_modules(sub)

    # provide a simple default status command
    def handle_status(args):
        print("Kali SOC Compliance Framework — status")
        print(f"Mode: {engine_cfg.get('mode', 'unknown')}")
        print(f"Log path: {cfg.get('paths', {}).get('logs', 'data/logs')}")

    status = sub.add_parser("status", help="Show engine status")
    status.set_defaults(handler=handle_status)

    args = parser.parse_args(argv)

    if not hasattr(args, "handler"):
        parser.print_help()
        return 2

    try:
        return args.handler(args) or 0
    except Exception as e:
        logging.exception("command failed: %s", e)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
PY

chmod +x core/engine.py

###############################################################################
# core/security/rbac.py
###############################################################################
mkdir -p core/security
cat > core/security/rbac.py <<'PY'
"""
Minimal RBAC manager used by tests and CLI checks.
Loads config/rbac.yaml and exposes simple checks.
"""
from pathlib import Path
import yaml

RBAC_FILE = Path("config/rbac.yaml")

class RBACManager:
    _roles = {}

    @classmethod
    def load_roles(cls, path: Path = RBAC_FILE):
        if not path.exists():
            cls._roles = {}
            return cls._roles
        data = yaml.safe_load(path.read_text()) or {}
        cls._roles = data.get("roles", {})
        return cls._roles

    @classmethod
    def check(cls, role: str, permission: str) -> bool:
        if not cls._roles:
            cls.load_roles()
        role_obj = cls._roles.get(role)
        if not role_obj:
            return False
        allowed = role_obj.get("allowed", [])
        if "all" in allowed:
            return True
        return permission in allowed
PY

###############################################################################
# .gitignore
###############################################################################
cat > .gitignore <<'TXT'
# Virtual env
venv/
.env

# Python caches
__pycache__/
*.py[cod]
*.so

# Pytest cache
.pytest_cache/

# Coverage
.coverage
htmlcov/

# Build artifacts
build/
dist/
*.egg-info/

# Editor files
.vscode/
.idea/
*.swp
.DS_Store

# Data directories (do not commit runtime artifacts)
data/logs/*
data/output/*
data/reports/*
data/integrity/*
data/cache/*

# Packaging
build/
TXT

###############################################################################
# ops/ingest/server.py (updated with client_identity logging)
###############################################################################
mkdir -p ops/ingest
cat > ops/ingest/server.py <<'PY'
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
    for ev in payload:
        if client_identity:
            ev["_client_identity"] = client_identity

    try:
        _atomic_append_json_list(ENDPOINT_FILE, payload)
        logger.info("Ingested %d events (client=%s)", len(payload), client_identity or "none")

        # Optionally also write a lightweight detection entry for unknown clients
        # or map client identity to detections. This is a simple append to data/output/detections.json
        if client_identity:
            try:
                det_dir = Path("data/output")
                det_dir.mkdir(parents=True, exist_ok=True)
                det_file = det_dir / "detections.json"
                detections = []
                if det_file.exists():
                    detections = json.loads(det_file.read_text())
                detections.append({"type": "ingest_client", "client": client_identity, "count": len(payload)})
                det_file.write_text(json.dumps(detections, indent=2))
            except Exception:
                logger.exception("Failed to write detection mapping for client_identity")
    except Exception as e:
        logger.exception("Failed to persist events: %s", e)
        raise HTTPException(status_code=500, detail="Failed to persist events")
    return {"received": len(payload)}
PY

###############################################################################
# agent/transport/send.py
###############################################################################
mkdir -p agent/transport
cat > agent/transport/send.py <<'PY'
#!/usr/bin/env python3
"""
Secure agent transport for sending events to the SOC ingest server.

Configuration via environment variables:
- SOC_INGEST_URL (e.g. https://soc.example.com:5514/ingest)
- SOC_API_KEY      (the API key to put in X-API-Key header)
- SOC_VERIFY_CERT  (optional; path to CA bundle or "false" to skip verification - NOT recommended)
- SOC_CLIENT_CERT  (optional; path to client cert PEM for mTLS)
- SOC_CLIENT_KEY   (optional; path to client key PEM for mTLS)
"""
import os
import json
import requests
from requests.adapters import HTTPAdapter, Retry

DEFAULT_TIMEOUT = 5  # seconds

SOC_INGEST_URL_ENV = "SOC_INGEST_URL"
SOC_API_KEY_ENV = "SOC_API_KEY"
SOC_VERIFY_CERT_ENV = "SOC_VERIFY_CERT"
SOC_CLIENT_CERT_ENV = "SOC_CLIENT_CERT"
SOC_CLIENT_KEY_ENV = "SOC_CLIENT_KEY"

def _build_session():
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

def send_event(event: dict):
    url = os.getenv(SOC_INGEST_URL_ENV)
    api_key = os.getenv(SOC_API_KEY_ENV)
    verify = os.getenv(SOC_VERIFY_CERT_ENV, "true")
    client_cert = os.getenv(SOC_CLIENT_CERT_ENV)
    client_key = os.getenv(SOC_CLIENT_KEY_ENV)

    if not url or not api_key:
        raise RuntimeError("SOC_INGEST_URL and SOC_API_KEY must be set in environment")

    # allow explicit 'false' (case-insensitive) to disable cert verification (use only in lab)
    if verify.lower() in ("false", "0", "no"):
        verify_val = False
    else:
        verify_val = True if verify.lower() in ("true", "1", "yes") else verify

    cert = None
    if client_cert and client_key:
        cert = (client_cert, client_key)

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }

    s = _build_session()
    try:
        resp = s.post(url, headers=headers, data=json.dumps(event), timeout=DEFAULT_TIMEOUT, verify=verify_val, cert=cert)
        resp.raise_for_status()
        return resp
    except requests.RequestException as e:
        print(f"[Agent] Failed to send event: {e}")
        raise
PY
chmod +x agent/transport/send.py

###############################################################################
# system/systemd/soc-ingest.service and env
###############################################################################
mkdir -p system/systemd
cat > system/systemd/soc-ingest.service <<'UNIT'
[Unit]
Description=Kali SOC Ingest Server
After=network.target

[Service]
User=soc
Group=soc
EnvironmentFile=/etc/default/soc-ingest
ExecStart=/usr/bin/env uvicorn ops.ingest.server:app --host 0.0.0.0 --port 5514 --ssl-certfile /etc/ssl/certs/soc_cert.pem --ssl-keyfile /etc/ssl/private/soc_key.pem --workers 4
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

cat > system/systemd/soc-ingest.env <<'ENV'
# Environment variables for soc-ingest systemd service
# DO NOT store real secrets in the repository. Replace with secure values on the host.
INGEST_API_KEY="REPLACE_WITH_SECURE_KEY"
ENV

###############################################################################
# deployment/nginx/soc_ingest_mtls.conf
###############################################################################
mkdir -p deployment/nginx
cat > deployment/nginx/soc_ingest_mtls.conf <<'NGINX'
# Nginx site configuration for SOC ingest API with mTLS
# Place at /etc/nginx/sites-available/soc_ingest and symlink to sites-enabled
# Replace soc.example.com with your domain and ensure the certificate paths below exist.

server {
    listen 80;
    server_name soc.example.com;

    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soc.example.com;

    # Server certificate (Let's Encrypt or your CA)
    ssl_certificate /etc/letsencrypt/live/soc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # mTLS: CA for client cert verification
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;
    # Optional: CRL
    # ssl_crl /etc/nginx/ssl/crl.pem;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    # Proxy settings to local uvicorn
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Forward mTLS verification and client cert to backend (if you want app-level checks)
        proxy_set_header X-SSL-CLIENT-VERIFY $ssl_client_verify;
        proxy_set_header X-SSL-CLIENT-CERT $ssl_client_escaped_cert;
        proxy_set_header X-SSL-CLIENT-S-DN $ssl_client_s_dn;

        # timeouts & buffering
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_buffering on;
        proxy_buffers 16 4k;

        client_max_body_size 10M;
    }
}
NGINX

###############################################################################
# scripts/generate_mtls_certs.sh
###############################################################################
mkdir -p scripts
cat > scripts/generate_mtls_certs.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
# scripts/generate_mtls_certs.sh
# Usage:
#   ./scripts/generate_mtls_certs.sh --domain soc.example.com --outdir ./certs --client-name agent-01
# IMPORTANT: Keep the resulting private keys safe. Do NOT commit them.

DOMAIN=""
OUTDIR="./certs"
CLIENT_NAME="agent-01"
DAYS=3650

while [[ $# -gt 0 ]]; do
  case $1 in
    --domain) DOMAIN="$2"; shift 2;;
    --outdir) OUTDIR="$2"; shift 2;;
    --client-name) CLIENT_NAME="$2"; shift 2;;
    --days) DAYS="$2"; shift 2;;
    *) echo "Unknown: $1"; exit 1;;
  esac
done

if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 --domain soc.example.com [--outdir ./certs] [--client-name agent-01]"
  exit 1
fi

mkdir -p "$OUTDIR"
cd "$OUTDIR"

echo "[*] Generating CA (private key and cert)"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days $DAYS -subj "/CN=${DOMAIN}-CA" -out ca.crt

echo "[*] Generating server key and CSR"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=${DOMAIN}" -out server.csr

cat > server_ext.cnf <<EOF
basicConstraints=CA:FALSE
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
IP.1 = 127.0.0.1
EOF

echo "[*] Signing server certificate with CA"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days $DAYS -sha256 -extfile server_ext.cnf

echo "[*] Generating client key and CSR"
openssl genrsa -out ${CLIENT_NAME}.key 2048
openssl req -new -key ${CLIENT_NAME}.key -subj "/CN=${CLIENT_NAME}" -out ${CLIENT_NAME}.csr

cat > client_ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${CLIENT_NAME}
EOF

echo "[*] Signing client certificate with CA"
openssl x509 -req -in ${CLIENT_NAME}.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out ${CLIENT_NAME}.crt -days $DAYS -sha256 -extfile client_ext.cnf

echo "[*] Generating PKCS#12 bundle for the client (optional, for easier distribution)"
openssl pkcs12 -export -out ${CLIENT_NAME}.p12 -inkey ${CLIENT_NAME}.key -in ${CLIENT_NAME}.crt -certfile ca.crt -password pass:

echo "Files created in $(pwd):"
ls -l server.crt server.key ca.crt ${CLIENT_NAME}.crt ${CLIENT_NAME}.key ${CLIENT_NAME}.p12
SH
chmod +x scripts/generate_mtls_certs.sh

###############################################################################
# deployment/docker files
###############################################################################
mkdir -p deployment/docker
cat > deployment/docker/Dockerfile.app <<'DF'
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir uvicorn fastapi pydantic
EXPOSE 8000
CMD ["uvicorn", "ops.ingest.server:app", "--host", "0.0.0.0", "--port", "8000"]
DF

cat > deployment/docker/nginx.conf <<'NG'
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;

    location / {
        proxy_pass http://app:8000;
        proxy_set_header X-SSL-CLIENT-VERIFY $ssl_client_verify;
        proxy_set_header X-SSL-CLIENT-CERT $ssl_client_escaped_cert;
        proxy_set_header X-SSL-CLIENT-S-DN $ssl_client_s_dn;
        proxy_set_header X-API-Key $http_x_api_key;
        proxy_set_header Host $host;
    }
}
NG

cat > deployment/docker/docker-compose.mtls.yml <<'YC'
version: '3.7'
services:
  app:
    build:
      context: ../..
      dockerfile: deployment/docker/Dockerfile.app
    environment:
      - INGEST_API_KEY=lab-secret
      - REQUIRE_MTLS=true
    networks:
      - socnet

  nginx:
    image: nginx:stable
    ports:
      - "5514:443"
    volumes:
      - ../../deployment/docker/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ../../certs:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - socnet

networks:
  socnet:
    driver: bridge
YC

###############################################################################
# scripts/run_mtls_e2e.sh
###############################################################################
cat > scripts/run_mtls_e2e.sh <<'E2E'
#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/run_mtls_e2e.sh --domain soc.test --client agent-01
DOMAIN=${DOMAIN:-soc.test}
CLIENT=${CLIENT:-agent-01}
CERT_DIR=${CERT_DIR:-./certs}
COMPOSE_FILE=deployment/docker/docker-compose.mtls.yml

# 1) Generate certs (CA, server, client)
echo "[*] Generating certs in ${CERT_DIR}..."
./scripts/generate_mtls_certs.sh --domain "$DOMAIN" --outdir "$CERT_DIR" --client-name "$CLIENT"

# 2) Start docker-compose
echo "[*] Starting docker-compose..."
docker-compose -f "$COMPOSE_FILE" up -d --build

# Wait for services to be ready
echo "[*] Waiting for services..."
sleep 5

# 3) Test with curl using client cert (trust CA)
CA_CERT="$CERT_DIR/ca.crt"
CLIENT_CERT="$CERT_DIR/${CLIENT}.crt"
CLIENT_KEY="$CERT_DIR/${CLIENT}.key"

echo "[*] Running curl test (should succeed)..."
curl --fail --silent --show-error --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
  -H "X-API-Key: lab-secret" \
  -d '{"type":"e2e-test","msg":"hello"}' \
  https://localhost:5514/ingest | jq .

echo
echo "[*] Attempting request without client cert (should fail)..."
set +e
curl --fail --silent --show-error --cacert "$CA_CERT" \
  -H "X-API-Key: lab-secret" \
  -d '{"type":"e2e-test","msg":"no-client"}' \
  https://localhost:5514/ingest && echo "Unexpected success" || echo "Expected failure"
set -e

# 4) Teardown
echo "[*] Tearing down..."
docker-compose -f "$COMPOSE_FILE" down
E2E
chmod +x scripts/run_mtls_e2e.sh

###############################################################################
# scripts/rotate_certs.sh
###############################################################################
cat > scripts/rotate_certs.sh <<'ROT'
#!/usr/bin/env bash
set -euo pipefail
# scripts/rotate_certs.sh
# Rotate server and client certificates signed by a local CA located in CERT_DIR (default ./certs)
# Usage: ./scripts/rotate_certs.sh --outdir ./certs --clients agent-01,agent-02 --days 365

OUTDIR="./certs"
CLIENTS=""
DAYS=365

while [[ $# -gt 0 ]]; do
  case $1 in
    --outdir) OUTDIR="$2"; shift 2;;
    --clients) CLIENTS="$2"; shift 2;;
    --days) DAYS="$2"; shift 2;;
    *) echo "Unknown: $1"; exit 1;;
  esac
done

mkdir -p "$OUTDIR"
cd "$OUTDIR"

if [ ! -f ca.key ] || [ ! -f ca.crt ]; then
  echo "CA (ca.key / ca.crt) not found in $OUTDIR. Use scripts/generate_mtls_certs.sh first or provide a CA." >&2
  exit 1
fi

# Rotate server cert
if [ -f server.key ]; then
  echo "[*] Reissuing server certificate"
  openssl req -new -key server.key -subj "/CN=$(hostname -f)" -out server.csr
else
  echo "[*] Generating new server key and CSR"
  openssl genrsa -out server.key 2048
  openssl req -new -key server.key -subj "/CN=$(hostname -f)" -out server.csr
fi

cat > server_ext.cnf <<EOF
basicConstraints=CA:FALSE
subjectAltName = @alt_names

[alt_names]
DNS.1 = $(hostname -f)
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days $DAYS -sha256 -extfile server_ext.cnf

echo "[*] Server certificate rotated: server.crt (days=$DAYS)"

# Rotate client certs if provided
if [ -n "$CLIENTS" ]; then
  IFS=',' read -ra NAMES <<< "$CLIENTS"
  for name in "${NAMES[@]}"; do
    if [ -f ${name}.key ]; then
      echo "[*] Reissuing client certificate for ${name}"
      openssl req -new -key ${name}.key -subj "/CN=${name}" -out ${name}.csr
    else
      echo "[*] Generating new key for ${name}"
      openssl genrsa -out ${name}.key 2048
      openssl req -new -key ${name}.key -subj "/CN=${name}" -out ${name}.csr
    fi

    cat > client_ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${name}
EOF

    openssl x509 -req -in ${name}.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out ${name}.crt -days $DAYS -sha256 -extfile client_ext.cnf
    echo "[*] Client cert rotated for ${name}: ${name}.crt"
  done
fi

echo "Certificate rotation complete. Ensure you securely distribute client certs and install server.crt/server.key on the server."
ROT
chmod +x scripts/rotate_certs.sh

###############################################################################
# scripts/create_release_tarball.sh and scripts/build_release.sh and ci_run
###############################################################################
cat > scripts/create_release_tarball.sh <<'CR'
#!/usr/bin/env bash
set -euo pipefail
OUT=release_mtls_bundle.tar.gz

FILES=(
  "ops/ingest/server.py"
  "scripts/generate_mtls_certs.sh"
  "scripts/run_mtls_e2e.sh"
  "scripts/rotate_certs.sh"
  "deployment/docker/Dockerfile.app"
  "deployment/docker/nginx.conf"
  "deployment/docker/docker-compose.mtls.yml"
  "tests/ingest/test_ingest.py"
  "README.md"
)

tar -czf "$OUT" "${FILES[@]}"
echo "Created $OUT"
CR
chmod +x scripts/create_release_tarball.sh

cat > scripts/build_release.sh <<'BR'
#!/usr/bin/env bash
set -euo pipefail
# convenience script to build the release tarball
chmod +x scripts/generate_mtls_certs.sh scripts/run_mtls_e2e.sh scripts/rotate_certs.sh scripts/create_release_tarball.sh
./scripts/create_release_tarball.sh
echo "Release bundle created: release_mtls_bundle.tar.gz"
BR
chmod +x scripts/build_release.sh

cat > scripts/ci_run.sh <<'CI'
#!/usr/bin/env bash
# convenience script for CI to run pytest and (optionally) the docker e2e locally
set -euo pipefail

echo "Running pytest..."
pytest -q

if [ "${RUN_E2E:-false}" = "true" ]; then
  echo "Running docker e2e..."
  ./scripts/run_mtls_e2e.sh --client agent-01
fi
CI
chmod +x scripts/ci_run.sh

###############################################################################
# tests/ingest/test_ingest.py
###############################################################################
mkdir -p tests/ingest
cat > tests/ingest/test_ingest.py <<'TT'
import os
import json
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from ops.ingest import server as ingest_server

CLIENT = TestClient(ingest_server.app)

@pytest.fixture(autouse=True)
def clear_env(monkeypatch, tmp_path):
    # default API key for tests
    monkeypatch.setenv("INGEST_API_KEY", "lab-secret")
    monkeypatch.setenv("REQUIRE_MTLS", "false")
    # point endpoint file to temp path
    tmp_file = tmp_path / "endpoint.json"
    ingest_server.ENDPOINT_FILE = tmp_file
    if tmp_file.exists():
        tmp_file.unlink()
    return tmp_file

def read_events(path: Path):
    if not path.exists():
        return []
    return json.loads(path.read_text())

def test_ingest_success_no_mtls(clear_env):
    hdr = {"X-API-Key": "lab-secret", "Content-Type": "application/json"}
    resp = CLIENT.post("/ingest", headers=hdr, json={"type": "test", "msg": "hello"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["received"] == 1
    evs = read_events(ingest_server.ENDPOINT_FILE)
    assert len(evs) == 1
    assert evs[0]["type"] == "test"

def test_ingest_fail_bad_api_key(clear_env):
    hdr = {"X-API-Key": "wrong", "Content-Type": "application/json"}
    resp = CLIENT.post("/ingest", headers=hdr, json={"type": "test"})
    assert resp.status_code == 401

def test_ingest_require_mtls_success(clear_env, monkeypatch):
    monkeypatch.setenv("REQUIRE_MTLS", "true")
    hdr = {
        "X-API-Key": "lab-secret",
        "X-SSL-CLIENT-VERIFY": "SUCCESS",
        "X-SSL-CLIENT-S-DN": "CN=agent-01,OU=Agents,O=Example",
        "Content-Type": "application/json",
    }
    resp = CLIENT.post("/ingest", headers=hdr, json={"type": "proc", "name": "cmd"})
    assert resp.status_code == 200
    evs = read_events(ingest_server.ENDPOINT_FILE)
    assert evs and evs[-1].get("_client_identity") == "agent-01"

def test_ingest_require_mtls_fail_missing_verify(clear_env, monkeypatch):
    monkeypatch.setenv("REQUIRE_MTLS", "true")
    hdr = {
        "X-API-Key": "lab-secret",
        # missing X-SSL-CLIENT-VERIFY -> should fail
        "X-SSL-CLIENT-S-DN": "CN=agent-01,OU=Agents",
        "Content-Type": "application/json",
    }
    resp = CLIENT.post("/ingest", headers=hdr, json={"type": "proc"})
    assert resp.status_code == 403
TT

###############################################################################
# .github workflows: tests.yml and docker-e2e.yml
###############################################################################
mkdir -p .github/workflows
cat > .github/workflows/tests.yml <<'YML'
name: Tests
on:
  push:
    branches: [ "main" ]
  pull_request:

jobs:
  tests:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest fastapi uvicorn httpx

      - name: Run tests
        run: pytest -q
YML

cat > .github/workflows/docker-e2e.yml <<'Y2'
name: Docker E2E
on:
  workflow_dispatch:

jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v2

      - name: Build and run docker-compose stack and run E2E script
        run: |
          # Build and start the E2E stack
          docker-compose -f deployment/docker/docker-compose.mtls.yml up -d --build
          # Give services time to start
          sleep 10
          # Run the e2e script inside the runner
          chmod +x scripts/run_mtls_e2e.sh
          ./scripts/run_mtls_e2e.sh --domain soc.test --client agent-01
        env:
          DOMAIN: soc.test
          CLIENT: agent-01

      - name: Teardown
        if: always()
        run: |
          docker-compose -f deployment/docker/docker-compose.mtls.yml down
Y2

###############################################################################
# README.md
###############################################################################
cat > README.md <<'RD'
# Kali-SOC-Compliance-CLI-Framework-

Complete custom Kali CLI SOC Framework

🛡️ Kali SOC Compliance Framework — Custom Automated SOC Analyst Toolkit

# A modular Bash + Python framework for ATT&CK simulations, log generation, lab automation, detection testing, and reporting. This repo supports lab exercises and the SOC Analyst Roadmap, enabling repeatable simulations and verification.

# Features
- MITRE ATT&CK Integration — Simulate techniques mapped to roadmap labs.
- Log Generation & Analysis — Produce realistic execution, network, and auth events for SIEM/ELK practice.
- Lab Automation — Bootstrap environments tied to roadmap sections.
- Rich Reporting — Track progress across Core Skills → Advanced Blue Team.
- Extensible — Add new modules and plugins with a simple manifest format.
- Secure Ingest — TLS and optional mTLS support for endpoint ingestion.

# Installation (lab)
1. Clone:
   git clone https://github.com/wkt21-0/Kali-CLI-SOC-Framework.git
   cd Kali-CLI-SOC-Framework

2. Make scripts executable and install:
   chmod +x scripts/*.sh
   # Install dependencies (create venv recommended)
   python3 -m venv venv
   venv/bin/pip install -r requirements.txt

3. Run server locally (lab):
   
   export INGEST_API_KEY="lab-secret"
   # Self-signed cert for lab: generate soc_cert.pem / soc_key.pem, then:
   uvicorn ops.ingest.server:app --host 0.0.0.0 --port 5514 --ssl-certfile ./soc_cert.pem --ssl-keyfile ./soc_key.pem

# Usage (examples)
- soc --help
- soc attack simulate T1059
- soc logs generate execution
- soc report generate soc-operations
- python -m core.engine status

# Project Structure (high-level)
- bin/ — Main CLI wrappers
- core/ — Engine, CLI router, module glue
- ops/ — Operational modules (ingest, threatintel, detection, alerts, dashboard)
- agent/ — Endpoint agent and transport code
- scripts/ — Helper scripts (cert generation, setup)
- config/ — Mappings & configuration (soc.yaml, rbac.yaml, compliance.yaml)
- system/ — systemd units, hardening scripts
- deployment/ — nginx/certbot snippets and deployment notes

# Roadmap Alignment
Every command links back to roadmap lab sections and ATT&CK mappings to help SOC analysts progress through practical exercises.

# Security & Notes
- Do NOT commit private keys or secrets to this repository.
- Use the scripts/generate_mtls_certs.sh script for local CA and cert creation, then distribute client certs securely.
- For production: use nginx + certbot + mTLS, and set REQUIRE_MTLS=true for the ingest server.
RD

###############################################################################
# Finalize: git add, commit, optional push
###############################################################################
echo "[*] Files created. Preparing git commit..."

git add -A

COMMIT_MSG="Add mTLS tooling, CI workflows, tests, and deployment scripts
- mTLS cert generation and rotation scripts
- nginx mTLS config and Docker E2E stack
- FastAPI ingest server updated for client identity logging
- pytest tests and GitHub Actions workflows
- release tarball builder and helper scripts"

git commit -m "$COMMIT_MSG" || {
  echo "[!] Nothing to commit (or commit failed)."
}

if [ "${DO_PUSH:-0}" = "1" ]; then
  echo "[*] Pushing to origin/main..."
  git push origin main
else
  echo "[*] Commit created locally. To push, run: git push origin main"
fi

echo "[*] Make scripts executable (if not already):"
echo "  chmod +x scripts/*.sh"
echo
echo "Done."

How to run

Save the script in your repo root:
nano create_and_commit_mtls_bundle.sh (paste contents)

Make executable:
chmod +x create_and_commit_mtls_bundle.sh
Run (commit only):

./create_and_commit_mtls_bundle.sh
Or run and push (if you have push rights and want automatic push):

DO_PUSH=1 ./create_and_commit_mtls_bundle.sh
After running

Review the new files (git status, git diff HEAD~1).

If you pushed, check GitHub for the new commit and CI runs.

Run tests locally: python -m venv venv; venv/bin/pip install -r requirements.txt pytest fastapi uvicorn httpx; venv/bin/pytest -q

To run Docker E2E locally: ensure Docker & docker-compose are installed, then 
chmod +x scripts/run_mtls_e2e.sh; ./scripts/run_mtls_e2e.sh --domain soc.test --client agent-01
