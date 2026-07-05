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
