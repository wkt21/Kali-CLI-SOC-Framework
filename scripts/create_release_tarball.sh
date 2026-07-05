#!/usr/bin/env bash
set -euo pipefail
OUT=release_mtls_bundle.tar.gz

FILES=(
  "ops/ingest/server.py"
  "scripts/generate_mtls_certs.sh"
  "scripts/run_mtls_e2e.sh"
  "deployment/docker/Dockerfile.app"
  "deployment/docker/nginx.conf"
  "deployment/docker/docker-compose.mtls.yml"
  "tests/ingest/test_ingest.py"
  "README.md"
)

tar -czf "$OUT" "${FILES[@]}"
echo "Created $OUT"
