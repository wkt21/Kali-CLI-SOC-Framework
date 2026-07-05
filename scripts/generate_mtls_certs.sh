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
