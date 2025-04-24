#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <SERVER_IP>"
  echo "Example: $0 192.168.1.14"
  exit 1
}

# Parse and validate arguments
if [ $# -ne 1 ]; then
  usage
fi

SERVER_IP="$1"
CERT_DIR="certs"

# Prepare output directory
mkdir -p "${CERT_DIR}"

# Generate CA key and self-signed cert
openssl genrsa -out "${CERT_DIR}/ca.key" 4096
openssl req -x509 -new -nodes \
  -key "${CERT_DIR}/ca.key" \
  -sha256 \
  -days 3650 \
  -subj "/C=US/ST=State/L=City/O=MyOrg/CN=MyOrg Root CA" \
  -out "${CERT_DIR}/ca.crt"

# Create SAN config file with the provided IP
cat > "${CERT_DIR}/san.cnf" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
C  = US
ST = State
L  = City
O  = MyOrg
CN = ${SERVER_IP}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = ${SERVER_IP}
EOF

# Generate server key & CSR using that SAN config
openssl genrsa -out "${CERT_DIR}/server.key" 2048
openssl req -new -nodes \
  -config "${CERT_DIR}/san.cnf" \
  -key "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.csr"

# Sign the server CSR (including the SAN extension)
openssl x509 -req \
  -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/server.crt" \
  -days 365 \
  -sha256 \
  -extensions req_ext \
  -extfile "${CERT_DIR}/san.cnf"

# Generate client key & CSR
openssl genrsa -out "${CERT_DIR}/client.key" 2048
openssl req -new \
  -key "${CERT_DIR}/client.key" \
  -subj "/C=US/ST=State/L=City/O=MyOrg/CN=client" \
  -out "${CERT_DIR}/client.csr"
openssl x509 -req \
  -in "${CERT_DIR}/client.csr" \
  -CA "${CERT_DIR}/ca.crt" \
  -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/client.crt" \
  -days 365 \
  -sha256

# Cleanup serial
rm -f "${CERT_DIR}/ca.srl"

echo "✓ Certificates generated in ${CERT_DIR}:"
echo "  - CA:         ca.crt, ca.key"
echo "  - Server:     server.crt, server.key"
echo "  - Client:     client.crt, client.key"
