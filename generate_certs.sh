#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="certs"
mkdir -p "${CERT_DIR}"

# 1. Generate CA key and cert
openssl genrsa -out "${CERT_DIR}/ca.key" 4096
openssl req -x509 -new -nodes \
  -key "${CERT_DIR}/ca.key" \
  -sha256 \
  -days 3650 \
  -subj "/C=US/ST=State/L=City/O=MyOrg/CN=MyOrg Root CA" \
  -out "${CERT_DIR}/ca.crt"

# 2. Create SAN config for server IP
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
CN = 192.168.2.152

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 192.168.2.152
EOF

# 3. Generate Server key & CSR with SAN
openssl genrsa -out "${CERT_DIR}/server.key" 2048
openssl req -new -nodes \
  -config "${CERT_DIR}/san.cnf" \
  -key "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.csr"

# 4. Sign server CSR including SAN extensions
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

# 5. Generate Client key & CSR (no SAN needed)
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

# 6. Cleanup
rm -f "${CERT_DIR}/ca.srl"

echo "All certificates and keys generated in '${CERT_DIR}/'"
