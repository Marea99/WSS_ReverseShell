# Wireless System Security Project

## Secure Reverse Shell with SSL/TLS and Password Authentication

A secure reverse shell application in Python that encrypts communication using SSL/TLS with client and server certificates and validates clients via a password authentication mechanism. This project demonstrates how to:

- Act as your own Certificate Authority (CA) to sign both server and client certificates for encrypted transport.
- Configure Python `ssl.SSLContext` objects with secure defaults using `ssl.create_default_context`, loading certs and enforcing mutual TLS.
- Implement a simple password authentication step inside the encrypted channel.
- Establish a reverse shell over the secured authenticated channel.

---

## Project Structure

```plaintext
WSS_ReverseShell/
├── certs/                  # Certificates and keys
│   ├── ca.key              # CA private key
│   ├── ca.crt              # CA root certificate
│   ├── server.key          # Server private key
│   ├── server.csr          # Server CSR
│   ├── server.crt          # Server certificate signed by CA
│   ├── client.key          # Client private key
│   ├── client.csr          # Client CSR
│   └── client.crt          # Client certificate signed by CA
├── server.py               # SSL/TLS server with password auth and reversed shell
├── client.py               # Reverse shell client with mutual TLS and password auth
└── README.md               # Project documentation (this file)
```

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Marea99/WSS_ReverseShell.git
   cd WSS_ReverseShell
   ```

2. Change line 36 with your specific IP
   ```bash
    IP.1 = 192.168.2.152
    ```

3. Certificate generation running generate_certs.sh script
   ```bash
    chmod +x generate_certs.sh
    ./generate_certs.sh
    ```
---

## Usage

1. Run the server 
    ```bash
    python3 4server.py --host 0.0.0.0 --port 4444
    ```

2. Run the client
    ```bash
    python3 2client.py --server 192.168.2.152 --port 4444
    ```

- The client uses its certificate to prove identity during TLS handshake.  
- Password is checked inside the encrypted channel for extra auth before any command are executed.

---

## Authors

Marta Espejo, Eric Ramírez and Jordi Nadeu

