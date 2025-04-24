# Wireless System Security Project

## Secure Reverse Shell with SSL/TLS and Password Authentication

A secure reverse shell application in Python that encrypts communication using SSL/TLS with client and server certificates and validates clients via a password authentication mechanism. 

This project implements how to:

- Act as your own Certificate Authority (CA) to sign both server and client certificates for encrypted transport.
- Configure Python `ssl.SSLContext` objects with secure defaults using `ssl.create_default_context`, loading certs and enforcing mutual TLS.
- Implement a simple password authentication step inside the encrypted channel.
- Establish a reverse shell over the secured authenticated channel.


## Project Structure

```plaintext
WSS_ReverseShell/
├── certs/
│   ├── ca.key
│   ├── ca.crt
│   ├── server.key
│   ├── server.csr
│   ├── server.crt
│   ├── client.key
│   ├── client.csr
│   └── client.crt
├── server.py
├── client.py
└── README.md          
```

## Installation

1. Clone the repository
   ```bash
   git clone https://github.com/Marea99/WSS_ReverseShell.git
   cd WSS_ReverseShell
   ```

2. Generate the certificates
   ```bash
    chmod +x generate_certs.sh
    ./generate_certs.sh <SERVER_IP>
    ```

3. Change in the `server.py` file the **PORT** variable (Line 28) that you wish to use

4. Change in the `client.py` file the server configuration vars, **SERVER_IP** (Line 14) and **SERVER_PORT** (Line 15)


## Usage

1. Run the server 
    ```bash
    python3 server.py
    ```

2. Run the client
    ```bash
    python3 client.py
    ```
3. Introduce the password in the client cli

4. Start to send commands in the server gui

- The client uses its certificate to prove identity during TLS handshake.  
- Password is checked inside the encrypted channel for extra auth before any command are executed.


## Authors

Marta Espejo, Eric Ramírez and Jordi Nadeu

