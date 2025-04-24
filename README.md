# Wireless System Security Project

## Secure Reverse Shell with SSL/TLS and Password Authentication

A secure reverse shell application in Python that encrypts communication using SSL/TLS with client and server certificates and validates clients via a password authentication mechanism. 

This project implements how to:

- Act as your own Certificate Authority (CA) to sign both server and client certificates for encrypted transport.
- Configure Python `ssl.SSLContext` objects with secure defaults using `ssl.create_default_context`, loading certs and enforcing mutual TLS.
- Implement a simple password authentication step inside the encrypted channel before executing any commands.
- Establish a reverse shell over the secured authenticated channel.
- **Manage multiple clients concurrently**, using a GUI dropdown to select and interact with any connected client session.

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
├── generate_certs.sh
├── server.py
├── client.py
└── README.md          
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Marea99/WSS_ReverseShell.git
   cd WSS_ReverseShell
   ```

2. Generate the certificates:
   ```bash
    chmod +x generate_certs.sh
    ./generate_certs.sh <SERVER_IP>
    ```

3. In `server.py` file set the **PORT** variable (Line 28) that you wish to use.

4. In `client.py` set the **SERVER_IP** (Line 14) and **SERVER_PORT** (Line 15)


## Usage

1. Run the server:
    ```bash
    python3 server.py
    ```
    - The GUI will appear, listening on the configured port.
    - Upon each client connection and successful password & TLS handshake, the client’s ID appears in the dropdown selector.

2. Run the client:
    ```bash
    python3 client.py
    ```
    - The client prompts for the shared password (input hidden).
    - After mutual TLS and password auth, the client awaits commands.
3. Start to use the reverse shell:

    - In the server GUI, use the Client Selector dropdown to choose any connected client session by its ID.

    - Type a shell command in the text entry and press Enter or click Send.

    - The command is sent only to the selected client; its output streams back into the GUI, prefixed with the client ID.

    - Switch the dropdown at any time to interact with a different client without interrupting others.

## Security Considerations

- Protect private keys: chmod 600 certs/*.key to restrict access.

- Rotate certificates and passwords periodically.

- Use strong passwords and consider moving to challenge–response or HMAC if desired.

- Audit logs of client connections and failed authentications.

## Authors

Marta Espejo, Eric Ramírez and Jordi Nadeu

