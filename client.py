#!/usr/bin/env python3

# Creates a socket client (A,B,C)

import socket
import threading
import time 
import sys

HEADER_LEN = 4     # This goes in front of the message and contains the length of the unpadded message
MESSAGE_LEN = 2048  # Total length of the padded message
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DIS"
CLIENT_IDS = ['A', 'B', 'C']
HOST = '127.0.0.1' # Localhost
PORT = 6032        

# Function to send a message to the server
def send(msg):
    # Encode the message
    message = msg.encode(FORMAT)
    
    # Create a header containing message length
    header = str(len(message))
    header = header.encode(FORMAT)
    if len(header) > HEADER_LEN:
        print("Error: message too long")
        return
    # Pad the header
    header += b' ' * (HEADER_LEN - len(header))

    # Append the header in front of the message
    message = header + message 

    # Pad the message
    message += b' ' * (MESSAGE_LEN - len(message))
    client.send(message)

if __name__ == "__main__":
    # Check if client ID was provided
    if len(sys.argv) > 1:
        CLIENT = sys.argv[1]

        # Check if valid client ID
        if CLIENT not in CLIENT_IDS:
            print(f"Error: Possible client IDs {CLIENT_IDS}")
    else:
        print(f"Error: Client ID not provided")
        print(f"Usage: $python3 client.py <ID>")

    # Create a client socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    client.connect((HOST, PORT))
    send(CLIENT)

    while True:
        message = input("$")
        send(message)
        if message == DISCONNECT_MESSAGE:
            exit()
