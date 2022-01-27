#!/usr/bin/env python3

# Creates a socket client (A,B,C)

import socket
import threading
import time 
import sys

MESSAGE_LEN = 2048
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DIS"
CLIENT_IDS = ['A', 'B', 'C']
HOST = '127.0.0.1' # Localhost
PORT = 6032        

# Function to send a message to the server
def send(msg):
    # Encode the message
    message = msg.encode(FORMAT)
    
    # Pad the message to fit the message length
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
