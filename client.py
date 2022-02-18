#!/usr/bin/env python3

# Creates a socket client (A,B,C)

import socket
import threading
import select
import time 
import sys
from helperFunctions import *

# Function to send a message to the server
def send(msg, client):
    message = encodeMessage(msg)
    client.send(message)

def main(CLIENT):
    # Create a client socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    client.connect((HOST, PORT))
    print(f"Sending {CLIENT}")
    send(CLIENT, client)
    
    # Receive and send messages
    while True:
        sockets_list = [sys.stdin, client]
        read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])
        
        for socks in read_sockets:
            if socks == client:
                message = socks.recv(MESSAGE_LEN)
                _, message = decodeMessage(message)
                print(f"{message[0]}: {message[1:]}") 
            
            else:
                message = sys.stdin.readline()
                sys.stdout.write(f"{CLIENT}:")
                sys.stdout.write(message)
                sys.stdout.flush()
                send(message, client)

                if message == DISCONNECT_MESSAGE:
                    exit()


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
    
    main(CLIENT)

    
