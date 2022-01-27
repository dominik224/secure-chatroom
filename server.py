#!/usr/bin/env python3

# Creates the socket server (S)

import socket
import threading
import time 

HEADER_LEN = 4
MESSAGE_LEN = 2048
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DIS"
HOST = '127.0.0.1' # Localhost
PORT = 6032        


# Function which handles connection to a client
def handle_client(conn, addr):
    print(f"New connection: {addr} connected.")
    
    # First message is the client ID (Skip header)
    CLIENT_ID = conn.recv(MESSAGE_LEN).decode(FORMAT)[HEADER_LEN]
    
    # Continuously listen for messages
    connected = True
    while connected:
        # Listen for message
        message = conn.recv(MESSAGE_LEN).decode(FORMAT)
        header = message[:HEADER_LEN-1]
        body_len = int(header)
        body = message[HEADER_LEN:HEADER_LEN + body_len]
        
        # Check for a disconnect
        if body[:len(DISCONNECT_MESSAGE)] == DISCONNECT_MESSAGE:
            connected = False

        print(f"{addr}, {CLIENT_ID}: {body}")

    conn.close()

# Function to start the server
def start(server):
    server.listen()
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"Active connections: {threading.activeCount() -1}")

if __name__ == "__main__":
    print("Starting server...")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST,PORT))
    start(server)
