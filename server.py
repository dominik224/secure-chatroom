#!/usr/bin/env python3

# Creates the socket server (S)

import socket
import threading
import time 
from helperFunctions import *

# Holds all of the connections
CONN_LIST = {}

# Function which handles connection to a client
def handle_client(conn, addr):
    print(f"New connection: {addr} connected.")
    
    # First message is the client ID (Skip header)
    CLIENT_ID = conn.recv(MESSAGE_LEN).decode(FORMAT)[HEADER_LEN]
    
    # Continuously listen for messages
    connected = True
    while connected:
        # Listen for message
        enc_message = conn.recv(MESSAGE_LEN)
        body_len, body = decodeMessage(enc_message)

        # Check for a disconnect
        if body[:len(DISCONNECT_MESSAGE)] == DISCONNECT_MESSAGE:
            connected = False
        # Otherwise broadcast the message to all other connected clients
        else:
            broadcast(body, CLIENT_ID, exclude=[conn.fileno()])

    # If a disconnect occurs delete the connection info and close the connection 
    del CONN_LIST[conn.fileno()]
    conn.close()

# Sends a message to all connected clients except the one who sent the message
def broadcast(body, sender, exclude=[]):
    msg = sender + body
    msg = encodeMessage(msg)
    for conn in CONN_LIST:
        if conn not in exclude:
            CONN_LIST[conn].send(msg)

# Function to start the server
def start(server):
    server.listen()
    while True:
        conn, addr = server.accept()
        CONN_LIST[conn.fileno()] = conn
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"Active connections: {threading.activeCount() -1}")

if __name__ == "__main__":
    print("Starting server...")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST,PORT))
    start(server)
