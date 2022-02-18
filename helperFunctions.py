#!/usr/bin/env python3

import socket
import threading
import select
import time 
import sys

# Size of the header in each message
HEADER_LEN = 4
# Length of each message, shorter messages have to be padded
MESSAGE_LEN = 2048
# Message encoding format
FORMAT = 'utf-8'
# Message which disconnects the Client from the Server
DISCONNECT_MESSAGE = "!DIS"
# Possible IDs for Clients
CLIENT_IDS = ['A', 'B', 'C']
# SERVER IP
HOST = '127.0.0.1'
# SERVER PORT
PORT = 6032        

# Decodes message
def decodeMessage(message):
    message = message.decode(FORMAT)
    header = message[:HEADER_LEN-1]
    body_len = int(header)
    body = message[HEADER_LEN:HEADER_LEN + body_len]

    return body_len, body

# Encodes the message
def encodeMessage(message):
    # Encode the message
    message = message.encode(FORMAT)
    
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
    
    return message
