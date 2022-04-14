"""
    Client file
"""
from rsa import PrivateKey, PublicKey, encrypt, decrypt
from lib.certificate import Certificate
from Cryptodome.Random import get_random_bytes
from lib.message import Message, MessageCertRequest, MessageCertResponse, MessageType
from lib.encryption import create_envelope, unpack_envelope, aes_encrypt, aes_decrypt
from random import randint
from socket import socket, AF_INET, SOCK_STREAM
from pickle import dumps, loads
from Entity import *
from termcolor import colored
import sys, select, os


class Client(Entity):
    """ Socket client. """
    def __init__(self, id: str):
        
        self.entities: list[str] = ['A', 'B', 'C']
        if id.upper() not in self.entities:
            raise Exception("Error: ID Must be A, B, or C")

        self.identity: str = id.upper()
        self.entities.remove(self.identity)
        self.nonces: dict = {self.identity: get_random_bytes(16)}
        self.nonce_challenge: int = -1
        self.certificate: Certificate = Certificate()
        self.public_keys: dict[PublicKey] = {}
        self.connection: socket = socket(AF_INET, SOCK_STREAM)
        self.session_key: bytes = None
        self.screen: list[str] = ['\n' for n in range(os.get_terminal_size().lines)]
        self.screen_colors: list[str] = ['white' for n in range(os.get_terminal_size().lines)]
        self.server_pub_key = None
        self.clear = lambda: os.system('cls' if os.name in ('nt', 'dos') else 'clear')
        self.colors = {'A': 'green', 'B': 'blue', 'C': 'red', 'X': 'yellow'}
        self.load_certificate()
        super().__init__()

    def load_certificate(self) -> None:
        """ Loads the certificate of the client. """
        self.certificate.load(filename=f'certificates/Cert{self.identity}.cer')
    
    def connect(self, host: str, port: int) -> None:
        """ Connects to the server. """
        print("Connecting to the server...")
        self.connection.connect((host, port))
        print("Connected.")
        print("Press Enter to establish a session key.")

        connectionMessage = self._gen_message_connection()
        self.connection.send(connectionMessage)

        # Obtain a session key from the server
        session_key = False
        
        # Input prompt
        prompt = f"{self.identity}: "

        # Receive and send messages
        while True:
            socket_list = [sys.stdin, self.connection]
            #socket_list = [socket(), self.connection]
            read_sockets, write_socket, error_socket = select.select(socket_list, [], [])
            for socks in read_sockets:
                if socks == self.connection:
                    message = socks.recv(MESSAGE_LEN)
                    self.read_message(message)
                elif not session_key:
                    _input = input()
                    self.obtain_session_key()
                    session_key = True
                else:
                    _input = input("A: ")
                    if _input != '':
                        self.send_message(_input)
                        print("Updating")
                        self._update_terminal(prompt + _input, self.identity)

    def _update_terminal(self, text, id = 'X'):
        """ Updates terminal to add new messages. """
        size = os.get_terminal_size().lines
        if len(self.screen) > size:
            self.screen.pop(0)
        
        if len(self.screen_colors) > size:
            self.screen_colors.pop(0)

        self.screen.append(text)
        self.screen_colors.append(self.colors[id])

        self.clear()
        for line, color in zip(self.screen, self.screen_colors):
            print(colored(line, color))
        
    def send_message(self, input: str):
        """ Sends encrypted text message. """
        if input == "!DISCONNECT":
            print("Disconnecting..")
            message = MessageDisconnection(self.certificate)
            message.gen_signature(self.private_key)
            self.connection.send(message.serialize())
            exit()
            
        enc_input, iv, _ = aes_encrypt(input.encode('utf-8'), self.session_key)
        message = MessageEncrypted(enc_input, iv)
        message.certificate = self.certificate
        message.gen_signature(self.private_key)
        self.connection.send(message.serialize())

    def _gen_message_connection(self):
        """ Generates connection message to identify itself to the server. """
        message = MessageConnection(self.certificate)
        message.gen_signature(self.private_key)
        return message.serialize()

    def _read_message_enc_text(self, message: Message):
        """ Reads encrypted text message. """
        if self.session_key == None:
            return
        
        enc_text = message.body['encrypted_text']
        iv = message.body['iv']
        text = aes_decrypt(enc_text, iv, self.session_key)
        origin = message.certificate.identity
        #print(f"{origin}: {text.decode('utf-8')}")
        self._update_terminal(f"{origin}: {text.decode('utf-8')}", origin)
    
    def _read_message_cert_response(self, message: Message):
        """ Read the certificates and save the public keys. """
        certificates = message.body['certificates']
        for cert in certificates:
            self.public_keys[cert.identity] = cert.public_key

    def _read_message_nonce_response(self, message: Message):
        """ Read the nonce response message. """
        body = message.body
        originCert = body['originCert']
        enc_nonce = body['encrypted_nonce']
        challengeResponse = body['nonceChallengeResponse']
        originID = originCert.identity

        challengeResponse = decrypt(challengeResponse, self.private_key)
        challengeResponse = int.from_bytes(challengeResponse, 'little')
        if self.nonce_challenge != challengeResponse:
            return
        
        nonce = decrypt(enc_nonce, self.private_key)
        #print("Received nonce from: ", originID)
        self.nonces[originID] = nonce

        if len(self.nonces) == (len(self.entities) + 1):
            self.gen_session_key()

    def _gen_message_nonce_response(self, targetCert: Certificate, challengeResponse: bytes):
        """ Generates a nonce response message. """
        target_public_key = targetCert.public_key
        target_id = targetCert.identity

        enc_nonce = encrypt(self.nonces[self.identity], target_public_key)
        nonce_response = MessageNonceResponse(target_id, self.certificate, enc_nonce, challengeResponse)
        nonce_response.certificate = self.certificate
        nonce_response.gen_signature(self.private_key)
        #print("Sending nonce response.")
        self.connection.send(nonce_response.serialize())
    
    def _read_message_nonce_request(self, message: Message):
        """ Reads the nonce request message. """
        request = message.body[self.identity]
        originCert = request['originCert']
        challenge = request['nonceChallenge']

        challengeResponse = decrypt(challenge, self.private_key)
        challengeResponse = encrypt(challengeResponse, originCert.public_key)
        
        # Respond to the request
        self._gen_message_nonce_response(originCert, challengeResponse)

    def _gen_message_cert_request(self, entities: list) -> bytes:
        """ Creates a certificate request message. """
        cert_request = MessageCertRequest(self.entities)
        cert_request.certificate = self.certificate
        cert_request.gen_signature(self.private_key)
        return cert_request.serialize(MESSAGE_LEN)
    
    def _gen_message_nonce_request(self, targets: list):
        """ Generates a nonce request message. """
        self.nonce_challenge = randint(1_000_000, 9_999_999)
        nonce_challenge_bytes = self.nonce_challenge.to_bytes(4, 'little')
        challenge = {}

        for target in targets:
            challenge[target] = encrypt(nonce_challenge_bytes, self.public_keys[target])

        message = MessageNonceRequest(targets, self.certificate, challenge)
        message.certificate = self.certificate
        message.gen_signature(self.private_key)
        return message.serialize()

    def obtain_session_key(self):
        """ Uses the created protocol to obtain the session key Kabc. """
        # (1) X->S
        # Certificate Request
        print("Sending certificate request.")
        cert_request = self._gen_message_cert_request(self.entities)
        self.connection.send(cert_request)

        # (2) S->X
        # Receiving certificates & extracting public keys
        print("Reading cert response.")
        cert_response_serial = self.connection.recv(MESSAGE_LEN).strip(b' ')
        self.read_message(cert_response_serial)

        # (3) X->S
        # Sending nonce request
        print("Sending nonce request.")
        nonce_request = self._gen_message_nonce_request(self.entities)
        self.connection.send(nonce_request)

    def gen_session_key(self):
        """ Uses the 3 nonces to generate a session key. """
        key = 0
        for value in self.nonces.values():
            key = key | int.from_bytes(value, 'big')
        
        self.session_key = sha256(key.to_bytes(16, 'big')).digest()[0:128]
        self._update_terminal("Session key established. Communication encrypted end-to-end.")

    def _read_message_cert_request(message: Message):
        return super()._read_message_cert_request()

if __name__ == "__main__":
    client = Client(sys.argv[1].upper())
    client.connect(HOST, PORT)
