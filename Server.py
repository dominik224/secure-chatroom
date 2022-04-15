from ssl import SOL_SOCKET
from lib.certificate import Certificate
from lib.message import Message, MessageType
from socket import SO_REUSEADDR, socket, AF_INET, SOCK_STREAM
from Entity import *
import threading

class Server(Entity):
    """ Socket server."""

    def __init__(self, host: str, port: int):
        self.host: str = host
        self.port: int = port
        self.identity = 'S'
        self.certificates: dict[Certificate] = {}
        self.connection: socket = socket(AF_INET, SOCK_STREAM)
        self.connection_list: dict[socket] = {}
        self.connection_ids: dict[int] = {}
        self.load_certificates()
        self.connection.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.connection.bind((self.host, self.port))
        super().__init__()
        
        self.start()

    def load_certificates(self) -> None:
        """ Loads the certificate of each entitiy. """
        entities = ['A', 'B', 'C', 'S']
        for entity in entities:
            cert = Certificate()
            cert.load(f'certificates/Cert{entity}.cer')
            self.certificates[entity] = cert

    def start(self):
        """ Starts the socket server S. """
        server = self.connection
        server.listen()

        while True:
            conn, addr = server.accept()
            self.connection_list[conn.fileno()] = conn
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()
            print(f"Active connections: {threading.active_count() - 1}")

    def handle_client(self, conn: socket, addr):
        """ Client handler. """
        print(f"New connection: {addr}.")
        connected = True
        
        while connected:
            message = conn.recv(MESSAGE_LEN)
            connected, id = self.read_message(message, conn)

        del self.connection_list[conn.fileno()]
        del self.connection_ids[id]
        conn.close()

    def read_message(self, msg: bytes, origin: socket) -> bool:
        """ Processes messages. """
        message = Message()
        message.deserialize(msg)
        message.verify_signature()
        
        if message.message_type == MessageType.encryptedText:
            self._read_message_enc_text(message)
        elif message.message_type == MessageType.certRequest:
            print('-' * 20)
            print("Reading cert request.")
            self._read_message_cert_request(message, origin)
        elif message.message_type == MessageType.nonceRequest:
            print("Reading nonce request.")
            self._read_message_nonce_request(message)
        elif message.message_type == MessageType.nonceResponse:
            print("Reading nonce response.")
            self._read_message_nonce_response(message)
        elif message.message_type == MessageType.connection:
            print(f"Reading connection message from {message.body['identity']}")
            self.connection_ids[message.body['identity']] = origin.fileno()
        elif message.message_type == MessageType.disconnect:
            return False, message.certificate.identity
        
        return True, ""

    def _read_message_cert_request(self, message: Message, origin: socket):
        """ Reads certificate request message & sends response. """
        cert_requests = message.body['requestIDs']
        certs = [self.certificates[ID] for ID in cert_requests]
        
        print("Sending cert response.") 
        cert_response = self._gen_message_cert_response(certs)
        origin.send(cert_response)

    def _gen_message_cert_response(self, certs: list) -> bytes:
        """ Generates a response with digital certificates. """
        message = MessageCertResponse(certs)
        message.certificate = self.certificates[self.identity]
        message.gen_signature(self.private_key)
        message.verify_signature()
        return message.serialize()

    def _read_message_nonce_request(self, message: Message):
        """ Reads nonce request message. """
        targets = message.body['requestIDs']

        # Send a nonce request to each target
        for target in targets:
            nonce_challenge = {target: message.body[target]['nonceChallenge']}
            target_request = MessageNonceRequest([target], message.body[target]['originCert'], nonce_challenge)
            target_request.certificate = self.certificates[self.identity]
            target_request.gen_signature(self.private_key)
            print(f"Forwarding nonce request to {target}.")
            self.connection_list[self.connection_ids[target]].send(target_request.serialize())
    
    def _read_message_nonce_response(self, message: Message):
        """ Reads nonce response message. """
        target = message.body['target']
        message.certificate = self.certificates[self.identity]
        message.gen_signature(self.private_key)
        print(f"Forwarding nonce response to {target}")
        self.connection_list[self.connection_ids[target]].send(message.serialize())

    def _read_message_enc_text(self, message: Message):
        """ Reads encrypted text message. """
        sender = message.certificate.identity
        print(f"Message from {sender}: {message.body['encrypted_text'][:20]}")
        for id in self.connection_ids: 
            if id != sender:
                self.connection_list[self.connection_ids[id]].send(message.serialize())

    def _read_message_cert_response(message: Message):
        return super()._read_message_cert_response()

if __name__ == "__main__":
    server = Server(HOST, PORT)
    print("Server started. Waiting for connections.")
