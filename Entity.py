from abc import ABC, abstractmethod
from rsa import PrivateKey
from lib.message import *

HOST = '127.0.0.1'
PORT = 6032
MESSAGE_LEN = 4096*3

class Entity(ABC):
    """ Base class for the Server and Client classes. """
    def __init__(self):
        self.private_key: PrivateKey = None
        self.load_private_key()

    def read_message(self, msg: bytes):
        """ Processes received messages. """
        message = Message()
        message.deserialize(msg)
        message.verify_signature()

        if message.message_type == MessageType.encryptedText:
            return self._read_message_enc_text(message)

        elif message.message_type == MessageType.certRequest:
            return self._read_message_cert_request(message)
        
        elif message.message_type == MessageType.certResponse:
            return self._read_message_cert_response(message)

        elif message.message_type == MessageType.nonceRequest:
            return self._read_message_nonce_request(message)

        elif message.message_type == MessageType.nonceResponse:
            return self._read_message_nonce_response(message)

    def load_private_key(self) -> None:
        """ Loads the privaet key of the client. """
        with open(f'keys/{self.identity}_privkey.pem', 'rb') as file:
            self.private_key = PrivateKey.load_pkcs1(file.read(), 'PEM')

    @abstractmethod
    def _read_message_enc_text(message: Message):
        """ Read encrypted text message. """
        raise NotImplementedError
    
    @abstractmethod
    def _read_message_cert_request(message: Message):
        """ Read certificate request message. """
        raise NotImplementedError
    
    @abstractmethod
    def _read_message_cert_response(message: Message):
        """ Read certificate response message. """
        raise NotImplementedError
    
    @abstractmethod
    def _read_message_nonce_request(message: Message):
        """ Read nonce request message. """
        raise NotImplementedError

    @abstractmethod
    def _read_message_nonce_response(message: Message):
        """ Read nonce response message. """
        raise NotImplementedError
