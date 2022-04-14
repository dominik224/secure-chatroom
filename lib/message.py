from cffi import VerificationError
from lib.certificate import Certificate
from rsa import sign, verify, PrivateKey
from pickle import dumps, loads
from enum import Enum, auto
from hashlib import sha256

class MessageType(Enum):
    connection = auto()         # Message on connection, includes identity
    disconnect = auto()         # Message signalling disconnect
    encryptedText = auto()      # Plain message encrypted with session key
    certRequest = auto()        # Request for a digital certificate from S
    certResponse = auto()       # Response for a cert request
    nonceRequest = auto()       # Request for a nonce to establish session key
    nonceResponse = auto()      # Response for a nonce request

class Message:
    """ Defines the messages sent between entities. """

    def __init__(self):
        self.certificate: Certificate = Certificate()
        self.message_type: MessageType 
        self.body: dict = {}
        self.signature: bytes = None
    
    def gen_signature(self, private_key: PrivateKey) -> bytes:
        """ Generates a signature of the message. """
        cert = self.certificate.export()
        body = dumps(loads(dumps(self.body))) # Dont ask
        
        self.signature = sign(cert+body, private_key, "SHA-256")
        return self.signature
    
    def verify_signature(self) -> bool:
        """ Verifies the signature of the message using the
            public key included in the certificate.
            Returns True if the verification was successful
            Returns False if the verification failed.  """
        cert = self.certificate.export()
        body = dumps(loads(dumps(self.body))) # Seriously, it only works this way

        try:
            verify(cert+body, self.signature, self.certificate.public_key)
            return True
        except VerificationError:
            return False

    def serialize(self, msg_length: int = 0) -> bytes:
        """ Serializes the message. """

        if self.signature == None:
            raise Exception("Signature needs to be generated first.")

        message = dumps(self.__dict__)
        length = len(message)
        if msg_length:
            message = message + ((' '.encode('utf-8')) * (msg_length - length))
        return message
    
    def deserialize(self, bytes) -> None:
        """ Deserializes a message. """
        self.__dict__ = loads(bytes)

class MessageDisconnection(Message):
    """ Disconnection message. """
    def __init__(self, certificate: Certificate):
        super().__init__()
        self.message_type = MessageType.disconnect
        self.certificate = certificate

class MessageConnection(Message):
    """ Identitification message on connection. """
    def __init__(self, certificate: Certificate):
        super().__init__()
        self.message_type = MessageType.connection
        self.certificate = certificate
        self.body = {'identity': certificate.identity}
    
class MessageEncrypted(Message):
    """ Encrypted text message. """
    def __init__(self, enc_text: str, iv):
        super().__init__()
        self.message_type = MessageType.encryptedText
        self.body = {'iv': iv, 'encrypted_text': enc_text}

class MessageCertRequest(Message):
    """ Certificate Request Message. """
    def __init__(self, requestIDs: list = None):
        super().__init__()
        self.message_type = MessageType.certRequest
        self.body = {'requestIDs': requestIDs}

class MessageCertResponse(Message):
    """ Certificate Request Response. """
    def __init__(self, certs: list):
        super().__init__()
        self.message_type = MessageType.certResponse
        self.body = {'certificates': certs}

class MessageNonceRequest(Message):
    """ Nonce request message. """
    def __init__(self, requestIDs: list, originCert: Certificate, nonceChallenge: dict):
        super().__init__()
        self.message_type = MessageType.nonceRequest
        self.body = {'requestIDs': requestIDs}
        for ID in requestIDs:
            self.body[ID] = {'originCert': originCert, 'nonceChallenge': nonceChallenge[ID]}

class MessageNonceResponse(Message):
    """ Nonce Request Response. """
    def __init__(self, target: str, originCert: Certificate, enc_nonce: int, nonceChallengeResponse: bytes):
        super().__init__()
        self.message_type = MessageType.nonceResponse
        self.body = {'target': target, 'originCert': originCert, 'encrypted_nonce': enc_nonce, 'nonceChallengeResponse': nonceChallengeResponse}

if __name__ == '__main__':
    # Some testing of the message
    m1 = Message()
    m1.certificate.load(filename='certificates/certA.cer')
    m1.body = {'nonce': "123"}

    with open('keys/A_privkey.pem', 'rb') as f:
        private_key = PrivateKey.load_pkcs1(f.read(), 'PEM')
    
    m1.gen_signature(private_key)

    m2 = Message()
    m3 = Message()
    
    m2.deserialize(m1.serialize())
    m3.deserialize(m1.serialize(1000))

    print(len(m1.serialize()))
    print(len(m1.serialize(1000)))

    print(m1.body == m2.body == m3.body)
    print(m1.signature == m2.signature == m3.signature)
    print(m1.certificate.identity == m2.certificate.identity == m3.certificate.identity)
    print(m1.certificate.public_key == m2.certificate.public_key == m3.certificate.public_key)
    print(m1.certificate.signature == m2.certificate.signature == m3.certificate.signature)
    print(m1.verify_signature())

