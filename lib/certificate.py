"""
    Handles definition and creation of public key certificates
"""
# Python modules
import pickle
from rsa import PublicKey, PrivateKey, newkeys, sign

class Certificate:
    """ 
    Public Key Certificate object 
    Eg. CertA = A, Ka, {H(A, Ka)}ks-1
    """

    def __init__(self, public_key=None, identity=None, signature=None):
        self.public_key: PublicKey = public_key
        self.identity: str = identity
        self.signature: bytes = signature

    def gen_public_key(self, key_size=2048) -> PrivateKey:
        """ Generates a new public key for the certificate. """
        public_key, private_key = newkeys(key_size)
        self.public_key = public_key
        return private_key

    def gen_signature(self, private_key: PrivateKey) -> bytes:
        """ Generates a signature of the certificate. """
        id = self.identity.encode('utf-8')
        PEM = self.public_key.save_pkcs1('PEM')
        
        self.signature = sign(id+PEM, private_key, "SHA-256")
        return self.signature

    def export(self):
        """ Exports the object. """
        return pickle.dumps(self.__dict__)

    def load(self, filename=None, obj=None):
        """ Loads an exported object either from bytes or a file. """

        if filename is None and obj is not None:
            self.__dict__ = pickle.loads(obj)

        elif filename is not None and obj is None:
            with open(filename, 'rb') as file:
                self.__dict__ = pickle.load(file, encoding='utf-8')
        else:
            raise Exception("Only an object OR a file can be provided.")

    def save(self, filename=None):
        """ Saves the object to a file. """
        if filename == None:
            filename = f'certificates/Cert{self.identity}.cer'

        with open(filename, 'wb') as file:
            pickle.dump(self.__dict__, file)


if __name__ == "__main__":
    test = 0
    create_new_certs = 0

    # Creates new certificates for A, B, C, S
    if create_new_certs:
        # Initialize all certificates
        certA = Certificate(identity='A')
        certB = Certificate(identity='B')
        certC = Certificate(identity='C')
        certS = Certificate(identity='S')

        # Generate the certificate for S first
        private_key_s = certS.gen_public_key()
        certS.gen_signature(private_key_s)

        # Save the private key for S
        with open('keys/S_privkey.pem', 'wb') as file:
            file.write(private_key_s.save_pkcs1('PEM'))
        
        # Save certificate for S
        certS.save()

        # Create certs for A, B, C with Ks-1
        certs = [certA, certB, certC]
        for cert in certs:
            private_key = cert.gen_public_key()

            # Save the private key
            with open(f'keys/{cert.identity}_privkey.pem', 'wb') as file:
                file.write(private_key.save_pkcs1('PEM'))
            
            # Generate a signature
            cert.gen_signature(private_key_s)

            # Save the certificate to a file
            cert.save()

    # Tests for the certificate
    if test:
        public_key, private_key = newkeys(2048)
        certA = Certificate(public_key, 'A')
        certA.gen_signature(private_key)

        certB = Certificate()
        certB.load(certA.export())

        print(certA.public_key == certB.public_key)
        print(certB.signature == certA.signature)

