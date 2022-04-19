# Cryptodome installed using 'pip install pycryptodomex'
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from rsa import encrypt, decrypt, PublicKey, PrivateKey, newkeys

def create_envelope(input: bytes, pub_key: PublicKey) -> tuple:
    """ Creates an envelope using AES-CBC and RSA. """
    ct, iv, key = aes_encrypt(input)            # Encrypts the data with a random 128bit key
    enc_key = encrypt(key, pub_key)             # Encrypts the random key with a public key of the receiver
    return ct, iv, enc_key                 

def unpack_envelope(ciphertext: bytes, iv: bytes, enc_key: bytes, priv_key: PrivateKey) -> bytes:
    """ Unpacks a digital envelope. """
    key = decrypt(enc_key, priv_key)            # Decrypts the key using the receivers private key
    return aes_decrypt(ciphertext, iv, key)     # Decrypts the ciphertext
    
def aes_encrypt(input: bytes, key: bytes=None) -> tuple:
    """ AES encryption with CBC mode. """
    if key is None:
        key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(input, AES.block_size))
    iv = cipher.iv
    ct = ct_bytes
    return ct, iv, key

def aes_decrypt(ciphertext, iv, key) -> bytes:
    """ AES decryption with CBC mode. """
    ct = ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

if __name__ == "__main__":
    # Some tests for the envelopes
    puk, prk = newkeys(1024)
    ct, iv, key = create_envelope(b'testing this envelope', puk)
    print(unpack_envelope(ct, iv, key, prk))
