# secure-chatroom
Cryptography python socket assignment for EE6032

Description
------
Project to help understand secure commmunication through an insecure channel.

Server acts as a trusted authority. Clients A, B, and C can communicate through a custom message protocol using asymmetric & symmetric encryption.

Files
-----
[Server.py](Server.py): Accepts messages from entities A, B, C and acts as a trusted authority. Supports establishing a shared secret session key, and sending encrypted text.

[Client.py](Client.py): Client communication is done through a server S. All messages utilize Authentication and Integrity. Confidentiality is first provided via RSA and then via AES-CBC.

[lib/certificate.py](lib/certificate.py): Defines the public key certificate class. (In the format: `CertX = X, Kx, {H(X, Kx)}ks-1`)

[lib/message.py](lib/message.py): Defines the necessary message protocol classes.

[lib/encryption.py](lib/encryption.py): Functions used for Asymmetric Encryption/Decrytpion & Digital Envelope creation and unpacking.
