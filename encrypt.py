# Nova Adams-Duma: encryption implementation
import nacl.bindings
import nacl.public
import os
import time
import hmac
import hashlib

class WireguardEncryption:
    # initialized encryption component with private / public keys
    def __init__(self, client_static_private_key, server_static_public_key):
        self.client_static_private_key = client_static_private_key # client's static private key
        self.server_static_public_key = server_static_public_key # server's static public key

        # Using eliptic curve cryptography, generate client's static public key
        self.client_static_public_key = nacl.bindings.crypto_scalarmult_base(self.client_static_private_key)

        # state variables ***********
        self.sender_index = None
        self.receiver_index = None
        self.chain_key = None
        self.hash_value = None
        self.sending_key = None
        self.receiving_key = None
        self.sending_counter = 0
        self.receiving_counter = 0

        # constants
        self.CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        self.IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
        self.LABEL_MAC1 = b"mac1----"

    # function that generates new ephemeral key pair
    def DH_Generate(self):
        private_key = nacl.public.PrivateKey.generate() # generate a PrivateKey object from the nacl library
        return (private_key._private_key, private_key.public_key._public _key) # note: .public_key gets the amtching public key of the private key (from .private_key)
        # return value is a tuple of both keys:
        # Raw private key bytes: (private_key._private_key)
        # Raw public key bytes: (private_key.public_key._public_key)

    #function that performs Diffie-Helman key exchange with Curve25519 (see paper)
    def DH(self):
        return nacl.bindings.crypto_scalarmult(private_key, public_key)

    # performs Authenticated Encryption with Associated Data (ChaCha20Poly1305)
    def AEAD_encrypt(self):

    def AEAD_decrypt(self):

    # function that computes BLAKE2s hash of input data
    def Hash(self): #*****
        h = hashlib.blake2s(digest_size=32)
        h.update(data)
        return h.digest()

    # function that hashes concatenated inputs
    def MixHash(self): #*****
        grouped = b"".join(inputs)
        return self.Hash(combined)

    # function that computes keted BLAKE2s 
    def Mac(self): #*****
        h = hashlib.blake2s(key, hashes.BLAKE2s(32), backend=default_backend())
        h.update(data)
        return h.finalize()

    def Hmac(self):
    
    def Kdf1(self):

    def Kdf2(self):
    
    def Kdf3(self):

    def Timestamp(self):

    def create_initiation_msg(self):
    
    def process_response_msg(self):
    
    def encrypt_msg(self):

    def decrypt_msg(self):