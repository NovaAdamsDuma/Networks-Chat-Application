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
    def DH(self, private_key, public_key):
        return nacl.bindings.crypto_scalarmult(private_key, public_key)

    # performs Authenticated Encryption with Associated Data (ChaCha20Poly1305)
    def AEAD_encrypt(self, key, count, plain_text, auth_text):
        nonce = count.to_bytes(12, byteorder='little')
        myCipher=Cipher(
            algorithms.ChaCha20(key, nonce),
            modes.Poly1305(), backend=default_backend()
        )
        myEncryptor = myCipher.encryptor()
        myEncryptor.authenticate_additional_data(auth_text)
        ciphText = myEncryptor.update(plain_text) + myEncryptor.finalize()
        tag = myEncryptor.tag
        return ciphText + tag

    # performs Authenticated Decryption with Associated Data (ChaCha20, Poly1305)
    def AEAD_decrypt(self, key, count, ciphText, auth_text):
        if len(ciphText < 16):
            raise ValueError("Ciphertext too short")

    # function that computes BLAKE2s hash of input data
    def Hash(self, data): #*****
        h = hashlib.blake2s(digest_size=32)
        h.update(data)
        return h.digest()

    # function that hashes concatenated inputs
    def MixHash(self, *inputs): #*****
        grouped = b"".join(inputs)
        return self.Hash(combined)

    # function that computes keyed BLAKE2s 
    def Mac(self, key, data): #*****
        h = hashlib.blake2s(key, hashes.BLAKE2s(16), backend=default_backend())
        h.update(data)
        return h.finalize()

    # function that computes HMACD with BLAKE2s
    def Hmac(self, key, data):
        h = cryptohmac.HMAC(key, hashes.BLAKE2s(32), backend = default_backend())
        h.update(data)
        return h.finalize()
    
    # produces one output key via derivation
    def Kdf1(self, key, input_data): #******
        temp0 = self.Hmac(key, input_data)
        temp1 = self.Hmac(temp0, b"\x01")
        return temp1

    # prodcues 2 output keys via derivation
    def Kdf2(self, key, input_data): #******
        temp0 = self.Hmac(key, input_data)
        temp1 = self.Hmac(temp0, b"\x01")
        temp2 = self.Hmac(temp0, temp1 + b"\x02")
        return (temp1, temp2)
    
    # produces 3 output keys via derivation
    def Kdf3(self, key, input_data):
        temp0 = self.Hmac(key, input_data)
        temp1 = self.Hmac(temp0, b"\x01")
        temp2 = self.Hmac(temp0, temp1 + b"\x02")
        temp3 = self.Hmac(temp0, temp2 + b"\x03")
        return (temp1, temp2, temp3)

    # returns the TAI64N timestamp
    def Timestamp(self):
        timeNow = time.time()
        sec = int(timeNow).to_bytes(8, bytorder='big')
        nanosec = int((timeNow - int(timeNow)) * 1e9).to_bytes(4, byteorder='big')
        return sec + nanosec

    def create_initiation_msg(self):
    
    def process_response_msg(self):
    
    def encrypt_msg(self):

    def decrypt_msg(self):