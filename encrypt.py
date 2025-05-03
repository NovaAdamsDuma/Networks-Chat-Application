# Nova Adams-Duma: encryption implementation
import nacl.bindings
import nacl.public
import os
import time
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as cryptohmac
from cryptography.hazmat.backends import default_backend

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
    def AEAD_decrypt(self, key, count, ciphText, auth_text): #*****
        if len(ciphText < 16):
            raise ValueError("Ciphertext is not long enough") #*****
        
        nonce = count.to_bytes(12, byteorder='little')
        plain_text = ciphText[:-16]
        tag = ciphText[-16:]

        myCipher=Cipher(
            algorithms.ChaCha20(key, nonce),
            modes.Poly1305(tag), backend=default_backend()
        )
        myDecryptor = myCipher.decryptor()
        myDecryptor.authenticate_additional_data(auth_text)

        try:
            decryptedData = decryptor.update(plain_text) + decryptor.finalize()
            return decryptedData
        except
            raise ValueError("Invalid tag, decrpytion unsuccsesful") #*****

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

    # function that creates handshake initiation message going to the server
    def create_initiation_msg(self):
        self.sender_index = int.from_bytes(os.urandom(4), byteorder='little')

        self.chain_key = self.Hash(self.CONSTRUCTION)
        self.hash_value = self.Hash(self.chain_key + self.IDENTIFIER)
        self.hash_value = self.Hash(self.hash_value + self.server_static_public)
        
        (self.ephemeral_private, self.ephemeral_public) = self.DH_Generate() # generating ephemeral key pair
        
        self.chain_key = self.Kdf1(self.chain_key, self.ephemeral_public) # Update chain key with ephemeral public key
        self.hash_value = self.Hash(self.hash_value + self.ephemeral_public) # Update hash with ephemeral public key
        
        (self.chain_key, key1) = self.Kdf2(
            self.chain_key, 
            self.DH(self.ephemeral_private, self.server_static_public)
        )
        
        msg_static = self.AEAD_encrypt( # encrypt static public key
            key1, 0, self.client_static_public, self.hash_value
        )
        self.hash_value = self.Hash(self.hash_value + msg_static)
        
        (self.chain_key, key2) = self.Kdf2(
            self.chain_key,
            self.DH(self.client_static_private, self.server_static_public)
        )
    
        timestamp = self.Timestamp()
        msg_timestamp = self.AEAD_encrypt( # encrypt timestamp
            key2, 0, timestamp, self.hash_value
        )
        self.hash_value = self.Hash(self.hash_value + msg_timestamp)
        
        # building the message
        message = bytearray()
        message.extend(b"\x01")  # Message type (1 = initiation)
        message.extend(b"\x00\x00\x00")  # Reserved zeros
        message.extend(self.sender_index.to_bytes(4, byteorder='little'))  # Sender index
        message.extend(self.ephemeral_public)  # Unencrypted ephemeral public key
        message.extend(msg_static)  # Encrypted static public key
        message.extend(msg_timestamp)  # Encrypted timestamp
        
        # calculating MAC1
        mac1_key = self.Hash(self.LABEL_MAC1 + self.server_static_public)
        mac1 = self.Mac(mac1_key, message)
        message.extend(mac1)
        
        # no implementation of mac2 given the requirements
        message.extend(b"\x00" * 16)
        
        return bytes(message)
    
    # function that processes server's response to the handshake message
    def process_response_msg(self, responseMsg):
        if len(responseMsg) < 56:
            return False
            
        msg_type = responseMsg[0]
        if msg_type != 0x02: # message parsing
            return False
            
        sender_index = int.from_bytes(responseMsg[4:8], byteorder='little')
        receiver_index = int.from_bytes(responseMsg[8:12], byteorder='little')
        if receiver_index != self.sender_index:
            return False
            
        self.receiver_index = sender_index
        server_ephemeral_public = responseMsg[12:44]
        msg_empty = responseMsg[44:60]  # 16 bytes for AEAD_LEN(0)
        
        mac1_key = self.Hash(self.LABEL_MAC1 + self.client_static_public) # verify Mac1
        mac1 = self.Mac(mac1_key, responseMsg[:60])
        if mac1 != responseMsg[60:76]:
            return False
            
        
        self.hash_value = self.Hash(self.hash_value + server_ephemeral_public) # update hash value with server's ephemeral public key
        
        self.chain_key = self.Kdf1(self.chain_key, server_ephemeral_public) # update chain key with server's ephemeral public key
        
        self.chain_key = self.Kdf1( # update chain key with DH result
            self.chain_key,
            self.DH(self.ephemeral_private, server_ephemeral_public)
        )
        
        self.chain_key = self.Kdf1( # update chain key with DH result
            self.chain_key,
            self.DH(self.client_static_private, server_ephemeral_public)
        )
        
        (self.chain_key, temp, key3) = self.Kdf3(self.chain_key, b"") # deriving final transport keys
        self.hash_value = self.Hash(self.hash_value + temp)
        
        try: # decrypting the empty message for verifications
            empty = self.AEAD_decrypt(key3, 0, msg_empty, self.hash_value)
            if empty != b"":
                return False
        except:
            return False
            
        self.hash_value = self.Hash(self.hash_value + msg_empty)
        
        (send_key, recv_key) = self.Kdf2(self.chain_key, b"") 
        self.sending_key = send_key # derive final sending key
        self.receiving_key = recv_key # derive final receiving key
        self.sending_counter = 0
        self.receiving_counter = 0
        
        self.chain_key = None # sensitive data, so must be cleared
        self.hash_value = None # sensitive data, so must be cleared
        self.ephemeral_private = None # sensitive data, so must be cleared
        
        return True
        
    # function that encrypts a message to be sent to the server
    def encrypt_msg(self, plain_text):
        if not self.sending_key:
            raise ValueError("Handshake not succesfully completed")

        pad_len = (16-(len(plain_text) % 16) % 16) # Pad plain text to multiple of 16 bytes, given spec
        padded = plain_text + (b"\x00" * pad_len)

        # message header
        msg = bytearray()
        msg.extend(b"\x04") # type 4 for transport data
        msg.extend(b"\x00\x00\x00") # reserved 0s
        msg.extend(self.receiver_index.to_bytes(4, byteorder='little'))
        msg.extend(self.sending_counter.to_bytes(8, byteorder='little'))

        # payload encryption
        encPayload = self.AED_encrypt(
            self.sending_key, self.sending_counter, padded, b"")
        msg.extend(encPayload)
        return(bytes(msg))

    # function that decrypts a message to be received from server
    def decrypt_msg(self, ciphText):
        if len (ciphText) < 16:
            return None
        if not self.receiving_key:
            return None
        
        msgType = ciphText[0] 
        if msgType != 0x04:
            return None

        recIndex = int.from_bytes(ciphertext[4:8], byteorder='little') # receiver index
        if recIndex != self.sender_index:
            return None
            
        count = int.from_bytes(ciphText[8:16], byteorder='little')
        encryptedTxt = ciphText[16:]
        
        # payload decryption
        try:
            padded = self.AEAD_decrypt(
                self.receiving_key,
                count,
                encryptedTxt,
                b""
            )
            # Remove last zero bytes (padding)
            plainTxt = padded.rstrip(b"\x00")
            self.receiving_counter = count + 1
            return plainTxt
        except:
            return None