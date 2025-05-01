# Nova Adams-Duma: encryption implementation

class WireguardEncryption:
    # initialized encryption component with private / public keys
    def __init__(self, client_static_private_key, server_static_public_key):
        self.client_static_private_key = client_static_private_key # client's static private key
        self.server_static_public_key = server_static_public_key # server's static public key

        # Using eliptic curve cryptography, generate client's static public key
        self.client_static_public_key = nacl.bindings.crypto_scalarmult_base(self.client_static_private_key)

    def DH_Generate(self):

    def DH(self):

    def DH_Generate(self):

    def AEAD_encrypt(self):

    def AEAD_decrypt(self):

    def Hash(self):

    def MixHash(self):

    def Mac(self):

    def Hmac(self):
    
    def Kdf1(self):

    def Kdf2(self):
    
    def Kdf3(self):

    def Timestamp(self):

    def create_initiation_msg(self):
    
    def process_response_msg(self):
    
    def encrypt_msg(self):

    def decrypt_msg(self):