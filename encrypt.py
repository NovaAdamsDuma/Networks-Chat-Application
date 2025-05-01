# Nova Adams-Duma: encryption implementation

class WireguardEncryption:
    # initialized encryption component with private / public keys
    def __init__(self, client_static_private_key, server_static_public_key):
        self.client_static_private_key = client_static_private_key # client's static private key
        self.server_static_public_key = server_static_public_key # server's static public key
    
        