from os.path import isfile
from poorman_handshake.asymmetric.utils import *


class HandShake:
    def __init__(self, path=None, expires=None):
        if path:
            if path.endswith(".asc") or path.endswith(".txt"):
                binary = False
            else:
                binary = True
        if path and isfile(path):
            self.load_private(path, binary=binary)
        else:
            self.private_key = create_private_key(expires=expires)
            if path:
                self.export_private_key(path, binary)
        self.target_key = None
        self.secret = None

    def load_private(self, path, binary=False):
        if binary:
            with open(path, "rb") as f:
                key_blob = f.read()
        else:
            with open(path, "r") as f:
                key_blob = f.read()
        self.private_key = self.import_key(key_blob)

    def export_private_key(self, path, binary=False):
        return export_private_key(path, self.private_key, binary)

    @property
    def pubkey(self):
        if not self.private_key:
            return None
        return str(self.private_key.pubkey)

    @staticmethod
    def import_key(key_blob):
        pubkey, _ = pgpy.PGPKey.from_blob(key_blob)
        return pubkey

    def generate_handshake(self, pub=None):
        pub = pub or self.target_key
        # read pubkey from client
        pubkey = self.import_key(pub)
        # generate new key
        self.secret = SymmetricKeyAlgorithm.AES256.gen_key()
        text_message = pgpy.PGPMessage.new(self.secret)
        # encrypt generated key
        encrypted_message = pubkey.encrypt(text_message)
        # sign message
        # the bitwise OR operator '|' is used to add a signature to a PGPMessage.
        encrypted_message |= self.private_key.sign(encrypted_message,
                                                   intended_recipients=[pubkey])
        return str(encrypted_message)

    def load_public(self, pub):
        self.target_key = pub

    def receive_handshake(self, shake):
        message_from_blob = pgpy.PGPMessage.from_blob(shake)
        decrypted = self.private_key.decrypt(message_from_blob)
        # XOR
        self.secret = bytes(a ^ b for (a, b) in
                            zip(self.secret, decrypted.message))

    def verify(self, shake, pub):
        message = pgpy.PGPMessage.from_blob(shake)
        pubkey = self.import_key(pub)
        return pubkey.verify(message)

    def receive_and_verify(self, shake, pub=None):
        pub = pub or self.target_key
        verified = self.verify(shake, pub)
        if verified:
            self.receive_handshake(shake)


class HalfHandShake(HandShake):

    def generate_handshake(self, pub=None):
        enc = super().generate_handshake(pub)
        self.secret = bytes(self.secret)
        return enc

    def receive_handshake(self, shake):
        message_from_blob = pgpy.PGPMessage.from_blob(shake)
        decrypted = self.private_key.decrypt(message_from_blob)
        # XOR
        self.secret = bytes(decrypted.message)


