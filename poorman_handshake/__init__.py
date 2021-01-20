import pgpy
from pgpy.constants import *
import random
from datetime import datetime, timedelta
import string


def random_key(key_lenght=16):
    """Generate a random string of letters and digits """
    valid_chars = string.ascii_letters + string.digits
    return ''.join(random.choice(valid_chars) for i in range(key_lenght))


class HandShake:
    def __init__(self):
        self.private_key = self.create_private()
        self.aes_key = None

    @staticmethod
    def create_private(name="PoorManHandshake", expires=None):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        uid = pgpy.PGPUID.new(name)
        expires = expires or datetime.now() + timedelta(minutes=15)
        key.add_uid(uid,
                    usage={KeyFlags.Sign,
                           KeyFlags.EncryptCommunications,
                           KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA512,
                            HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256,
                             SymmetricKeyAlgorithm.Camellia256],
                    compression=[CompressionAlgorithm.BZ2,
                                 CompressionAlgorithm.Uncompressed],
                    expiry_date=expires)
        return key

    @property
    def pubkey(self):
        if not self.private_key:
            return None
        return str(self.private_key.pubkey)

    @staticmethod
    def read_pubkey(pub):
        pubkey, _ = pgpy.PGPKey.from_blob(pub)
        return pubkey

    def communicate_key(self, pub):
        # read pubkey from client
        pubkey = self.read_pubkey(pub)
        self.aes_key = random_key()
        text_message = pgpy.PGPMessage.new(self.aes_key)
        encrypted_message = pubkey.encrypt(text_message)
        return str(encrypted_message)

    def receive_key(self, encrypted_message):
        message_from_blob = pgpy.PGPMessage.from_blob(encrypted_message)
        decrypted = self.private_key.decrypt(message_from_blob)
        self.aes_key = decrypted.message
