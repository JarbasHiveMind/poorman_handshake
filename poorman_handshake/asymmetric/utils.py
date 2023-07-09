import os
import pgpy
from pgpy.constants import *
from datetime import datetime, timedelta


def export_private_key(path, key=None, binary=False, *args, **kwargs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = key or create_private_key(*args, **kwargs)
    if binary:
        with open(path, "wb") as f:
            f.write(bytes(key))
    else:
        with open(path, "w") as f:
            f.write(str(key))


def create_private_key(name="PoorManHandshake", expires=None):
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(name)
    if isinstance(expires, timedelta):
        expires = datetime.now() + expires
    key.add_uid(uid,
                usage={KeyFlags.Sign,
                       KeyFlags.EncryptCommunications},
                hashes=[HashAlgorithm.SHA512,
                        HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256,
                         SymmetricKeyAlgorithm.Camellia256],
                compression=[CompressionAlgorithm.BZ2,
                             CompressionAlgorithm.ZIP,
                             CompressionAlgorithm.Uncompressed],
                expiry_date=expires)
    return key

