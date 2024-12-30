import logging
import os
import warnings
from typing import Tuple, Union

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss


def export_private_key(path, key=None):
    """
    Deprecated function for exporting an RSA private key.
    Logs a deprecation warning and redirects to export_RSA_key.

    Args:
        path (str): File path to save the key.
        key: The RSA private key.

    Returns:
        None
    """
    warnings.warn(
        "export_private_key is deprecated and will be removed in a future version. "
        "Use export_RSA_key instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    logging.warning(
        "export_private_key is deprecated and will be removed in a future version. Use export_RSA_key instead."
    )
    key = key or RSA.generate(2048)
    export_RSA_key(key, path)


def create_private_key(name="PoorManHandshake", expires=None):
    """
    Deprecated function for creating an RSA private key.
    Logs a deprecation warning and creates a new RSA key.

    Args:
        name (str): Unused parameter for naming the key.
        expires: Unused parameter for key expiration.

    Returns:
        RSA.RsaKey: The generated RSA private key.
    """
    warnings.warn(
        "create_private_key is deprecated and will be removed in a future version. "
        "Use create_RSA_key instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    logging.warning(
        "create_private_key is deprecated and will be removed in a future version. Use create_RSA_key instead."
    )
    k = RSA.generate(2048)
    # add property that NodeIdentity expects for compat
    k.pubkey = k.public_key().export_key(format="PEM").decode("utf-8")
    return k


def export_RSA_key(key: Union[str, bytes, RSA.RsaKey], path: str):
    """
    Exports an RSA key (public or private) to a file in PEM format.

    Args:
        key (Union[str, bytes, RSA.RsaKey]): The RSA key to export. Can be a string, bytes, or an RSA.RsaKey object.
        path (str): The file path where the key will be saved.

    Returns:
        None
    """
    base = os.path.dirname(path)
    if base:
        os.makedirs(base, exist_ok=True)
    if isinstance(key, RSA.RsaKey):
        key = key.export_key(format="PEM")
    if isinstance(key, str):
        key = key.encode("utf-8")
    with open(path, "wb") as f:
        f.write(key)


def load_RSA_key(path: str) -> RSA.RsaKey:
    """
    Loads an RSA key (public or private) from a file.

    Args:
        path (str): The file path to the PEM-formatted key.

    Returns:
        RSA.RsaKey: The loaded RSA key.
    """
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def create_RSA_key(key_size=2048) -> Tuple[str, str]:
    """
    Generates a new RSA key pair.

    Args:
        key_size (int, optional): The size of the RSA key in bits. Default is 2048.

    Returns:
        Tuple[str, str]: A tuple containing the public key and private key as PEM-encoded strings.
    """
    mykey = RSA.generate(key_size)
    secret = mykey.export_key(format="PEM").decode("utf-8")
    pub = mykey.public_key().export_key(format="PEM").decode("utf-8")
    return pub, secret


def encrypt_RSA(public_key: Union[str, bytes, RSA.RsaKey], plaintext: Union[str, bytes]) -> bytes:
    """
    Encrypts plaintext using an RSA public key.

    Args:
        public_key (Union[str, bytes, RSA.RsaKey]): The RSA public key to use for encryption.
        plaintext (Union[str, bytes]): The plaintext to encrypt. Can be a string or bytes.

    Returns:
        bytes: The encrypted ciphertext.
    """
    if isinstance(public_key, RSA.RsaKey):
        key = public_key
    else:
        key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return cipher.encrypt(plaintext)


def decrypt_RSA(secret_key: Union[str, bytes, RSA.RsaKey], ciphertext: Union[str, bytes]) -> bytes:
    """
    Decrypts ciphertext using an RSA private key.

    Args:
        secret_key (Union[str, bytes, RSA.RsaKey]): The RSA private key to use for decryption.
        ciphertext (Union[str, bytes]): The ciphertext to decrypt. Can be bytes or a string (if encoded).

    Returns:
        bytes: The decrypted plaintext.
    """
    if isinstance(secret_key, RSA.RsaKey):
        key = secret_key
    else:
        key = RSA.import_key(secret_key)
    cipher = PKCS1_OAEP.new(key)
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode("utf-8")
    return cipher.decrypt(ciphertext)


def sign_RSA(secret_key: Union[str, bytes, RSA.RsaKey], message: Union[str, bytes]) -> bytes:
    """
    Signs a message using an RSA private key.

    Args:
        secret_key (Union[str, bytes, RSA.RsaKey]): The RSA private key to use for signing.
        message (Union[str, bytes]): The message to sign. Can be a string or bytes.

    Returns:
        bytes: The signature of the message.
    """
    if isinstance(secret_key, RSA.RsaKey):
        key = secret_key
    else:
        key = RSA.import_key(secret_key)
    if isinstance(message, str):
        message = message.encode("utf-8")
    h = SHA256.new(message)
    return pss.new(key).sign(h)


def verify_RSA(public_key: Union[str, bytes, RSA.RsaKey], message: Union[str, bytes],
               signature: bytes) -> bool:
    """
    Verifies a signature using an RSA public key.

    Args:
        public_key (Union[str, bytes, RSA.RsaKey]): The RSA public key to use for verification.
        message (Union[str, bytes]): The message whose signature needs to be verified. Can be a string or bytes.
        signature (bytes): The signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    if isinstance(public_key, RSA.RsaKey):
        key = public_key
    else:
        key = RSA.import_key(public_key)
    if isinstance(message, str):
        message = message.encode("utf-8")
    h = SHA256.new(message)
    verifier = pss.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    pub, sec = create_RSA_key()
    m = "attack at dawn"
    encrypted = encrypt_RSA(pub, m)
    assert decrypt_RSA(sec, encrypted).decode("utf-8") == m

    signature = sign_RSA(sec, encrypted)
    print(verify_RSA(pub, encrypted, signature))
    print(len(signature))
