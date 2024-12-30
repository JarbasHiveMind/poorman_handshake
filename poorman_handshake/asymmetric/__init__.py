import os
from binascii import hexlify, unhexlify
from os.path import isfile
from typing import Union, Optional

import logging
import shutil
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

from poorman_handshake.asymmetric.utils import (
    load_RSA_key,
    export_RSA_key,
    decrypt_RSA,
    encrypt_RSA,
    sign_RSA,
    verify_RSA,
)


class HandShake:
    """
    Class for performing a secure handshake using RSA encryption and signatures.

    Attributes:
        private_key (RSA.RsaKey): The private RSA key for this handshake instance.
        target_key (RSA.RsaKey): The public key of the target for the handshake.
        secret (bytes): The shared secret generated during the handshake.
    """

    def __init__(self, path: str = None, key_size: int = 2048):
        """
        Initializes the HandShake instance.

        Args:
            path (str, optional): Path to load or save the private key.
            key_size (int, optional): Size of the RSA key in bits (default is 2048).
        """
        self.private_key = None
        if path and isfile(path):

            try:
                self.load_private(path)
            except ValueError:
                try:
                    backup_path = path + ".bak"
                    shutil.copy2(path, backup_path)
                    os.remove(path)
                    logging.warning(
                        f"Invalid RSA key format in '{path}'. "
                        f"Created backup at '{backup_path}' and will generate new key."
                    )
                except Exception as e:
                    raise ValueError(f"Failed to handle invalid key file: {e}")

        if not self.private_key:
            self.private_key = RSA.generate(key_size)
            if path:
                self.export_private_key(path)
        self.target_key = None
        self.secret = None

    def load_private(self, path: str):
        """
        Loads the private RSA key from a file.

        Args:
            path (str): Path to the private key file.
        """
        self.private_key = load_RSA_key(path)

    def export_private_key(self, path: str):
        """
        Exports the private RSA key to a file.

        Args:
            path (str): Path to save the private key.
        """
        secret = self.private_key.export_key(format="PEM")
        export_RSA_key(secret, path)

    @property
    def pubkey(self) -> str:
        """
        Returns the public key as a PEM-encoded string.

        Returns:
            str: PEM-encoded public key.
        """
        if not self.private_key:
            return None
        return self.private_key.public_key().export_key(format="PEM").decode("utf-8")

    def generate_handshake(self, pub: Optional[Union[str, bytes, RSA.RsaKey]]  = None) -> str:
        """
        Generates a handshake message encrypted with the target's public key.

        Args:
            pub (str, optional): Public key of the recipient in PEM format.

        Returns:
            bytes: Hex-encoded handshake message (signature + ciphertext).
        """
        pubkey = pub or self.target_key
        self.secret = get_random_bytes(32)  # Generate a new shared secret
        ciphertext = encrypt_RSA(pubkey, self.secret)  # Encrypt the secret
        signature = sign_RSA(self.private_key, ciphertext)  # Sign the ciphertext
        return hexlify(signature + ciphertext).decode("utf-8")

    def load_public(self, pub: Union[str, bytes, RSA.RsaKey]):
        """
        Loads the target's public RSA key.

        Args:
            pub (str): Public key in PEM format.
        """
        if isinstance(pub, RSA.RsaKey):
            self.target_key = pub
        else:
            self.target_key = RSA.import_key(pub)

    def receive_handshake(self, shake: Union[str, bytes]):
        """
        Processes a received handshake message to decrypt the shared secret.

        Args:
            shake (bytes): Hex-encoded handshake message (signature + ciphertext).
        """
        signature_size = self.private_key.size_in_bytes()
        ciphertext = unhexlify(shake)[signature_size:]  # Drop the signature
        decrypted = decrypt_RSA(self.private_key, ciphertext)
        # XOR the received secret with the existing one
        self.secret = bytes(a ^ b for a, b in zip(self.secret, decrypted))

    def verify(self, shake: Union[str, bytes], pub: Union[str, bytes, RSA.RsaKey]) -> bool:
        """
        Verifies the signature in a handshake message.

        Args:
            shake (bytes): Hex-encoded handshake message (signature + ciphertext).
            pub (str): Public key in PEM format of the sender.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        if isinstance(pub, RSA.RsaKey):
            signature_size = pub.size_in_bytes()
        else:
            signature_size = RSA.import_key(pub).size_in_bytes()
        ciphertext = unhexlify(shake)
        signature = ciphertext[:signature_size]
        ciphertext = ciphertext[signature_size:]
        return verify_RSA(pub, ciphertext, signature)

    def receive_and_verify(self, shake: Union[str, bytes],
                           pub: Optional[Union[str, bytes, RSA.RsaKey]] = None):
        """
        Verifies and processes a handshake message.

        Args:
            shake (bytes): Hex-encoded handshake message (signature + ciphertext).
            pub (str, optional): Public key in PEM format of the sender.
        """
        pub = pub or self.target_key
        if self.verify(shake, pub):
            self.receive_handshake(shake)


class HalfHandShake(HandShake):
    """
    A simpler handshake implementation where the shared secret is directly decrypted.
    """

    def receive_handshake(self, shake: Union[str, bytes]):
        """
        Processes a received handshake message to decrypt the shared secret.

        Args:
            shake (bytes): Hex-encoded handshake message (signature + ciphertext).
        """
        signature_size = self.private_key.size_in_bytes()
        ciphertext = unhexlify(shake)[signature_size:]  # Drop the signature
        self.secret = decrypt_RSA(self.private_key, ciphertext)
