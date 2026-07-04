from poorman_handshake.symmetric.utils import *
from poorman_handshake.symmetric.strength import (
    check_password_strength,
    WeakPasswordError,
    DEFAULT_MIN_BITS,
)
import hashlib


class PasswordHandShake:
    """Password-based key agreement.

    Refuses low-entropy, guessable passwords: the constructor raises
    :class:`WeakPasswordError` unless the password's estimated guess resistance
    reaches ``min_bits`` (default :data:`DEFAULT_MIN_BITS`). Pass ``min_bits=0``
    to disable the check.

    The on-wire verifier is an offline-crackable image of the password, so this
    is safe only with a strong secret — prefer
    :class:`poorman_handshake.noise.NoiseHandShake` (see ``docs/security.md``).
    """

    def __init__(self, password, min_bits: float = DEFAULT_MIN_BITS):
        check_password_strength(password, min_bits)
        self.password = password
        self.iv = None
        self.salt = None

    def generate_handshake(self):
        self.iv = generate_iv()
        return create_hsub(self.password, self.iv)

    def receive_handshake(self, shake):
        self.salt = bytes(a ^ b for (a, b) in
                          zip(self.iv, iv_from_hsub(shake)))

    def receive_and_verify(self, shake):
        if self.verify(shake):
            self.receive_handshake(shake)
            return True
        return False

    def verify(self, shake):
        if match_hsub(shake, self.password):
            return True
        return False

    @property
    def secret(self):
        dk = hashlib.pbkdf2_hmac('sha256', self.password.encode("utf-8"),
                                 self.salt, 100000)
        return dk

