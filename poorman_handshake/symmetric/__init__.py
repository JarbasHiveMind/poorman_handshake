from poorman_handshake.symmetric.utils import *
import hashlib
import warnings


class PasswordHandShake:
    """Password-based key agreement (legacy; **discouraged**).

    Not a PAKE — the on-wire verifier is an offline-crackable image of the
    password. Prefer :class:`poorman_handshake.noise.NoiseHandShake`
    (see docs/security.md).
    """

    def __init__(self, password):
        warnings.warn(
            "PasswordHandShake is not a PAKE: it sends a salted-hash verifier of "
            "the password that a passive observer can attack offline, and it has "
            "no forward secrecy. It is kept for HiveMind protocol v0-v2 "
            "interoperability; for new code use "
            "poorman_handshake.noise.NoiseHandShake, or only use this with a "
            "high-entropy shared secret (see docs/security.md).",
            DeprecationWarning,
            stacklevel=2,
        )
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

