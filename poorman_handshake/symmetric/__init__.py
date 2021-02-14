from poorman_handshake.symmetric.utils import *
import hashlib


class PasswordHandShake:
    def __init__(self, password):
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

