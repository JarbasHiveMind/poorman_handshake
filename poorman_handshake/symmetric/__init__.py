from poorman_handshake.symmetric.utils import *
import hashlib


class PasswordHandShake:
    def __init__(self, password):
        self.password = password
        self.iv = None
        self.salt = None

    def send_handshake(self):
        self.iv = generate_iv()
        return create_hsub(self.password, self.iv)

    def receive_handshake(self, password):
        if match_hsub(password, self.password):
            self.salt = bytes(a ^ b for (a, b) in
                              zip(self.iv, iv_from_hsub(password)))
            return True
        return False

    @property
    def secret(self):
        dk = hashlib.pbkdf2_hmac('sha256', self.password.encode("utf-8"),
                                 self.salt, 100000)
        return dk

