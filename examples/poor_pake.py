from poorman_handshake import PasswordHandShake
from secrets import compare_digest
"""
derive a session key from pre shared passwords
"""

password = "Super Secret Pass Phrase"
bob = PasswordHandShake(password)
alice = PasswordHandShake(password)


#### Insecure communication starts here
eve = PasswordHandShake("WRONG PASSWORD")


def do_the_shake(alice, bob):
    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    # exchange handshakes (hsubs) over any insecure channel
    if not alice.receive_and_verify(bob_shake):
        raise KeyError
    if not bob.receive_and_verify(alice_shake):
        raise KeyError

    # a common key was derived from the password
    compare_digest(alice.secret, bob.secret)
    print("Shared key:", bob.secret.hex())


do_the_shake(alice, bob)
try:
    do_the_shake(alice, eve)
except KeyError:
    print("HANDSHAKE FAILED: pre shared passwords don't match")
