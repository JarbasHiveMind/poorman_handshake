from poorman_handshake import HalfHandShake

"""
In this example alice needs to authenticate bob, 
but bob does not care who alice is 
Bob RSA keys are static
bob public key was exchanged securely
bob decides what the secret is and simply transmits it
"""
path_to_bob_key = "bob.asc"
bob = HalfHandShake(path_to_bob_key)

alice = HalfHandShake()
alice.load_public(bob.pubkey)  # previously exchanged securely


#### Insecure communication starts here

def do_the_shake(alice, bob):
    # exchange handshakes (encrypted with pubkey) over any insecure channel
    bob_shake = bob.generate_handshake(alice.pubkey)

    # read and verify handshakes
    alice.receive_and_verify(bob_shake)

    print("Success", alice.secret.hex())
    assert alice.secret == bob.secret


do_the_shake(alice, bob)
