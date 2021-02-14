from poorman_handshake import HandShake

"""
In this example the RSA keys are ephemeral
You will be vulnerable to MitM attacks, you have no way of knowing if the 
received public keys are legit or from an attacker
"""


bob = HandShake()
alice = HandShake()

#### Insecure communication starts here


def do_the_shake(alice, bob):
    bob.load_public(alice.pubkey)
    alice.load_public(bob.pubkey)

    # exchange handshakes (encrypted with pubkey) over any insecure channel
    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    # read and verify handshakes
    bob.receive_and_verify(alice_shake)
    alice.receive_and_verify(bob_shake)

    print("Success", bob.secret)


do_the_shake(alice, bob)

# eve pretends to be bob
eve = HandShake()
eve.load_public(alice.pubkey)
do_the_shake(alice, eve)
print("alice thinks eve is bob")  # MitM success