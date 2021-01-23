from poorman_handshake import HandShake

"""
In this example the RSA keys are static
On every new handshake the same private keys are used
the public keys were exchanged insecurely
you can verify you are communicating with the same node you got the keys from 
you are still vulnerable to MitM on initial connection
"""
path_to_bob_key = "bob.asc"
path_to_alice_key = "alice.asc"

bob = HandShake(path_to_bob_key)
alice = HandShake(path_to_alice_key)


#### Insecure communication starts here


def do_the_shake(alice, bob):
    # exchange public keys over any insecure channel
    # trust on first use
    if not bob.target_key:
        bob.load_public(alice.pubkey)
        print("Bob now trusts Alice")
        # NOTE you probably want to save this (tied to an identity) and load
        # it before the next handshake, that's out of scope for this example

    if not alice.target_key:
        alice.load_public(bob.pubkey)
        print("Alice now trusts Bob")

    # exchange handshakes (encrypted with pubkey) over any insecure channel
    alice_shake = alice.generate_secret()
    bob_shake = bob.generate_secret()

    # read and verify handshakes
    bob.receive_and_verify(alice_shake)
    alice.receive_and_verify(bob_shake)

    print("Success", bob.secret)


do_the_shake(alice, bob)  # trust established
do_the_shake(alice, bob)
do_the_shake(alice, bob)
