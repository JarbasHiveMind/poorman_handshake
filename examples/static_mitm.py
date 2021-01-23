from poorman_handshake import HandShake

"""
In this example the RSA keys are static
On every new handshake the same private keys are used
the public keys were exchanged securely
you can verify you are communicating with the same node you got the keys from
"""
path_to_bob_key = "bob.asc"
path_to_alice_key = "alice.asc"

bob = HandShake(path_to_bob_key)
alice = HandShake(path_to_alice_key)
bob.load_public(alice.pubkey)  # previously exchanged securely
alice.load_public(bob.pubkey)  # previously exchanged securely


#### Insecure communication starts here

def do_the_shake(alice, bob):
    # exchange handshakes (encrypted with pubkey) over any insecure channel
    alice_shake = alice.generate_secret()
    bob_shake = bob.generate_secret()

    # read and verify handshakes
    bob.receive_and_verify(alice_shake)
    alice.receive_and_verify(bob_shake)

    print("Success", bob.secret)


# eve pretends to be bob
eve = HandShake()
eve.load_public(alice.pubkey)
try:
    do_the_shake(alice, eve)
except:
    print("alice did not trust eve")  # MitM failed
