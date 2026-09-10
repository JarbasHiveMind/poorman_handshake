from poorman_handshake.noise import NoiseHandShake

"""
Noise KKpsk0 handshake — the pre-provisioned variant.

Use this when both peers already hold each other's static public keys (for
example, keys pinned from a previous XXpsk2 handshake, or distributed out of
band). KK authenticates both static keys from the very first message and is a
two-message pattern.

As in the XX example, the shared password enters as the PSK, so authentication
does not depend on transport security.
"""

PASSWORD = "correct horse battery staple"
NODE_ID = "server-01"

# Persist each side's static X25519 key so it survives restarts (and so pins
# established elsewhere keep matching).
alice_key = "alice_noise.key"
bob_key = "bob_noise.key"

# First, learn each other's static public keys (any prior channel / pinning).
alice_pub = NoiseHandShake(initiator=True, password=PASSWORD, node_id=NODE_ID,
                           path=alice_key).pubkey
bob_pub = NoiseHandShake(initiator=False, password=PASSWORD, node_id=NODE_ID,
                         path=bob_key).pubkey

# Now run KKpsk0 with the remote static key supplied up front (this selects the
# KK pattern automatically).
alice = NoiseHandShake(initiator=True, password=PASSWORD, node_id=NODE_ID,
                       path=alice_key, remote_pubkey=bob_pub)
bob = NoiseHandShake(initiator=False, password=PASSWORD, node_id=NODE_ID,
                     path=bob_key, remote_pubkey=alice_pub)

#### Insecure communication starts here

msg1 = alice.write_message()   # -> psk, e, es, ss
bob.read_message(msg1)

msg2 = bob.write_message()     # -> e, ee, se
alice.read_message(msg2)

assert alice.handshake_finished and bob.handshake_finished
print("KK handshake complete — mutual static-key authentication from message one.")

#### Encrypted session starts here

ciphertext = alice.encrypt(b"hello again")
print("bob decrypts:", bob.decrypt(ciphertext))
