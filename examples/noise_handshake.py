from poorman_handshake.noise import NoiseHandShake

"""
Noise handshake (HiveMind protocol v3) — the recommended path.

Both peers share a site *password*. Unlike the password (hSub) handshake,
the password here enters as the Noise PSK: the on-wire messages are NOT an
offline-crackable image of it, and the session keys come from an ephemeral
X25519 exchange, so:

  - a passive observer cannot mount an offline dictionary attack (PAKE-grade);
  - past sessions stay secret even if the password later leaks (forward secrecy);
  - a machine-in-the-middle without the password cannot complete the handshake.

This example uses the default XXpsk2 pattern: neither side needs the other's
static key in advance; each *learns and can pin* it during the exchange (TOFU).
"""

# The shared secret, plus the server's node id (used as the PSK salt so two
# different servers derive different keys from the same password).
PASSWORD = "correct horse battery staple"
NODE_ID = "server-01"

# alice = the connecting node (initiator); bob = the server (responder).
alice = NoiseHandShake(initiator=True, password=PASSWORD, node_id=NODE_ID)
bob = NoiseHandShake(initiator=False, password=PASSWORD, node_id=NODE_ID)


#### Insecure communication starts here — these three messages may cross any
#### untrusted channel (no TLS required).

# XXpsk2 is a three-message pattern:
msg1 = alice.write_message()   # -> e
bob.read_message(msg1)

msg2 = bob.write_message()     # -> e, ee, s, es, psk
alice.read_message(msg2)

msg3 = alice.write_message()   # -> s, se
bob.read_message(msg3)

assert alice.handshake_finished and bob.handshake_finished
print("Handshake complete — both sides derived matching transport keys.")

# Trust-on-first-use: each side now holds the other's static public key and
# SHOULD pin it, so a later handshake with a different key is rejected.
assert alice.remote_pubkey == bob.pubkey_bytes
assert bob.remote_pubkey == alice.pubkey_bytes
print("Static keys learned and ready to pin (TOFU).")

# The handshake hash is a shared transcript fingerprint (channel binding).
assert alice.handshake_hash == bob.handshake_hash

#### Encrypted session starts here

# Transport messages carry per-CipherState counter nonces, so a replayed or
# reordered frame fails to decrypt — replay resistance for free.
ciphertext = alice.encrypt(b"hello over the mesh")
print("bob decrypts:", bob.decrypt(ciphertext))

reply = bob.encrypt(b"ack")
print("alice decrypts:", alice.decrypt(reply))
