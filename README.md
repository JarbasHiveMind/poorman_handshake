# Poor Man's Handshake

securely exchange symmetric encryption keys over insecure channels

## Usage

Basic usage below, check [examples](./examples) folder for more advanced usage

A session key can be exchanged if there is a pre shared password

```python
from poorman_handshake import PasswordHandShake
from secrets import compare_digest

password = "Super Secret Pass Phrase"
bob = PasswordHandShake(password)
alice = PasswordHandShake(password)

alice_shake = alice.generate_handshake()
bob_shake = bob.generate_handshake()

# exchange handshakes (hsubs) over any insecure channel
if not alice.receive_handshake(bob_shake):
    raise KeyError
if not bob.receive_handshake(alice_shake):
    raise KeyError

# a common key was derived from the password
assert compare_digest(alice.secret, bob.secret)
```

Another possibility is to use PGP based key exchange

```python
from poorman_handshake import HandShake
from secrets import compare_digest

bob = HandShake()
alice = HandShake()

# exchange public keys somehow
bob.load_public(alice.pubkey)
alice.load_public(bob.pubkey)

# exchange handshakes (encrypted with pubkey) over any insecure channel
alice_shake = alice.generate_handshake()
bob_shake = bob.generate_handshake()

# read and verify handshakes
bob.receive_and_verify(alice_shake)
alice.receive_and_verify(bob_shake)

assert compare_digest(bob.secret, alice.secret)
```
