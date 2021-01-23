# Poor Man's Handshake

securely exchange symmetric encryption keys over insecure channels

## Usage

Basic usage below, check [examples](./examples) folder for more advanced usage

```python
from poorman_handshake import HandShake
from secrets import compare_digest

bob = HandShake()
alice = HandShake()

# exchange public keys somehow
bob.load_public(alice.pubkey)
alice.load_public(bob.pubkey)

# exchange handshakes (encrypted with pubkey) over any insecure channel
alice_shake = alice.generate_secret()
bob_shake = bob.generate_secret()

assert not compare_digest(bob.secret, alice.secret)

# read and verify handshakes
bob.receive_and_verify(alice_shake)
alice.receive_and_verify(bob_shake)

assert compare_digest(bob.secret, alice.secret)
```

## How does it work

PGP keys are used only to exchange a symmetric key to be used in follow-up communications

if the public keys have been previously exchanged, this is secure, if not 
then you are still vulnerable to man in the middle attacks

Recommended usage is either pre sharing pubkeys some other way or [trust on 
first use](https://en.wikipedia.org/wiki/Trust_on_first_use)