# Poor Man's Handshake

Securely exchange symmetric encryption keys over insecure channels using a Noise-framework handshake or the legacy password / RSA handshakes. This library provides the cryptographic bootstrap primitive for the HiveMind distributed mesh — nodes use it to establish a shared session secret before raising an encrypted channel.

> **Which handshake should I use?** The **Noise handshake** (`NoiseHandShake`) is the recommended path: it adds forward secrecy, PAKE-grade password authentication (no offline-crackable image on the wire), replay resistance, and downgrade protection that the password and RSA handshakes lack. The legacy handshakes remain for interoperability with existing deployments. See [`docs/security.md`](docs/security.md) for the full analysis of why.

## Features

- **Noise handshake** (`NoiseHandShake`): A [Noise Protocol Framework](https://noiseprotocol.org/) authenticated key exchange (`Noise_XXpsk2` / `Noise_KKpsk0` over X25519 + ChaCha20-Poly1305 + SHA-256). The shared password enters as the Noise PSK — never as an on-wire image — and session keys come from an ephemeral X25519 exchange, giving **forward secrecy**, **PAKE-grade** password authentication, per-message **replay resistance**, and prologue-bound **downgrade protection**. Static keys are learned during `XX` for trust-on-first-use pinning. This is HiveMind protocol v3.
- **Password-based key exchange** (`PasswordHandShake`): Derive a shared symmetric key from a pre-shared password without ever transmitting the password. Each party generates a random IV, hashes it with the password, and XORs the IVs to form a common salt. The final key is derived via PBKDF2-HMAC-SHA256. Note: the on-wire verifier is an offline-crackable image of the password (safe only with a high-entropy secret) — prefer `NoiseHandShake`.
- **RSA public-key exchange** (`HandShake`): Mutual RSA key agreement where both parties contribute a random secret. The secrets are XORed to form the final shared key, ensuring both contributions are needed.
- **Asymmetric exchange** (`HalfHandShake`): One-way key agreement for asymmetric trust scenarios (only one party's secret is used).
- **Hybrid RSA+AES-GCM encryption**: Arbitrary-length plaintext support via RSA-encrypted AES keys.
- **Key file management**: Automatic PEM key export/import with `.bak` recovery and regeneration on corruption.

## Installation

```bash
pip install poorman_handshake
```

Requires Python 3.10+, `pycryptodomex >= 3.19.1`, `noiseprotocol >= 0.3.1`, `argon2-cffi >= 21.3.0`, and `zxcvbn >= 4.4.28` (for password-strength checking).

## Quick Start

### Noise handshake (recommended)

Both peers share a site *password*; the connecting node initiates. The default
`XXpsk2` pattern needs no prior knowledge of the peer's static key — each side
learns and can pin it during the exchange.

```python
from poorman_handshake.noise import NoiseHandShake

# alice = connecting node (initiator); bob = server (responder).
# node_id is the server's id, used as the PSK derivation salt.
alice = NoiseHandShake(initiator=True, password="site-password", node_id="server-01")
bob = NoiseHandShake(initiator=False, password="site-password", node_id="server-01")

# XXpsk2 is three messages, exchanged over any insecure channel (no TLS needed):
bob.read_message(alice.write_message())    # msg 1: e
alice.read_message(bob.write_message())    # msg 2: e, ee, s, es, psk
bob.read_message(alice.write_message())    # msg 3: s, se

assert alice.handshake_finished and bob.handshake_finished
assert alice.remote_pubkey == bob.pubkey_bytes   # learned static key — pin it (TOFU)

# Encrypted session: per-message counter nonces make replays fail to decrypt.
ciphertext = alice.encrypt(b"hello over the mesh")
assert bob.decrypt(ciphertext) == b"hello over the mesh"
```

Pre-provisioned peers (both static keys known in advance) select the two-message
`KKpsk0` pattern automatically by passing `remote_pubkey=`. See
[`examples/noise_kk.py`](examples/noise_kk.py).

### Password-based handshake

Both parties share a pre-arranged password and derive an identical symmetric key:

```python
from poorman_handshake import PasswordHandShake
from secrets import compare_digest

password = "Super Secret Pass Phrase"
bob = PasswordHandShake(password)
alice = PasswordHandShake(password)

# Generate handshake messages (exchange these over any insecure channel)
alice_shake = alice.generate_handshake()
bob_shake = bob.generate_handshake()

# Receive and verify each other's handshake
if not alice.receive_and_verify(bob_shake):
    raise ValueError("Failed to verify handshake")
if not bob.receive_and_verify(alice_shake):
    raise ValueError("Failed to verify handshake")

# Both now hold the same symmetric key
assert compare_digest(alice.secret, bob.secret)
```

### RSA public-key handshake

Mutual key agreement using RSA public keys (with signature verification):

```python
from poorman_handshake import HandShake
from secrets import compare_digest

bob = HandShake()
alice = HandShake()

# Exchange public keys out-of-band (e.g., over a secure channel or pre-distributed)
bob.load_public(alice.pubkey)
alice.load_public(bob.pubkey)

# Generate signed, encrypted handshake messages
alice_shake = alice.generate_handshake()
bob_shake = bob.generate_handshake()

# Receive, verify, and decrypt each other's handshakes
bob.receive_and_verify(alice_shake)
alice.receive_and_verify(bob_shake)

# Both now hold an identical shared secret
assert compare_digest(bob.secret, alice.secret)
print(f"Shared secret: {alice.secret.hex()}")
```

### One-way handshake (asymmetric trust)

`HalfHandShake` derives the secret directly without XOR, for scenarios where only one party's contribution matters. The sender chooses the secret and encrypts it with the receiver's public key; the receiver authenticates the sender and decrypts the secret. Only the receiver needs the sender's public key in advance:

```python
from poorman_handshake import HalfHandShake
from secrets import compare_digest

sender = HalfHandShake()
receiver = HalfHandShake()

# The receiver holds the sender's public key (exchanged securely beforehand)
receiver.load_public(sender.pubkey)

# The sender encrypts its secret with the receiver's public key
sender_shake = sender.generate_handshake(receiver.pubkey)

# The receiver verifies the sender's signature and decrypts the secret
receiver.receive_and_verify(sender_shake)

# Both hold the same key (chosen by the sender)
assert compare_digest(receiver.secret, sender.secret)
```

## API Reference

### `NoiseHandShake`

Noise-framework authenticated key exchange (HiveMind protocol v3). Recommended.

**Constructor:**
```python
NoiseHandShake(
    initiator: bool,
    path: str = None,
    password: str | bytes = None,
    node_id: str | bytes = None,
    psk: bytes = None,
    remote_pubkey: str | bytes = None,
    prologue: bytes = b"",
    pattern: bytes = None,
)
```
- `initiator`: `True` for the connecting side, `False` for the responder.
- `path`: Optional file to load/persist the static X25519 key (generated if absent).
- `password` / `node_id`: Shared password, stretched into the 32-byte PSK with argon2id salted by `SHA-256(node_id)`. Provide either this pair or `psk`.
- `psk`: A pre-derived 32-byte pre-shared key (alternative to `password`).
- `remote_pubkey`: Peer static public key (hex or 32 raw bytes). Supplying it selects `KKpsk0`; omitting it uses `XXpsk2` (learn-and-pin).
- `prologue`: Bytes bound into the handshake hash for downgrade protection; both sides must supply identical bytes. Encode the negotiated protocol version and cipher/encoding lists here.
- `pattern`: Override the Noise protocol name (defaults per `remote_pubkey`).

**Methods:**
- `write_message(payload: bytes = b"") -> bytes`: Produce the next handshake message (or, once finished, a transport message).
- `read_message(data: bytes) -> bytes`: Consume the peer's next message.
- `split() -> (send, recv)`: The two transport `CipherState`s after the handshake.
- `encrypt(data: bytes) -> bytes` / `decrypt(data: bytes) -> bytes`: Transport encryption using the split CipherStates (per-message counter nonces → replay resistant).
- `load_private(path)` / `export_private_key(path)`: Static-key persistence.

**Properties:**
- `handshake_finished: bool`: Whether the handshake is complete.
- `pubkey: str` / `pubkey_bytes: bytes`: This node's static public key.
- `remote_pubkey: bytes | None`: The peer's static public key (learned during `XX`); pin it for TOFU.
- `handshake_hash: bytes | None`: Shared transcript fingerprint for channel binding.

### `derive_psk(password, node_id=None, salt=None) -> bytes`

Derive a 32-byte Noise PSK from a password using argon2id. The salt defaults to `SHA-256(node_id)` (per HIVEMIND-CRYPTO-1) when `node_id` is given. Both peers must derive with identical inputs.

### `PasswordHandShake`

Password-based key agreement. **Not a PAKE** — the handshake transmits a salted-hash *verifier* of the password, which a passive observer can attack offline; it is safe only with a high-entropy shared secret. For a low-entropy password, use `NoiseHandShake` instead (see [`docs/security.md`](docs/security.md)).

**Constructor:**
```python
PasswordHandShake(password: str, min_bits: float = 40)
```
- `password`: Pre-shared password string.
- `min_bits`: Minimum estimated guess resistance (bits, via zxcvbn). The constructor raises `WeakPasswordError` for a weaker password. Pass `min_bits=0` to disable the check (e.g. for a machine-generated high-entropy secret).

> ⚠️ **Breaking:** since the on-wire verifier is offline-crackable, weak passwords are now **refused** by default. Use a strong passphrase, `min_bits=0` to opt out, or prefer `NoiseHandShake`.

**Methods:**
- `generate_handshake() -> str`: Generate a hex-encoded handshake message (hsub).
- `receive_handshake(shake: str) -> None`: Process a peer's handshake and compute salt.
- `verify(shake: str) -> bool`: Check if a handshake matches the password.
- `receive_and_verify(shake: str) -> bool`: Verify and receive in one step.

**Properties:**
- `secret: bytes`: Derived symmetric key (bytes). Only valid after successful `receive_handshake`.

### `HandShake`

Mutual RSA key agreement with signature verification.

**Constructor:**
```python
HandShake(path: str = None, key_size: int = 2048)
```
- `path`: Optional file path to load/save the private key (PEM format).
- `key_size`: RSA key size in bits (default 2048).

**Methods:**
- `generate_handshake(pub: Union[str, bytes, RSA.RsaKey] = None) -> str`: Generate a signed, encrypted handshake message.
- `load_public(pub: Union[str, bytes, RSA.RsaKey]) -> None`: Load the peer's public key.
- `load_private(path: str) -> None`: Load the private key from a file.
- `export_private_key(path: str) -> None`: Save the private key to a file (PEM format).
- `verify(shake: str, pub: Union[str, bytes, RSA.RsaKey]) -> bool`: Verify a handshake signature.
- `receive_handshake(shake: str) -> None`: Decrypt a handshake and XOR with locally generated secret.
- `receive_and_verify(shake: str, pub: Union[str, bytes, RSA.RsaKey] = None) -> None`: Verify signature, then receive.

**Properties:**
- `pubkey: str`: PEM-encoded public key.
- `secret: bytes`: Shared symmetric key (derived from XOR of both secrets).

### `HalfHandShake`

Extends `HandShake` for one-way key agreement. Same API, but `receive_handshake` assigns the decrypted secret directly instead of XORing.

## Asymmetric Path (RSA Utilities)

Low-level RSA operations in `poorman_handshake.asymmetric.utils`:

- `encrypt_RSA(public_key, plaintext) -> bytes`: RSA-OAEP encryption.
- `decrypt_RSA(secret_key, ciphertext) -> bytes`: RSA-OAEP decryption.
- `sign_RSA(secret_key, message) -> bytes`: RSA-PSS signature.
- `verify_RSA(public_key, message, signature) -> bool`: Verify RSA-PSS signature.
- `hybrid_encrypt_RSA(public_key, plaintext) -> bytes`: RSA + AES-GCM for arbitrary-length payloads.
- `hybrid_decrypt_RSA(secret_key, ciphertext) -> bytes`: Decrypt hybrid ciphertext.
- `load_RSA_key(path) -> RSA.RsaKey`: Load PEM key from file.
- `export_RSA_key(key, path) -> None`: Save PEM key to file.

## Symmetric Path (Password Utilities)

Low-level PAKE operations in `poorman_handshake.symmetric.utils`:

- `generate_iv(key_length=8) -> bytes`: Generate a random 64-bit IV.
- `create_hsub(text, iv=None, hsublen=48) -> str`: Create a hex-encoded hashed subject (hsub) from the shared secret `text`.
- `match_hsub(hsub, subject) -> bool`: Verify an hsub against the shared secret `subject`.
- `iv_from_hsub(hsub, digits=16) -> bytes`: Extract the IV from an hsub.

## Examples

See the [examples](./examples) folder for additional use cases:
- `noise_handshake.py`: Noise `XXpsk2` password handshake with TOFU key learning (**recommended**).
- `noise_kk.py`: Noise `KKpsk0` handshake with pre-provisioned static keys.
- `simple_handshake.py`: Basic RSA handshake.
- `static_handshake.py`: Persistent key file handshake.
- `tofu_handshake.py`: Trust-on-first-use (TOFU) key pinning.
- `half_handshake.py`: One-way key agreement.
- `poor_pake.py`: Password-based key exchange.
- `*_mitm.py` demos: Man-in-the-middle attack illustrations.

## Deeper reference

[`docs/protocol.md`](./docs/protocol.md) walks through how each variant derives
its shared secret, the TOFU and pre-distributed-key trust models, the low-level
RSA helpers, and where the handshake fits in the HiveMind connection flow.

[`docs/security.md`](./docs/security.md) is the threat-model analysis: what each
construction protects against and what it does not, why the password and RSA
handshakes are safe in their origin but weak as a standalone live-link exchange,
and how the Noise handshake supplies the missing properties (offline-attack
resistance, forward secrecy, MITM resistance, transcript binding).

## Security Notes

The **Noise handshake** (`NoiseHandShake`) is the recommended path and provides forward secrecy, PAKE-grade password authentication, replay resistance, and downgrade protection out of the box. The legacy password and RSA handshakes remain for interoperability; when using them in security-critical applications:
- Prefer a high-entropy shared secret — the password verifier is offline-crackable (see [`docs/security.md`](./docs/security.md)).
- Ensure channel integrity after handshake (the derived secret should be used with authenticated encryption like AES-GCM or ChaCha20-Poly1305).
- Validate out-of-band public key distribution (TOFU, PKI, or other models).
- The RSA path has no forward secrecy — a later key compromise decrypts past sessions; use `NoiseHandShake` where that matters.

## License

Apache License 2.0 — see [LICENSE.md](./LICENSE.md).
