# Poor Man's Handshake

Securely exchange symmetric encryption keys over insecure channels using either password-based or RSA public-key handshakes. This library provides the cryptographic bootstrap primitive for the HiveMind distributed mesh — nodes use it to establish a shared session secret before raising an encrypted channel.

## Features

- **Password-based key exchange** (`PasswordHandShake`): Derive a shared symmetric key from a pre-shared password without ever transmitting the password. Each party generates a random IV, hashes it with the password, and XORs the IVs to form a common salt. The final key is derived via PBKDF2-HMAC-SHA256.
- **RSA public-key exchange** (`HandShake`): Mutual RSA key agreement where both parties contribute a random secret. The secrets are XORed to form the final shared key, ensuring both contributions are needed.
- **Asymmetric exchange** (`HalfHandShake`): One-way key agreement for asymmetric trust scenarios (only one party's secret is used).
- **Hybrid RSA+AES-GCM encryption**: Arbitrary-length plaintext support via RSA-encrypted AES keys.
- **Key file management**: Automatic PEM key export/import with `.bak` recovery and regeneration on corruption.

## Installation

```bash
pip install poorman_handshake
```

Requires Python 3.10+ and `pycryptodomex >= 3.19.1`.

## Quick Start

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

`HalfHandShake` derives the secret directly without XOR, for scenarios where only one party's contribution matters:

```python
from poorman_handshake import HalfHandShake

server = HalfHandShake()
client = HalfHandShake()

client.load_public(server.pubkey)

# Client generates handshake
client_shake = client.generate_handshake()

# Server receives and derives the client's secret directly
server.receive_and_verify(client_shake)

# Both hold the same key (derived from client's secret only)
assert compare_digest(server.secret, client.secret)
```

## API Reference

### `PasswordHandShake`

Password-based authenticated key agreement (PAKE-like).

**Constructor:**
```python
PasswordHandShake(password: str)
```
- `password`: Pre-shared password string.

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
- `create_hsub(password, iv=None, hsublen=48) -> str`: Create a hex-encoded hashed subject (hsub).
- `match_hsub(hsub, password) -> bool`: Verify an hsub against a password.
- `iv_from_hsub(hsub) -> bytes`: Extract IV from an hsub.

## Examples

See the [examples](./examples) folder for additional use cases:
- `simple_handshake.py`: Basic RSA handshake.
- `static_handshake.py`: Persistent key file handshake.
- `tofu_handshake.py`: Trust-on-first-use (TOFU) key pinning.
- `half_handshake.py`: One-way key agreement.
- `poor_pake.py`: Password-based key exchange.
- `*_mitm.py` demos: Man-in-the-middle attack illustrations.

## Security Notes

This library is a **proof-of-concept for HiveMind's key bootstrap**. For production use in security-critical applications:
- Review cryptographic assumptions (PBKDF2 iteration count, RSA key size, OAEP/PSS parameters).
- Ensure channel integrity after handshake (the derived secret should be used with authenticated encryption like AES-GCM or ChaCha20-Poly1305).
- Validate out-of-band public key distribution (TOFU, PKI, or other models).
- Consider forward secrecy mechanisms if long-lived keys are at risk.

## License

Apache License 2.0 — see [LICENSE.md](./LICENSE.md).
