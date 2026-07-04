# Handshake protocol reference

This page documents how the three handshake variants in `poorman_handshake`
derive a shared secret, and where each fits in the HiveMind mesh. For the
quickstart and API surface, see the [README](../README.md).

## Where this sits in HiveMind

A HiveMind satellite and the [hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core)
hub establish an encrypted channel before exchanging any bus traffic. The
shared secret produced by a handshake here is the input to that channel's
authenticated symmetric encryption. The access key handed out by
`hivemind-core add-client` is the pre-shared password consumed by the
password path below.

## Symmetric path — `PasswordHandShake`

Both parties already share a password and derive a symmetric key without ever
sending the password over the wire. This is Usenet **hSub** (hashed-subject)
addressing repurposed as a key-confirmation step.

> **It is not a PAKE, despite the shape.** A checkable image of the password
> (`SHA256(IV ‖ password)`, IV public) travels on the wire, so a passive
> observer can mount an **offline dictionary attack** against a weak password.
> Use a high-entropy access key here, and read [`security.md`](security.md)
> before relying on this path — it is a worked example of why the distinction
> matters.

1. Each party generates a random 64-bit IV (`generate_iv`).
2. Each derives a **hsub** (hashed subject) binding the IV to the password
   (`create_hsub`) and sends it as the handshake message.
3. On receipt, each party extracts the peer's IV (`iv_from_hsub`) and verifies
   the hsub against the shared password (`match_hsub`). A mismatch means the
   peer does not hold the password — the handshake is rejected.
4. The two IVs are XORed into a common salt, and the final key is derived with
   PBKDF2-HMAC-SHA256 over the password and that salt.

Because the salt mixes both IVs, neither side alone fixes the key, and the
password itself never travels.

```python
from poorman_handshake import PasswordHandShake
from secrets import compare_digest

a = PasswordHandShake("shared access key")
b = PasswordHandShake("shared access key")
ha, hb = a.generate_handshake(), b.generate_handshake()
assert a.receive_and_verify(hb) and b.receive_and_verify(ha)
assert compare_digest(a.secret, b.secret)
```

## Asymmetric path — `HandShake`

Mutual RSA key agreement where **both** parties contribute randomness, so a
single compromised party cannot dictate the key.

1. Each party owns an RSA keypair (generated, or loaded from a PEM file via the
   `path` constructor argument for a stable identity).
2. Public keys are exchanged out of band and loaded with `load_public`.
3. Each party picks a random secret, signs it (RSA-PSS), encrypts it to the
   peer's public key (RSA-OAEP), and sends the concatenation as the handshake.
4. `receive_and_verify` checks the signature against the peer's public key,
   decrypts the peer's secret, and XORs it with the locally chosen secret.

The final `secret` is the XOR of both contributions, so it is identical on both
ends and depends on input from each.

```python
from poorman_handshake import HandShake
from secrets import compare_digest

a, b = HandShake(), HandShake()
a.load_public(b.pubkey); b.load_public(a.pubkey)
ha, hb = a.generate_handshake(), b.generate_handshake()
a.receive_and_verify(hb); b.receive_and_verify(ha)
assert compare_digest(a.secret, b.secret)
```

### One-way — `HalfHandShake`

Subclass of `HandShake` for asymmetric trust: the **sender** chooses the secret
and the **receiver** authenticates the sender. Only the sender's contribution
is used (no XOR), so only the receiver needs the sender's public key in
advance.

```python
from poorman_handshake import HalfHandShake
from secrets import compare_digest

sender, receiver = HalfHandShake(), HalfHandShake()
receiver.load_public(sender.pubkey)            # sender pubkey known to receiver
shake = sender.generate_handshake(receiver.pubkey)
receiver.receive_and_verify(shake)
assert compare_digest(receiver.secret, sender.secret)
```

## Identity and trust models

`HandShake(path=...)` loads or creates a persistent private key, giving a node a
stable public identity across restarts. With stable keys you can layer a trust
model on top of the raw exchange:

- **TOFU (trust on first use)** — pin a peer's public key the first time it is
  seen and reject changes thereafter. See `examples/tofu_handshake.py`.
- **Pre-distributed keys** — ship known public keys out of band and refuse
  unknown peers. See `examples/static_handshake.py`.

The `examples/*_mitm.py` scripts demonstrate why out-of-band public-key
validation matters: without it, an attacker who can relay messages can sit
between two parties. The signature step prevents tampering, but only if each
side already knows the other's authentic public key.

## Low-level RSA helpers

`poorman_handshake.asymmetric.utils` exposes the primitives the handshake is
built from, usable directly for ad-hoc encryption or signing:

- `encrypt_RSA` / `decrypt_RSA` — RSA-OAEP for short payloads.
- `hybrid_encrypt_RSA` / `hybrid_decrypt_RSA` — RSA-wrapped AES-GCM for
  arbitrary-length payloads.
- `sign_RSA` / `verify_RSA` — RSA-PSS signatures.
- `load_RSA_key` / `export_RSA_key` / `create_RSA_key` — PEM key management.

## Security caveats

This library is the bootstrap primitive, not a full secure-transport stack.
The derived `secret` must be used with authenticated encryption (AES-GCM,
ChaCha20-Poly1305), and public-key distribution must be validated out of band.

Both paths have real limits that shape when they are safe to use: the password
path is offline-guessable and only safe with a high-entropy key, and the RSA
path provides **no forward secrecy**. These are analysed in depth — with the
threat model, the exact attacks, and why they are a cautionary tale about
composing your own crypto — in [`security.md`](security.md). Read it before
using either handshake outside its original context.
