# Security analysis — what these handshakes protect, and what they don't

This page is the honest threat analysis of the two handshakes in
`poorman_handshake`. It explains why each construction is *safe for the job it
was originally built to do*, why neither is *safe enough to be the sole key
exchange on a live, untrusted link*, and — because that gap is instructive —
what it teaches about building your own cryptographic protocols.

Read [`protocol.md`](protocol.md) first for how the handshakes actually work.
Everything below is grounded in the shipped code, not an idealized description.

## Threat model

A handshake here runs over an "insecure channel." Spell out what the adversary
can do, because the whole analysis turns on it:

- **Passive eavesdropper** — records every byte in both directions. Cannot
  modify traffic, but keeps the transcript forever and attacks it offline, at
  their own pace, on their own hardware.
- **Active attacker** — can also inject, drop, reorder, replay, and modify
  messages, and can sit between two parties as a machine-in-the-middle (MITM).
- **Later compromise** — may, at some future point, obtain a node's long-term
  private key (theft, seizure, a decommissioned disk, cryptanalytic progress).

A key-exchange primitive that is meant to secure real traffic should ideally
resist all three. The properties that correspond to them have names:

- **Offline-dictionary resistance** — a captured transcript must not let the
  attacker *test password guesses offline*. Guesses should only be checkable by
  talking to the honest party, where they can be rate-limited. This is the
  defining property of a **PAKE** (Password-Authenticated Key Exchange).
- **Forward secrecy (FS)** — compromising a long-term key later must not
  decrypt sessions captured earlier.
- **Authentication / MITM resistance** — each party must be sure it shares the
  key with the intended peer and no one in the middle.
- **Transcript / downgrade binding** — the negotiated parameters must be
  authenticated, so an attacker cannot silently force a weaker mode.

Hold the two handshakes against this list.

## The password path (`PasswordHandShake`)

### What it actually does

From `poorman_handshake/symmetric/`:

1. Each side picks a random 64-bit IV and sends
   `hsub = hex(IV ‖ SHA256(IV ‖ password))`, truncated to 48 hex chars — i.e.
   the 64-bit IV followed by **128 bits of the SHA-256** of `IV ‖ password`.
2. Each side verifies the peer's `hsub` by recomputing it with the peer's IV
   (stripped from the message) and comparing.
3. The shared salt is `IV_self XOR IV_peer` — both IVs are on the wire.
4. The session key is `PBKDF2-HMAC-SHA256(password, salt, 100_000)`.

The password itself is never transmitted.

### Why this is safe — for what it was built for

This is **hSub (hashed-subject)** technology from Usenet nym remailers. There,
its job is *unlinkable addressing*: a recipient scans `alt.anonymous.messages`,
recomputes `SHA256(IV ‖ passphrase)` for each Subject line, and recognizes
"this message is for me" — while an observer cannot link a post to a recipient.
Message **confidentiality is a completely separate PGP layer** encrypted to the
nym's key. hSub is the label on the mailbox; PGP is the lock.

In that setting the construction is sound, and for a good reason: it is fine
that the label is a directly recomputable function of the passphrase, because
cracking the label only *de-anonymizes a nym* — the body stays PGP-sealed. The
recipient **must** be able to recompute the hash (that is how they recognize
their own mail), so being offline-checkable is a feature, not a flaw.

And there is a case where it is genuinely fine here too: if the "password" is a
**high-entropy random key** (say ≥128 bits), there is simply nothing to
enumerate, and every attack below evaporates. The construction keeps the
password secret; the only question is whether the password is *guessable*.

### Why it is not safe enough as a live handshake

The moment this becomes the sole key exchange on a live link — with **no PGP
layer underneath** and a **human-chosen password** — the very property that
made it a good address makes it a liability.

1. **It is not a PAKE, though it looks like one.** The wire carries
   `SHA256(IV ‖ password)` with the IV public: a *checkable image* of the
   password. A passive eavesdropper who captures one handshake runs an
   **offline dictionary attack** —
   ```
   for guess in wordlist:
       if SHA256(IV ‖ guess)[:128 bits] == captured_hash:
           password = guess
   ```
   — with no server round-trip, nothing to rate-limit, and nothing to alert on.
   *"The password never crosses the wire"* is true and irrelevant: you do not
   need the password on the wire, you need a way to **test guesses**, and the
   hash is exactly that. Secrecy of the material is not unguessability.

2. **The work factor is trivial.** The oracle is a bare SHA-256, on the order of
   billions of guesses per second on a commodity GPU. A memorable access key
   ("attic-pi", "hivemind123") falls in seconds to hours. Note that the
   `PBKDF2(..., 100_000)` stretching **does not help**: the attacker cracks the
   fast, unstretched SHA-256 verifier, then runs the recovered password through
   PBKDF2 themselves. The KDF protects the derived key from precomputation; it
   does nothing for the password, because a cheaper oracle sits right beside it.

3. **The salt is public.** `salt = IV_a XOR IV_b`, both IVs on the wire, so
   PBKDF2's salt provides no secrecy — only mild cross-handshake amortization
   resistance.

4. **No forward secrecy.** The key is a deterministic function of the password
   alone (the IVs merely salt it and are not secret). Recover the password once
   and *every* past and future session under it is readable. Nothing ephemeral
   is ever contributed.

5. **No transcript binding.** Shared knowledge of the password gives a weak form
   of mutual authentication, but nothing binds the exchange's parameters, and
   combined with (4) a MITM who later learns the (weak) password owns all of it
   retroactively.

The contrast with a real PAKE is the whole point: against a PAKE, a captured
transcript yields **no offline oracle at all**. The only way to test a password
guess is to run a fresh exchange with the honest server — an *online* guess it
can throttle and lock. That single property is what makes a weak, memorable
password safe, and it is precisely what this construction lacks.

## The RSA path (`HandShake` / `HalfHandShake`)

### What it actually does

From `poorman_handshake/asymmetric/`:

1. Each side owns an RSA-2048 keypair and picks a random 32-byte secret.
2. It encrypts the secret to the peer's public key with **RSA-OAEP**, signs the
   ciphertext with **RSA-PSS**, and sends `signature ‖ ciphertext`.
3. `receive_and_verify` checks the PSS signature against the peer's public key,
   RSA-OAEP-decrypts the peer's secret, and XORs it into its own.
4. The session key is `secret_a XOR secret_b` (for `HalfHandShake`, only the
   sender's secret is used).

### Why this is safe — as far as it goes

The paddings are the modern, sound ones: OAEP for encryption and PSS for
signing, not textbook RSA or PKCS#1 v1.5. Signing the ciphertext gives
integrity and origin authentication **provided the public key is authentic**.
XOR-combining two contributions means neither party can unilaterally fix the
key, so a single misbehaving side cannot force a known key.

### Why it is not safe enough

1. **No forward secrecy — this is the serious one.** The session secret is
   *RSA key-transported* under a **long-term** key. An attacker who records
   handshakes today and later obtains a node's RSA private key decrypts the
   transported secret, and therefore every past session that key established.
   An ephemeral Diffie-Hellman exchange (e.g. X25519) makes past sessions
   unrecoverable even given the long-term key; RSA key transport structurally
   cannot. On its own this disqualifies the RSA path as a modern transport
   bootstrap.

2. **Authentication is entirely on the caller.** The signature only helps if you
   already hold the peer's *authentic* public key. First contact with an
   unauthenticated key is a MITM waiting to happen — the repo's own
   `examples/simple_mitm.py` and `examples/tofu_mitm.py` demonstrate exactly
   this. TOFU-pinning or out-of-band pre-distribution is left to the user, and
   nothing in the handshake binds identities into the transcript.

3. **RSA is heavy and brittle for the target.** 2048-bit RSA is large and slow
   on the ESP32 / MicroPython class of nodes this ecosystem targets, and any
   future slip in decrypt-error handling reintroduces padding-oracle risk that
   an ECDH exchange never has.

4. **`HalfHandShake` is weaker still** — only the sender contributes, so the
   sender fully determines the key; there is no mutual randomness.

## The cautionary tale: why this is a case study in *not* rolling your own crypto

None of the individual pieces here are broken. SHA-256, PBKDF2, RSA-OAEP,
RSA-PSS, hSub addressing — all are fine, well-understood primitives used within
their specs. **The vulnerability lives entirely in the composition**, and that
is almost always where do-it-yourself cryptography fails. A few lessons fall
straight out of the analysis above:

- **"It never sends the secret" is not a security argument.** The most seductive
  wrong intuition in applied crypto is: *if the secret material never crosses
  the wire, it must be protected.* But a *verifiable image* of the secret
  crossing the wire is enough to break it, because the attacker's job is to
  **test guesses**, not to read the secret. Confidentiality of the bytes and
  unguessability of the secret are different properties; this construction has
  the first and lacks the second.

- **The name was the tell.** `protocol.md` used to call the password path
  "PAKE-style." It has the *silhouette* of a PAKE — shared password in, shared
  key out, password never transmitted — without the one property that *defines*
  a PAKE: no offline dictionary attack. Building something that resembles a
  known primitive is not the same as building the primitive, and "-style" or
  "-inspired" in a crypto description is a reliable warning sign that a security
  property was approximated by shape rather than achieved.

- **It passes every test except the adversary.** Both sides derive the same
  key; the unit tests are green; the demo works. Correctness tests confirm that
  *honest* parties agree — they say nothing about what a *dishonest* party can
  do. Cryptographic security is a property against an adversary you have to
  explicitly model, and a hand-built protocol ships with neither a threat model
  nor a proof, so the gap only surfaces under an attacker you did not think of
  (here: offline guessing, and future key compromise).

- **Reusing good tech in the wrong context is still a bug.** hSub is *correct*
  remailer technology, and HiveMind's Usenet transport still uses it correctly —
  as an unlinkable label with a separate PGP layer doing confidentiality. The
  error was carrying that same construction onto a live link where nothing sits
  underneath it, so a mechanism designed to *address* mail was asked to
  *establish a session key*. Context is part of a primitive's contract.

- **"Use vetted crypto" means vetted *protocols*, not just vetted ciphers.** The
  fix is not "use a library's AES instead of writing AES." It is: **use a
  reviewed key-exchange protocol** — Noise, TLS 1.3, or a real asymmetric PAKE
  such as OPAQUE or SPAKE2 — instead of assembling your own handshake out of
  hashes and RSA calls. A protocol comes with a threat model and a proof; a
  hand-wired handshake comes with neither, and this page is what the difference
  looks like.

## What replaces it, and what to do meanwhile

HiveMind protocol **v3** moves the shared password into the **PSK slot of
`Noise_XXpsk2`** (X25519 + ChaCha20-Poly1305 + SHA-256), with `Noise_KKpsk0`
for the pre-provisioned-keys case. That single, reviewed pattern supplies the
four properties this bespoke handshake lacked, all at once:

- the wire messages stop being a checkable image of the password → **offline-
  dictionary resistance** (the real PAKE property);
- an ephemeral X25519 exchange → **forward secrecy**;
- mutual static-key authentication → **MITM resistance**;
- the negotiated parameters mixed into the handshake hash → **transcript /
  downgrade binding**.

Until you are on v3, if you must use this library:

- **Use a high-entropy random access key (≥128 bits), never a human
  passphrase.** This is the one change that actually neutralizes the password
  path's offline-dictionary weakness — there is nothing to enumerate.
- Treat the RSA path as providing **no forward secrecy**, and **validate public
  keys out of band** (TOFU-pin or pre-distribute); never accept an unauthenticated
  key on first contact in a hostile setting.
- Always wrap the derived `secret` in authenticated encryption (AES-GCM,
  ChaCha20-Poly1305) — the handshake is a bootstrap, not a transport.
- Prefer the v3 Noise handshake wherever it is available.
