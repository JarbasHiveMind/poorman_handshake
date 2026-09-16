"""Noise Protocol Framework handshake primitive for HiveMind protocol v3.

Wraps the vetted ``noiseprotocol`` library (which delegates all cryptography to
``pyca/cryptography``) to provide an authenticated key exchange with:

- **Mutual static-key authentication** (X25519 static keys)
- **Forward secrecy** (ephemeral X25519 Diffie-Hellman per handshake)
- **A password channel** via the Noise PSK slot: the site password is stretched
  with **argon2id** into a 32-byte pre-shared key and mixed into the handshake,
  so a wrong password aborts the handshake cryptographically (fail-fast) and an
  observer gains no offline verifier
- **Transcript binding** via the Noise handshake hash and an optional
  ``prologue`` (protocol version + cipher/encoding negotiation lists), which
  makes any tampering with the negotiation abort the handshake

Supported patterns (cipher suite: X25519 + ChaCha20-Poly1305 + SHA-256):

- ``Noise_XXpsk2_25519_ChaChaPoly_SHA256`` — general case: static public keys
  are exchanged (and authenticated) during the handshake; use for
  TOFU-then-pin deployments. The learned remote static key is exposed via
  :attr:`NoiseHandShake.remote_pubkey` for pinning by the caller.
- ``Noise_KKpsk0_25519_ChaChaPoly_SHA256`` — pre-provisioned case: both static
  public keys are known in advance (pass ``remote_pubkey``).
"""

import hashlib
import os
from binascii import hexlify, unhexlify
from os.path import isfile
from typing import Optional, Tuple, Union

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from noise.connection import Keypair, NoiseConnection

XX_PSK2 = b"Noise_XXpsk2_25519_ChaChaPoly_SHA256"
KK_PSK0 = b"Noise_KKpsk0_25519_ChaChaPoly_SHA256"

# fallback domain-separation salt for the password -> PSK derivation, used
# when no server node_id is available; a fixed public constant is fine here
# (the salt only needs to be public and shared by both peers)
_PSK_SALT = b"poorman_handshake:noise:psk:v1"


def derive_psk(
    password: Union[str, bytes],
    node_id: Optional[Union[str, bytes]] = None,
    salt: Optional[bytes] = None,
) -> bytes:
    """Derive a 32-byte Noise PSK from a shared password using argon2id.

    Per HIVEMIND-CRYPTO-1 v4, the salt is ``SHA-256(server node_id)`` — pass
    the server's ``node_id``. Both peers must derive with the same inputs.

    Args:
        password: The shared site password.
        node_id: The server's node id; salted as ``SHA-256(node_id)``.
        salt: Explicit salt override; defaults to ``SHA-256(node_id)`` when
            ``node_id`` is given, else a fixed public constant.

    Returns:
        bytes: A 32-byte pre-shared key suitable for the Noise ``psk`` slot.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    if salt is None:
        if node_id is not None:
            if isinstance(node_id, str):
                node_id = node_id.encode("utf-8")
            salt = hashlib.sha256(node_id).digest()
        else:
            salt = _PSK_SALT
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,  # 64 MiB
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


class NoiseHandShake:
    """Noise-pattern authenticated key exchange (HiveMind protocol v3).

    Mirrors the ergonomics of :class:`poorman_handshake.asymmetric.HandShake`:
    construct with an optional key ``path`` (the static X25519 key is generated
    and persisted if absent) and step the handshake with
    :meth:`write_message` / :meth:`read_message`. After
    :attr:`handshake_finished`, use :meth:`encrypt` / :meth:`decrypt` (or the
    raw CipherStates from :meth:`split`) for transport encryption with
    per-message nonce counters (replay resistant).

    Attributes:
        initiator (bool): Whether this side initiates the handshake.
        pattern (bytes): Full Noise protocol name in use.
    """

    def __init__(
        self,
        initiator: bool,
        path: Optional[str] = None,
        password: Optional[Union[str, bytes]] = None,
        node_id: Optional[Union[str, bytes]] = None,
        psk: Optional[bytes] = None,
        remote_pubkey: Optional[Union[str, bytes]] = None,
        prologue: bytes = b"",
        pattern: Optional[bytes] = None,
    ):
        """
        Args:
            initiator: True for the initiating side, False for the responder.
            path: Optional path to load/persist the static X25519 private key
                (hex-encoded). A new key is generated if the file is absent.
            password: Shared site password; stretched into the PSK with
                argon2id (see :func:`derive_psk`). Ignored if ``psk`` is given.
            node_id: The server's node id, used as the PSK derivation salt
                (``SHA-256(node_id)``) per HIVEMIND-CRYPTO-1 v4.
            psk: Pre-derived 32-byte pre-shared key.
            remote_pubkey: Remote static public key (32 raw bytes or hex str).
                Required for the KK pattern; optional for XX.
            prologue: Arbitrary bytes bound into the handshake hash — callers
                should encode the negotiated protocol version and
                cipher/encoding lists here for downgrade protection. Both
                sides must supply identical bytes or the handshake aborts.
            pattern: Noise protocol name; defaults to :data:`KK_PSK0` when
                ``remote_pubkey`` is provided, else :data:`XX_PSK2`.
        """
        if psk is None:
            if password is None:
                raise ValueError("either 'password' or 'psk' is required")
            psk = derive_psk(password, node_id=node_id)
        if len(psk) != 32:
            raise ValueError("psk must be exactly 32 bytes")

        self.initiator = initiator
        self.pattern = pattern or (KK_PSK0 if remote_pubkey else XX_PSK2)
        self._private_key = None
        self._remote_static: Optional[bytes] = None

        if path and isfile(path):
            self.load_private(path)
        if not self._private_key:
            self._private_key = X25519PrivateKey.generate()
            if path:
                self.export_private_key(path)

        if isinstance(remote_pubkey, str):
            remote_pubkey = unhexlify(remote_pubkey)

        self.noise = NoiseConnection.from_name(self.pattern)
        self.noise.set_keypair_from_private_bytes(
            Keypair.STATIC, self._private_bytes()
        )
        if remote_pubkey:
            self.noise.set_keypair_from_public_bytes(
                Keypair.REMOTE_STATIC, remote_pubkey
            )
            self._remote_static = remote_pubkey
        self.noise.set_psks(psk)
        if prologue:
            self.noise.set_prologue(prologue)
        if initiator:
            self.noise.set_as_initiator()
        else:
            self.noise.set_as_responder()
        self.noise.start_handshake()
        # keep our own reference: noiseprotocol drops handshake_state from the
        # NoiseProtocol object once the handshake completes, but we still need
        # the learned remote static key (XX) for TOFU pinning
        self._hs_state = self.noise.noise_protocol.handshake_state

    # ------------------------------------------------------------------ keys
    def _private_bytes(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def load_private(self, path: str):
        """Loads the static X25519 private key from a hex-encoded file."""
        with open(path, "rb") as f:
            self._private_key = X25519PrivateKey.from_private_bytes(
                unhexlify(f.read().strip())
            )

    def export_private_key(self, path: str):
        """Persists the static X25519 private key to a hex-encoded file."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(path, flags, 0o600), "wb") as f:
            f.write(hexlify(self._private_bytes()))

    @property
    def pubkey(self) -> str:
        """Static X25519 public key, hex-encoded (share/pin this)."""
        return hexlify(self.pubkey_bytes).decode("utf-8")

    @property
    def pubkey_bytes(self) -> bytes:
        """Static X25519 public key, 32 raw bytes."""
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def remote_pubkey(self) -> Optional[bytes]:
        """Remote static public key (32 raw bytes).

        For XX this is learned during the handshake — available once the peer's
        static key message has been read; callers should TOFU-pin it. For KK it
        is the pre-provisioned key.
        """
        return self._remote_static

    # ------------------------------------------------------------- handshake
    @property
    def handshake_finished(self) -> bool:
        """True once the handshake completed and transport keys exist."""
        # noiseprotocol deletes handshake_state from the NoiseProtocol object
        # exactly when the handshake completes and the transport keys are split
        return not hasattr(self.noise.noise_protocol, "handshake_state")

    # ergonomic alias
    complete = handshake_finished

    @property
    def handshake_hash(self) -> Optional[bytes]:
        """The Noise handshake hash ``h`` (32 bytes) after completion.

        Authenticates the full transcript (prologue + all handshake messages);
        use for channel binding, e.g. keying an access-key challenge-response.
        """
        if not self.handshake_finished:
            return None
        return self.noise.get_handshake_hash()

    def _snapshot_remote_static(self):
        # capture the remote static key learned during the handshake (XX)
        rs = getattr(self._hs_state, "rs", None)
        if getattr(rs, "public", None) is not None:
            self._remote_static = rs.public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )

    def write_message(self, payload: bytes = b"") -> bytes:
        """Produces the next handshake message to send to the peer.

        Args:
            payload: Optional application payload to piggyback (encrypted as
                soon as the pattern allows).

        Returns:
            bytes: The handshake message to transmit.
        """
        msg = self.noise.write_message(payload)
        self._snapshot_remote_static()
        return msg

    def read_message(self, data: bytes) -> bytes:
        """Consumes a handshake message received from the peer.

        Raises on any authentication failure — wrong PSK/password, mismatched
        prologue, wrong static key, or tampered message.

        Args:
            data: The handshake message received.

        Returns:
            bytes: The peer's application payload (may be empty).
        """
        payload = self.noise.read_message(data)
        self._snapshot_remote_static()
        return payload

    # ------------------------------------------------------------- transport
    def split(self) -> Tuple[object, object]:
        """Returns the two transport CipherState objects after completion.

        Returns:
            tuple: ``(send_cipher, recv_cipher)`` — CipherStates with
            ``encrypt_with_ad``/``decrypt_with_ad`` and internal nonce
            counters.
        """
        if not self.handshake_finished:
            raise RuntimeError("handshake not finished")
        proto = self.noise.noise_protocol
        return proto.cipher_state_encrypt, proto.cipher_state_decrypt

    def encrypt(self, data: bytes) -> bytes:
        """Encrypts a transport message under the send CipherState.

        The internal nonce counter increments per message, giving replay
        resistance: a ciphertext only decrypts at its position in the stream.
        """
        return self.noise.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypts a transport message under the receive CipherState.

        Raises ``noise.exceptions.NoiseInvalidMessage`` on tampering or replay.
        """
        return self.noise.decrypt(data)
