import os
import unittest

import pytest
from noise.exceptions import NoiseInvalidMessage

from poorman_handshake.noise import KK_PSK0, XX_PSK2, NoiseHandShake, derive_psk

PASSWORD = "super secret site password"
PROLOGUE = b"hivemind-v3|ciphers:CHACHA20_POLY1305|encodings:JSON-B64"


def run_xx(initiator: NoiseHandShake, responder: NoiseHandShake):
    """Drive a 3-message XX handshake to completion."""
    responder.read_message(initiator.write_message())
    initiator.read_message(responder.write_message())
    responder.read_message(initiator.write_message())


class TestDerivePSK(unittest.TestCase):
    def test_derive_psk_deterministic_and_32_bytes(self):
        a = derive_psk(PASSWORD)
        b = derive_psk(PASSWORD)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)
        self.assertNotEqual(a, derive_psk("other password"))
        # str and bytes passwords are equivalent
        self.assertEqual(a, derive_psk(PASSWORD.encode("utf-8")))

    def test_node_id_salt(self):
        # HIVEMIND-CRYPTO-1 v4: salt = SHA-256(server node_id)
        import hashlib

        expected_salt = hashlib.sha256(b"tcp4://core:5678").digest()
        self.assertEqual(
            derive_psk(PASSWORD, node_id="tcp4://core:5678"),
            derive_psk(PASSWORD, salt=expected_salt),
        )
        self.assertNotEqual(
            derive_psk(PASSWORD, node_id="tcp4://core:5678"),
            derive_psk(PASSWORD, node_id="tcp4://other:5678"),
        )
        # str/bytes node_id equivalent
        self.assertEqual(
            derive_psk(PASSWORD, node_id="abc"), derive_psk(PASSWORD, node_id=b"abc")
        )

    def test_handshake_with_node_id_salt(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD, node_id="core-1")
        bob = NoiseHandShake(initiator=False, password=PASSWORD, node_id="core-1")
        run_xx(alice, bob)
        self.assertEqual(bob.decrypt(alice.encrypt(b"salted")), b"salted")
        # mismatched node_id -> different PSK -> handshake fails
        alice = NoiseHandShake(initiator=True, password=PASSWORD, node_id="core-1")
        bob = NoiseHandShake(initiator=False, password=PASSWORD, node_id="core-2")
        with pytest.raises(Exception):
            run_xx(alice, bob)

    def test_salt_changes_psk(self):
        self.assertNotEqual(
            derive_psk(PASSWORD), derive_psk(PASSWORD, salt=b"another-context!")
        )


class TestXXpsk2(unittest.TestCase):
    def test_full_roundtrip_shared_password(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD, prologue=PROLOGUE)
        bob = NoiseHandShake(initiator=False, password=PASSWORD, prologue=PROLOGUE)
        self.assertEqual(alice.pattern, XX_PSK2)
        self.assertFalse(alice.handshake_finished)

        run_xx(alice, bob)

        self.assertTrue(alice.handshake_finished)
        self.assertTrue(bob.handshake_finished)
        self.assertTrue(alice.complete)

        # transport messages flow both ways
        self.assertEqual(bob.decrypt(alice.encrypt(b"hello bob")), b"hello bob")
        self.assertEqual(alice.decrypt(bob.encrypt(b"hello alice")), b"hello alice")

    def test_handshake_hash_matches_and_channel_binding(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD)
        bob = NoiseHandShake(initiator=False, password=PASSWORD)
        self.assertIsNone(alice.handshake_hash)
        run_xx(alice, bob)
        self.assertEqual(alice.handshake_hash, bob.handshake_hash)
        self.assertEqual(len(alice.handshake_hash), 32)

    def test_remote_static_key_learned_for_pinning(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD)
        bob = NoiseHandShake(initiator=False, password=PASSWORD)
        run_xx(alice, bob)
        # each side learned the other's static pubkey (TOFU pinning material)
        self.assertEqual(alice.remote_pubkey, bob.pubkey_bytes)
        self.assertEqual(bob.remote_pubkey, alice.pubkey_bytes)
        self.assertEqual(len(alice.pubkey_bytes), 32)
        self.assertEqual(alice.pubkey, alice.pubkey_bytes.hex())

    def test_wrong_password_fails_handshake(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD)
        mallory = NoiseHandShake(initiator=False, password="wrong password")
        with pytest.raises(Exception):
            run_xx(alice, mallory)
        self.assertFalse(alice.handshake_finished and mallory.handshake_finished)

    def test_wrong_psk_fails_handshake(self):
        alice = NoiseHandShake(initiator=True, psk=os.urandom(32))
        bob = NoiseHandShake(initiator=False, psk=os.urandom(32))
        with pytest.raises(Exception):
            run_xx(alice, bob)

    def test_tampered_prologue_aborts_handshake(self):
        # downgrade protection: negotiation lists bound via prologue must match
        alice = NoiseHandShake(initiator=True, password=PASSWORD, prologue=PROLOGUE)
        bob = NoiseHandShake(
            initiator=False,
            password=PASSWORD,
            prologue=b"hivemind-v2|ciphers:WEAK",
        )
        with pytest.raises(Exception):
            run_xx(alice, bob)

    def test_split_transport_cipherstates(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD)
        bob = NoiseHandShake(initiator=False, password=PASSWORD)
        with pytest.raises(RuntimeError):
            alice.split()
        run_xx(alice, bob)
        a_send, a_recv = alice.split()
        b_send, b_recv = bob.split()
        ct = a_send.encrypt_with_ad(None, b"via cipherstate")
        self.assertEqual(b_recv.decrypt_with_ad(None, ct), b"via cipherstate")
        ct = b_send.encrypt_with_ad(None, b"reply")
        self.assertEqual(a_recv.decrypt_with_ad(None, ct), b"reply")

    def test_replay_rejected(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD)
        bob = NoiseHandShake(initiator=False, password=PASSWORD)
        run_xx(alice, bob)
        ct = alice.encrypt(b"only once")
        self.assertEqual(bob.decrypt(ct), b"only once")
        # nonce counter advanced: replaying the same ciphertext must fail
        with pytest.raises(NoiseInvalidMessage):
            bob.decrypt(ct)

    def test_tampered_ciphertext_rejected(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD)
        bob = NoiseHandShake(initiator=False, password=PASSWORD)
        run_xx(alice, bob)
        ct = bytearray(alice.encrypt(b"payload"))
        ct[-1] ^= 0x01
        with pytest.raises(NoiseInvalidMessage):
            bob.decrypt(bytes(ct))

    def test_forward_secrecy_ephemeral_sessions(self):
        # Structural check: with identical static keys, PSK and prologue, two
        # handshakes still derive different session secrets, because the keys
        # come from the ephemeral X25519 DH. Static keys (or the password)
        # alone therefore cannot recover a past session key.
        psk = derive_psk(PASSWORD)
        sessions = []
        for _ in range(2):
            alice = NoiseHandShake(initiator=True, psk=psk)
            bob = NoiseHandShake(initiator=False, psk=psk)
            run_xx(alice, bob)
            sessions.append((alice.handshake_hash, alice.encrypt(b"same plaintext")))
        (h1, ct1), (h2, ct2) = sessions
        self.assertNotEqual(h1, h2)  # unique transcript per session
        self.assertNotEqual(ct1, ct2)  # unique transport keys per session

    def test_handshake_payloads(self):
        alice = NoiseHandShake(initiator=True, password=PASSWORD)
        bob = NoiseHandShake(initiator=False, password=PASSWORD)
        bob.read_message(alice.write_message())
        # from message 2 onwards payloads are encrypted under handshake keys
        self.assertEqual(alice.read_message(bob.write_message(b"hello")), b"hello")
        self.assertEqual(bob.read_message(alice.write_message(b"world")), b"world")


class TestKKpsk0(unittest.TestCase):
    def test_roundtrip_with_preprovisioned_static_keys(self):
        psk = derive_psk(PASSWORD)
        # exchange static pubkeys out of band first
        alice_tmp = NoiseHandShake(initiator=True, psk=psk)
        bob_tmp = NoiseHandShake(initiator=False, psk=psk)
        alice_pub, bob_pub = alice_tmp.pubkey_bytes, bob_tmp.pubkey_bytes
        # not usable: KK needs the keypair, so persist and reload via path
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            a_path, b_path = f"{tmp}/alice.key", f"{tmp}/bob.key"
            alice_tmp.export_private_key(a_path)
            bob_tmp.export_private_key(b_path)

            alice = NoiseHandShake(
                initiator=True, path=a_path, psk=psk, remote_pubkey=bob_pub
            )
            bob = NoiseHandShake(
                initiator=False, path=b_path, psk=psk, remote_pubkey=alice_pub
            )
            self.assertEqual(alice.pattern, KK_PSK0)
            self.assertEqual(alice.pubkey_bytes, alice_pub)

            # KK is a 2-message pattern
            bob.read_message(alice.write_message())
            alice.read_message(bob.write_message())

            self.assertTrue(alice.handshake_finished)
            self.assertTrue(bob.handshake_finished)
            self.assertEqual(bob.decrypt(alice.encrypt(b"kk!")), b"kk!")
            self.assertEqual(alice.decrypt(bob.encrypt(b"ack")), b"ack")
            self.assertEqual(alice.remote_pubkey, bob_pub)

    def test_kk_wrong_remote_static_fails(self):
        psk = derive_psk(PASSWORD)
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            a_path, b_path = f"{tmp}/alice.key", f"{tmp}/bob.key"
            alice = NoiseHandShake(
                initiator=True,
                path=a_path,
                psk=psk,
                remote_pubkey=os.urandom(32),  # not bob's key
            )
            bob_pubgrab = NoiseHandShake(initiator=False, path=b_path, psk=psk)
            alice_pub = alice.pubkey_bytes
            bob = NoiseHandShake(
                initiator=False, path=b_path, psk=psk, remote_pubkey=alice_pub
            )
            del bob_pubgrab
            with pytest.raises(Exception):
                bob.read_message(alice.write_message())
                alice.read_message(bob.write_message())


class TestKeyPersistence(unittest.TestCase):
    def test_generate_persist_reload(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = f"{tmp}/node.key"
            hs1 = NoiseHandShake(initiator=True, password=PASSWORD, path=path)
            self.assertTrue(os.path.isfile(path))
            hs2 = NoiseHandShake(initiator=True, password=PASSWORD, path=path)
            self.assertEqual(hs1.pubkey, hs2.pubkey)

    def test_requires_password_or_psk(self):
        with pytest.raises(ValueError):
            NoiseHandShake(initiator=True)

    def test_psk_must_be_32_bytes(self):
        with pytest.raises(ValueError):
            NoiseHandShake(initiator=True, psk=b"short")


if __name__ == "__main__":
    unittest.main()
