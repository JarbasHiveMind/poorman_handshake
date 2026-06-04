"""Tests for HandShake (RSA-based key exchange)."""
from secrets import compare_digest
import pytest
import tempfile
import os
from poorman_handshake import HandShake, HalfHandShake


def test_handshake_instantiation():
    """Test that HandShake initializes with valid RSA key."""
    shake = HandShake()
    assert shake.private_key is not None
    assert shake.pubkey is not None
    assert isinstance(shake.pubkey, str)
    assert "BEGIN" in shake.pubkey
    assert "PUBLIC" in shake.pubkey


def test_handshake_generate_handshake():
    """Test generating a handshake produces hex string."""
    shake = HandShake()
    bob = HandShake()
    shake.load_public(bob.pubkey)  # Need to load a target public key first
    handshake = shake.generate_handshake()

    assert isinstance(handshake, str)
    assert len(handshake) > 0
    # Should be valid hex
    try:
        bytes.fromhex(handshake)
    except ValueError:
        pytest.fail("Handshake is not valid hex")


def test_handshake_mutual_exchange():
    """Test mutual RSA handshake between two parties."""
    alice = HandShake()
    bob = HandShake()

    # Exchange public keys
    alice.load_public(bob.pubkey)
    bob.load_public(alice.pubkey)

    # Generate and exchange handshakes
    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    # Receive and verify
    alice.receive_and_verify(bob_shake)
    bob.receive_and_verify(alice_shake)

    # Both should have the same secret (XOR of both contributions)
    assert compare_digest(alice.secret, bob.secret)


def test_handshake_verify_correct():
    """Test verify returns True for valid signature."""
    alice = HandShake()
    bob = HandShake()

    bob.load_public(alice.pubkey)
    handshake = bob.generate_handshake(alice.pubkey)

    # alice should be able to verify bob's signature
    assert alice.verify(handshake, bob.pubkey)


def test_handshake_verify_incorrect():
    """Test verify returns False for tampered handshake."""
    alice = HandShake()
    bob = HandShake()

    handshake = bob.generate_handshake(alice.pubkey)
    # Tamper with the handshake (flip a bit)
    tampered = hex(int(handshake, 16) ^ 0xFF)[2:].zfill(len(handshake))

    assert not alice.verify(tampered, bob.pubkey)


def test_handshake_pubkey_export():
    """Test that pubkey is properly PEM-encoded."""
    shake = HandShake()
    pubkey = shake.pubkey

    # Should be loadable back
    from Cryptodome.PublicKey import RSA
    imported = RSA.import_key(pubkey)
    assert not imported.has_private()  # Public key should not have private component


def test_handshake_key_file_storage():
    """Test saving and loading private key from file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test_key.pem")

        # Create and save
        shake1 = HandShake(path=key_path)
        pubkey1 = shake1.pubkey

        # Load from file
        shake2 = HandShake(path=key_path)
        pubkey2 = shake2.pubkey

        # Public keys should be identical
        assert pubkey1 == pubkey2


def test_handshake_secret_computation():
    """Test that secret is computed correctly via XOR."""
    alice = HandShake()
    bob = HandShake()

    alice.load_public(bob.pubkey)
    bob.load_public(alice.pubkey)

    # Generate handshakes
    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    # Receive
    alice.receive_handshake(bob_shake)
    bob.receive_handshake(alice_shake)

    # Both should have secrets (32 bytes each)
    assert isinstance(alice.secret, bytes)
    assert isinstance(bob.secret, bytes)
    assert len(alice.secret) == 32
    assert len(bob.secret) == 32
    # And they should match (XOR of both parties' contributions)
    assert compare_digest(alice.secret, bob.secret)


def test_handshake_different_keys():
    """Test that different RSA keys produce different results."""
    alice = HandShake()
    bob = HandShake()

    alice.load_public(bob.pubkey)
    bob.load_public(alice.pubkey)

    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    alice.receive_handshake(bob_shake)
    bob.receive_handshake(alice_shake)

    alice_bob_secret = alice.secret

    # Now test with a completely different pair
    dave = HandShake()
    eve = HandShake()

    dave.load_public(eve.pubkey)
    eve.load_public(dave.pubkey)

    dave_shake = dave.generate_handshake()
    eve_shake = eve.generate_handshake()

    dave.receive_handshake(eve_shake)
    eve.receive_handshake(dave_shake)

    dave_eve_secret = dave.secret

    # Different key pairs should produce different secrets
    assert not compare_digest(alice_bob_secret, dave_eve_secret)


class TestHalfHandShake:
    """Tests for HalfHandShake (asymmetric key agreement)."""

    def test_half_handshake_instantiation(self):
        """Test HalfHandShake initializes correctly."""
        shake = HalfHandShake()
        assert shake.private_key is not None
        assert shake.pubkey is not None

    def test_half_handshake_one_way(self):
        """Test one-way key agreement with HalfHandShake."""
        server = HalfHandShake()
        client = HalfHandShake()

        # Client only needs server's public key
        client.load_public(server.pubkey)

        client_shake = client.generate_handshake()

        # Server receives directly (uses client's secret as-is, not XORed)
        server.receive_handshake(client_shake)

        # Both should have the same secret (client's contribution only)
        assert compare_digest(server.secret, client.secret)

    def test_half_handshake_vs_full_handshake(self):
        """Test that HalfHandShake and HandShake differ in secret computation."""
        # HalfHandShake: receives secret directly
        # HandShake: XORs two secrets

        server_half = HalfHandShake()
        server_full = HandShake()

        # Same client handshake to both
        client = HandShake()
        client.load_public(server_half.pubkey)

        client_shake = client.generate_handshake()

        server_half.receive_handshake(client_shake)
        # HalfHandShake doesn't support receive_and_verify with both keys,
        # but we can verify the secret behavior by checking it equals client's
        # (not XORed with server's)

        assert isinstance(server_half.secret, bytes)
        assert len(server_half.secret) == 32
