"""Tests for PasswordHandShake (password-based key exchange)."""
from secrets import compare_digest
import pytest
from poorman_handshake import PasswordHandShake


def test_password_handshake_generates_handshake():
    """Test that generate_handshake produces a hex string."""
    password = "shared_secret"
    shake = PasswordHandShake(password, min_bits=0)
    handshake = shake.generate_handshake()

    assert isinstance(handshake, str)
    assert len(handshake) > 0
    # hsub should be hex-encoded
    try:
        bytes.fromhex(handshake)
    except ValueError:
        pytest.fail("Handshake is not valid hex")


def test_password_handshake_mutual_agreement():
    """Test that two parties with the same password derive the same key."""
    password = "Super Secret Pass Phrase"
    alice = PasswordHandShake(password, min_bits=0)
    bob = PasswordHandShake(password, min_bits=0)

    # Generate handshakes
    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    # Exchange and verify
    assert alice.receive_and_verify(bob_shake)
    assert bob.receive_and_verify(alice_shake)

    # Both should have the same secret
    assert compare_digest(alice.secret, bob.secret)


def test_password_handshake_different_passwords():
    """Test that different passwords result in different keys."""
    alice = PasswordHandShake("password_a", min_bits=0)
    bob = PasswordHandShake("password_b", min_bits=0)

    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    alice.receive_handshake(bob_shake)
    bob.receive_handshake(alice_shake)

    # Different passwords should produce different secrets
    assert not compare_digest(alice.secret, bob.secret)


def test_password_handshake_verify_correct():
    """Test verify returns True for matching password."""
    password = "test_password"
    shake = PasswordHandShake(password, min_bits=0)
    handshake = shake.generate_handshake()

    # Create another instance with same password to verify
    verifier = PasswordHandShake(password, min_bits=0)
    assert verifier.verify(handshake)


def test_password_handshake_verify_incorrect():
    """Test verify returns False for non-matching password."""
    password = "correct_password"
    shake = PasswordHandShake(password, min_bits=0)
    handshake = shake.generate_handshake()

    # Try to verify with different password
    verifier = PasswordHandShake("wrong_password", min_bits=0)
    assert not verifier.verify(handshake)


def test_password_handshake_receive_and_verify():
    """Test receive_and_verify succeeds on correct password."""
    password = "shared"
    alice = PasswordHandShake(password, min_bits=0)
    bob = PasswordHandShake(password, min_bits=0)

    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    # receive_and_verify should return True and set salt
    assert bob.receive_and_verify(alice_shake)
    assert bob.salt is not None


def test_password_handshake_deterministic_secret():
    """Test that the same handshakes always produce the same secret."""
    password = "test"
    alice = PasswordHandShake(password, min_bits=0)
    bob = PasswordHandShake(password, min_bits=0)

    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    # Both should derive the same secret
    alice.receive_handshake(bob_shake)
    bob.receive_handshake(alice_shake)

    secret1 = alice.secret
    secret2 = bob.secret
    assert compare_digest(secret1, secret2)
    assert isinstance(secret1, bytes)
    assert len(secret1) == 32  # SHA256 produces 32 bytes


def test_password_handshake_exchange_without_verify():
    """Test plain receive_handshake without verify still derives key."""
    password = "no_verify"
    alice = PasswordHandShake(password, min_bits=0)
    bob = PasswordHandShake(password, min_bits=0)

    alice_shake = alice.generate_handshake()
    bob_shake = bob.generate_handshake()

    # Receive without verify
    alice.receive_handshake(bob_shake)
    bob.receive_handshake(alice_shake)

    # Should still have matching secrets
    assert compare_digest(alice.secret, bob.secret)
