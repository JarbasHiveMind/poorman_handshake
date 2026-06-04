"""Smoke tests: verify imports and basic instantiation."""
import pytest


def test_import_password_handshake():
    """Test that PasswordHandShake can be imported."""
    from poorman_handshake import PasswordHandShake
    assert PasswordHandShake is not None


def test_import_handshake():
    """Test that HandShake can be imported."""
    from poorman_handshake import HandShake
    assert HandShake is not None


def test_import_half_handshake():
    """Test that HalfHandShake can be imported."""
    from poorman_handshake import HalfHandShake
    assert HalfHandShake is not None


def test_instantiate_password_handshake():
    """Test basic PasswordHandShake instantiation."""
    from poorman_handshake import PasswordHandShake
    password = "test_password"
    shake = PasswordHandShake(password)
    assert shake.password == password
    assert shake.iv is None
    assert shake.salt is None


def test_instantiate_handshake():
    """Test basic HandShake instantiation."""
    from poorman_handshake import HandShake
    shake = HandShake()
    assert shake.private_key is not None
    assert shake.target_key is None
    assert shake.secret is None
    assert shake.pubkey is not None


def test_instantiate_half_handshake():
    """Test basic HalfHandShake instantiation."""
    from poorman_handshake import HalfHandShake
    shake = HalfHandShake()
    assert shake.private_key is not None
    assert shake.target_key is None
    assert shake.secret is None
