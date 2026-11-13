"""Tests for symmetric encryption utilities (password-based)."""
import pytest
from poorman_handshake.symmetric.utils import (
    generate_iv,
    create_hsub,
    match_hsub,
    iv_from_hsub,
)


def test_generate_iv():
    """Test IV generation."""
    iv1 = generate_iv()
    iv2 = generate_iv()

    assert isinstance(iv1, bytes)
    assert len(iv1) == 8  # Default is 64 bits (8 bytes)
    assert iv1 != iv2  # Should be different each time


def test_generate_iv_custom_length():
    """Test IV generation with custom length."""
    iv = generate_iv(16)
    assert len(iv) == 16


def test_create_hsub():
    """Test creating an hsub (hashed subject)."""
    password = "test_password"
    iv = generate_iv()

    hsub = create_hsub(password, iv)

    assert isinstance(hsub, str)
    assert len(hsub) > 0
    # Should be hex-encoded
    try:
        bytes.fromhex(hsub)
    except ValueError:
        pytest.fail("hsub is not valid hex")


def test_create_hsub_default_iv():
    """Test creating hsub with auto-generated IV."""
    password = "test"
    hsub1 = create_hsub(password)
    hsub2 = create_hsub(password)

    assert isinstance(hsub1, str)
    assert hsub1 != hsub2  # Different IVs should give different hashes


def test_iv_from_hsub():
    """Test extracting IV from hsub."""
    password = "test_password"
    iv_original = generate_iv()
    hsub = create_hsub(password, iv_original)

    iv_extracted = iv_from_hsub(hsub)

    assert isinstance(iv_extracted, bytes)
    assert iv_extracted == iv_original


def test_match_hsub_correct():
    """Test matching hsub with correct password."""
    password = "secret_password"
    hsub = create_hsub(password)

    # Should match
    assert match_hsub(hsub, password)


def test_match_hsub_incorrect():
    """Test matching hsub with incorrect password."""
    password = "correct_password"
    hsub = create_hsub(password)

    # Wrong password should not match
    assert not match_hsub(hsub, "wrong_password")


def test_hsub_length_bounds():
    """Test hsub length validation."""
    password = "test"
    iv = generate_iv()
    hsub = create_hsub(password, iv, hsublen=48)

    # Valid length (48 hex chars = 192 bits)
    assert match_hsub(hsub, password)

    # Too short hsub should return False
    short_hsub = hsub[:10]
    assert not match_hsub(short_hsub, password)

    # Create a longer hsub
    long_hsub = create_hsub(password, iv, hsublen=80)
    assert match_hsub(long_hsub, password)


def test_iv_from_hsub_invalid():
    """Test IV extraction from invalid hsub."""
    # Too short
    short_hsub = "abc123"
    iv = iv_from_hsub(short_hsub)
    assert iv is False

    # Not hex-encoded
    bad_hsub = "zzzzzzzzzzzzzzzz"
    iv = iv_from_hsub(bad_hsub)
    assert iv is False


def test_hsub_deterministic():
    """Test that same password and IV produce same hsub."""
    password = "test"
    iv = generate_iv()

    hsub1 = create_hsub(password, iv)
    hsub2 = create_hsub(password, iv)

    assert hsub1 == hsub2


def test_hsub_custom_lengths():
    """Test hsub with different custom lengths."""
    password = "test"
    iv = generate_iv()

    hsub_48 = create_hsub(password, iv, hsublen=48)
    hsub_64 = create_hsub(password, iv, hsublen=64)

    assert len(hsub_48) == 48
    assert len(hsub_64) == 64
    # Both should match
    assert match_hsub(hsub_48, password)
    assert match_hsub(hsub_64, password)
