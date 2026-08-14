"""Tests for asymmetric encryption utilities (RSA operations)."""
import tempfile
import os
import pytest
from poorman_handshake.asymmetric.utils import (
    encrypt_RSA,
    decrypt_RSA,
    sign_RSA,
    verify_RSA,
    create_RSA_key,
    load_RSA_key,
    export_RSA_key,
    hybrid_encrypt_RSA,
    hybrid_decrypt_RSA,
)


def test_create_rsa_key():
    """Test RSA key generation."""
    pub, sec = create_RSA_key()

    assert isinstance(pub, str)
    assert isinstance(sec, str)
    assert "BEGIN PUBLIC KEY" in pub
    assert "BEGIN RSA PRIVATE KEY" in sec


def test_encrypt_decrypt_rsa():
    """Test RSA encryption and decryption."""
    pub, sec = create_RSA_key()
    plaintext = b"secret message"

    ciphertext = encrypt_RSA(pub, plaintext)
    assert isinstance(ciphertext, bytes)
    assert ciphertext != plaintext

    decrypted = decrypt_RSA(sec, ciphertext)
    assert decrypted == plaintext


def test_encrypt_decrypt_string():
    """Test RSA encryption with string input."""
    pub, sec = create_RSA_key()
    plaintext = "secret message"

    ciphertext = encrypt_RSA(pub, plaintext)
    decrypted = decrypt_RSA(sec, ciphertext).decode("utf-8")

    assert decrypted == plaintext


def test_sign_verify_rsa():
    """Test RSA signing and verification."""
    pub, sec = create_RSA_key()
    message = b"important message"

    signature = sign_RSA(sec, message)
    assert isinstance(signature, bytes)
    assert len(signature) > 0

    # Should verify correctly
    assert verify_RSA(pub, message, signature)


def test_verify_wrong_signature():
    """Test that wrong signatures fail verification."""
    pub, sec = create_RSA_key()
    message = b"important"

    signature = sign_RSA(sec, message)
    # Tamper with signature
    bad_signature = bytes([b ^ 0xFF for b in signature[:10]]) + signature[10:]

    assert not verify_RSA(pub, message, bad_signature)


def test_export_load_rsa_key():
    """Test exporting and loading RSA keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test.pem")
        pub, sec = create_RSA_key()

        # Export private key
        export_RSA_key(sec, key_path)
        assert os.path.exists(key_path)

        # Load and verify
        loaded_key = load_RSA_key(key_path)
        assert loaded_key.has_private()


def test_hybrid_encrypt_decrypt():
    """Test hybrid RSA+AES-GCM encryption for large payloads."""
    pub, sec = create_RSA_key()
    # Plaintext larger than RSA can handle directly
    plaintext = b"This is a much longer message that exceeds RSA plaintext limit" * 10

    ciphertext = hybrid_encrypt_RSA(pub, plaintext)
    assert isinstance(ciphertext, bytes)
    assert len(ciphertext) > 0

    decrypted = hybrid_decrypt_RSA(sec, ciphertext)
    assert decrypted == plaintext


def test_hybrid_encrypt_string():
    """Test hybrid encryption with string input."""
    pub, sec = create_RSA_key()
    plaintext = "test message for hybrid"

    ciphertext = hybrid_encrypt_RSA(pub, plaintext)
    decrypted = hybrid_decrypt_RSA(sec, ciphertext).decode("utf-8")

    assert decrypted == plaintext


def test_hybrid_tamper_detection():
    """Test that hybrid encryption detects tampering."""
    pub, sec = create_RSA_key()
    plaintext = b"important data"

    ciphertext = hybrid_encrypt_RSA(pub, plaintext)
    # Tamper with the ciphertext
    tampered = bytes([b ^ 0xFF for b in ciphertext[:20]]) + ciphertext[20:]

    # Should raise an exception due to failed authentication tag
    with pytest.raises(Exception):  # ValueError or struct.error
        hybrid_decrypt_RSA(sec, tampered)


def test_sign_verify_string():
    """Test signing and verifying with string message."""
    pub, sec = create_RSA_key()
    message = "test message"

    signature = sign_RSA(sec, message)
    assert verify_RSA(pub, message, signature)



# --- load_RSA_key memoization -------------------------------------------
# RSA.import_key runs a full consistency check on private keys (~100ms on
# constrained hosts) and servers construct a HandShake per client connection
# from one identity file -- a connection storm re-paid that cost per client.

def test_rsa_key_cache_repeat_loads_share_object(tmp_path):
    from poorman_handshake.asymmetric.utils import load_RSA_key, create_RSA_key
    priv, _ = create_RSA_key()
    path = tmp_path / "id.pem"
    path.write_text(priv)
    first = load_RSA_key(str(path))
    assert load_RSA_key(str(path)) is first, \
        "unchanged file must serve the cached key"


def test_rsa_key_cache_rewritten_file_reloads(tmp_path):
    from poorman_handshake.asymmetric.utils import load_RSA_key, create_RSA_key
    priv1, _ = create_RSA_key()
    priv2, _ = create_RSA_key()
    path = tmp_path / "id.pem"
    path.write_text(priv1)
    first = load_RSA_key(str(path))
    path.write_text(priv2)
    # force a distinct stat signature even on coarse-mtime filesystems
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    second = load_RSA_key(str(path))
    assert second is not first, "rewritten key file must reload"
    assert first.n != second.n


def test_rsa_key_cache_missing_file_still_raises():
    from poorman_handshake.asymmetric.utils import load_RSA_key
    with pytest.raises(OSError):
        load_RSA_key("/nonexistent/key.pem")
