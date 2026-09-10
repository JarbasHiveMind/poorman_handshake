import secrets

import pytest

from poorman_handshake import (
    PasswordHandShake,
    WeakPasswordError,
    check_password_strength,
    password_bits,
)
from poorman_handshake.symmetric.strength import DEFAULT_MIN_BITS


WEAK = [
    "test",
    "password",
    "test_password",
    "Password123!",   # high char-set diversity, still trivially guessable
    "hunter2",
    "Tr0ub4dour&3",   # the xkcd "hard for humans, easy for machines" example
]

STRONG = [
    "correct horse battery staple",
    "MyDogChews5Bones every Tuesday",
]


@pytest.mark.parametrize("pw", WEAK)
def test_weak_passwords_are_refused(pw):
    with pytest.raises(WeakPasswordError):
        PasswordHandShake(pw)


@pytest.mark.parametrize("pw", STRONG)
def test_strong_passphrases_are_accepted(pw):
    # Does not raise, and the handshake still works.
    a = PasswordHandShake(pw)
    b = PasswordHandShake(pw)
    assert b.verify(a.generate_handshake())


def test_min_bits_zero_disables_the_check():
    # explicit opt-out for tests / known-high-entropy machine secrets
    PasswordHandShake("test", min_bits=0)


def test_min_bits_can_be_raised():
    # a passphrase that clears the default bar can still be refused at a higher one
    with pytest.raises(WeakPasswordError):
        PasswordHandShake("correct horse battery staple", min_bits=128)


def test_empty_password_refused():
    with pytest.raises(WeakPasswordError):
        PasswordHandShake("")


def test_bytes_password_supported():
    with pytest.raises(WeakPasswordError):
        check_password_strength(b"password")


def test_password_bits_orders_by_strength():
    assert password_bits("password") < password_bits("correct horse battery staple")


def test_long_machine_secret_is_scored_not_raised():
    # A 128-char hex secret (a realistic 64-byte machine secret) exceeds
    # zxcvbn's internal 72-char hard cap; it must be scored via a bounded
    # prefix, not raise ValueError out of the strength check.
    secret = secrets.token_hex(64)
    assert len(secret) == 128
    bits = password_bits(secret)
    assert bits > DEFAULT_MIN_BITS
    # Does not raise, and the handshake still works with the full secret.
    check_password_strength(secret)
    a = PasswordHandShake(secret)
    b = PasswordHandShake(secret)
    assert b.verify(a.generate_handshake())


def test_long_weak_password_is_still_refused():
    # Truncating for scoring must not become a bypass: a long but low-entropy
    # password (padded well past the 72-char cap) is still refused.
    weak_long = "password" * 10
    assert len(weak_long) > 72
    with pytest.raises(WeakPasswordError):
        check_password_strength(weak_long)
