import pytest

from poorman_handshake import (
    PasswordHandShake,
    WeakPasswordError,
    check_password_strength,
    password_bits,
)


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

LONG_MACHINE_SECRET = (
    "N7hPp0kCq9Zr2sVx6bLd4mTa8WfY3jQe5uIg1oSnKcR94HzXvBt6PaDy"
    "M2lEwUqF8gJs0nRb5Tz"
)


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


def test_long_machine_generated_password_supported():
    PasswordHandShake(LONG_MACHINE_SECRET)
    assert password_bits(LONG_MACHINE_SECRET) >= 40


def test_long_guessable_password_still_refused():
    with pytest.raises(WeakPasswordError):
        PasswordHandShake("password" * 12)


def test_password_bits_orders_by_strength():
    assert password_bits("password") < password_bits("correct horse battery staple")
