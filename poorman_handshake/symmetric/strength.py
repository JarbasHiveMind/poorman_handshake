"""Password guess-resistance checking for the password handshake.

The password handshake transmits an offline-crackable *verifier* of the
password (see ``docs/security.md``), so a low-entropy secret falls to a
dictionary attack regardless of transport. This module estimates a password's
guess resistance with `zxcvbn <https://github.com/dropbox/zxcvbn>`_ so that
:class:`~poorman_handshake.symmetric.PasswordHandShake` can refuse guessable
secrets.
"""

from math import log2
from typing import Union

from zxcvbn import zxcvbn

# zxcvbn reports guesses as a base-10 magnitude; convert to bits of resistance.
_BITS_PER_LOG10 = log2(10)

#: Default minimum guess resistance (in bits) required of a password. Chosen so
#: obviously guessable secrets ("Password123!", "correct_password", the xkcd
#: "Tr0ub4dour&3") are refused while real passphrases pass.
DEFAULT_MIN_BITS = 40.0

#: zxcvbn hard-rejects any input longer than this with a ValueError instead of
#: scoring it. A prefix this long of a high-entropy secret already scores far
#: above any realistic ``min_bits`` threshold, so scoring only the prefix does
#: not weaken the check: the full secret is still what gets used, only the
#: strength *estimate* is based on the prefix.
_ZXCVBN_MAX_LEN = 72


class WeakPasswordError(ValueError):
    """Raised when a password is too weak/guessable for the password handshake."""


def _zxcvbn(password: str) -> dict:
    """Run zxcvbn on a bounded prefix, so long secrets are scored, not rejected."""
    return zxcvbn(password[:_ZXCVBN_MAX_LEN])


def password_bits(password: Union[str, bytes]) -> float:
    """Return the estimated guess resistance of ``password`` in bits.

    This is ``log2`` of zxcvbn's estimated guess count — a realistic measure
    that accounts for dictionary words, keyboard patterns, and substitutions,
    unlike a naive character-set entropy estimate.
    """
    if isinstance(password, bytes):
        password = password.decode("utf-8", "replace")
    return _zxcvbn(password)["guesses_log10"] * _BITS_PER_LOG10


def check_password_strength(
    password: Union[str, bytes], min_bits: float = DEFAULT_MIN_BITS
) -> None:
    """Raise :class:`WeakPasswordError` if ``password`` is weaker than ``min_bits``.

    Passing ``min_bits <= 0`` disables the check (for tests, or deployments that
    knowingly use a high-entropy machine-generated secret).
    """
    if min_bits <= 0:
        return
    if not password:
        raise WeakPasswordError("password must be a non-empty string")
    pw = password.decode("utf-8", "replace") if isinstance(password, bytes) else password
    result = _zxcvbn(pw)
    bits = result["guesses_log10"] * _BITS_PER_LOG10
    if bits < min_bits:
        feedback = result.get("feedback") or {}
        hint = feedback.get("warning") or next(iter(feedback.get("suggestions") or []), "")
        detail = f" {hint}" if hint else ""
        raise WeakPasswordError(
            f"password is too guessable (~{bits:.0f} bits of resistance; "
            f"{min_bits:.0f} required).{detail} Use a longer passphrase, or "
            "NoiseHandShake with a high-entropy secret. Pass min_bits=0 to bypass "
            "this check (not recommended)."
        )
