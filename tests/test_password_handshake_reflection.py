"""PasswordHandShake refuses its own envelope sent back to it.

The envelope is iv || SHA256(iv || password). A peer that does not know the
password can copy the envelope it received and send it back: match_hsub
recomputes the hash over the same IV and finds a match, so verify() returned
True. The salt, XOR of the two IVs, then became eight zero bytes. So the check
proved only that the peer can copy, and the salt lost all its entropy.
"""
import pytest

from poorman_handshake import PasswordHandShake

PASSWORD = "correct-horse-battery-staple-9"


def test_verify_refuses_this_objects_own_envelope():
    alice = PasswordHandShake(PASSWORD)
    envelope = alice.generate_handshake()
    assert not alice.verify(envelope)
    assert not alice.receive_and_verify(envelope)
    assert alice.salt is None


def test_an_envelope_with_this_objects_iv_is_refused_at_any_length():
    # match_hsub accepts 48 to 80 hex digits: a longer copy over the same IV
    # must be refused too
    from poorman_handshake.symmetric.utils import create_hsub
    alice = PasswordHandShake(PASSWORD)
    alice.generate_handshake()
    longer = create_hsub(PASSWORD, alice.iv, 80)
    assert not alice.verify(longer)


def test_receive_handshake_does_not_set_a_zero_salt():
    alice = PasswordHandShake(PASSWORD)
    envelope = alice.generate_handshake()
    with pytest.raises(ValueError):
        alice.receive_handshake(envelope)
    assert alice.salt is None


def test_a_genuine_peer_still_agrees():
    alice = PasswordHandShake(PASSWORD)
    bob = PasswordHandShake(PASSWORD)
    a, b = alice.generate_handshake(), bob.generate_handshake()
    assert alice.receive_and_verify(b)
    assert bob.receive_and_verify(a)
    assert alice.salt != bytes(8)
    assert alice.secret == bob.secret


def test_a_verifier_that_has_not_sent_an_envelope_still_verifies():
    # verify() before generate_handshake() has no IV of its own to compare
    sender = PasswordHandShake(PASSWORD)
    verifier = PasswordHandShake(PASSWORD)
    assert verifier.verify(sender.generate_handshake())
