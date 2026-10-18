import pytest

from bitchat.identity import Identity
from bitchat.noise_session import NoiseSession, NoiseSessionError, PeerIdentityMismatch


def _handshake(alice_identity, bob_identity):
    alice = NoiseSession(alice_identity, bob_identity.peer_id_hex, is_initiator=True)
    bob = NoiseSession(bob_identity, alice_identity.peer_id_hex, is_initiator=False)

    msg1 = alice.start_handshake()
    msg2 = bob.process_handshake_message(msg1)
    msg3 = alice.process_handshake_message(msg2)
    assert msg3 is not None
    response = bob.process_handshake_message(msg3)
    assert response is None
    return alice, bob


def test_handshake_establishes_on_both_sides():
    alice_identity = Identity.generate()
    bob_identity = Identity.generate()
    alice, bob = _handshake(alice_identity, bob_identity)

    assert alice.established
    assert bob.established
    assert alice.remote_static_public_key == bob_identity.noise_public_bytes
    assert bob.remote_static_public_key == alice_identity.noise_public_bytes


def test_handshake_message_sizes_match_xx_pattern():
    alice_identity = Identity.generate()
    bob_identity = Identity.generate()
    alice = NoiseSession(alice_identity, bob_identity.peer_id_hex, is_initiator=True)
    bob = NoiseSession(bob_identity, alice_identity.peer_id_hex, is_initiator=False)

    msg1 = alice.start_handshake()
    assert len(msg1) == 32  # -> e
    msg2 = bob.process_handshake_message(msg1)
    assert len(msg2) == 96  # <- e, ee, s, es
    msg3 = alice.process_handshake_message(msg2)
    assert len(msg3) == 64  # -> s, se


def test_encrypt_decrypt_round_trip_both_directions():
    alice_identity = Identity.generate()
    bob_identity = Identity.generate()
    alice, bob = _handshake(alice_identity, bob_identity)

    ct = alice.encrypt(b"hello bob")
    assert bob.decrypt(ct) == b"hello bob"

    ct2 = bob.encrypt(b"hello alice")
    assert alice.decrypt(ct2) == b"hello alice"


def test_wire_format_has_four_byte_nonce_prefix():
    alice_identity = Identity.generate()
    bob_identity = Identity.generate()
    alice, bob = _handshake(alice_identity, bob_identity)

    ct = alice.encrypt(b"x")
    assert int.from_bytes(ct[:4], "big") == 0  # first message uses counter 0
    ct2 = alice.encrypt(b"y")
    assert int.from_bytes(ct2[:4], "big") == 1  # counter increments


def test_replayed_ciphertext_is_rejected():
    alice_identity = Identity.generate()
    bob_identity = Identity.generate()
    alice, bob = _handshake(alice_identity, bob_identity)

    ct = alice.encrypt(b"only once")
    assert bob.decrypt(ct) == b"only once"
    with pytest.raises(NoiseSessionError):
        bob.decrypt(ct)


def test_peer_identity_mismatch_is_rejected():
    alice_identity = Identity.generate()
    bob_identity = Identity.generate()
    mallory_identity = Identity.generate()

    # Alice correctly expects bob's real peer ID (e.g. from a legitimate
    # announce) -- her side of the handshake validates fine. Bob, though,
    # thinks he's handshaking with mallory's peer ID; when alice's real key
    # shows up instead it must be rejected, not silently bound to the wrong
    # identity. The remote static key (and thus the mismatch) is only
    # learned on message 3 -- messages 1/2 only carry ephemeral keys, per
    # the XX pattern.
    alice = NoiseSession(alice_identity, bob_identity.peer_id_hex, is_initiator=True)
    bob = NoiseSession(bob_identity, mallory_identity.peer_id_hex, is_initiator=False)

    msg1 = alice.start_handshake()
    msg2 = bob.process_handshake_message(msg1)
    msg3 = alice.process_handshake_message(msg2)
    with pytest.raises(PeerIdentityMismatch):
        bob.process_handshake_message(msg3)
