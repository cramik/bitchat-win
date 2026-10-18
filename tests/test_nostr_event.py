from bitchat.nostr_event import (
    NostrEvent,
    NostrKind,
    create_private_message_gift_wrap,
    decrypt_private_message_gift_wrap,
)
from bitchat.nostr_identity import NostrIdentity


def test_gift_wrap_round_trip_delivers_content_and_sender():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()

    gift_wrap = create_private_message_gift_wrap("hi bob, over the internet", bob.pubkey_hex, alice)
    assert gift_wrap.kind == NostrKind.GIFT_WRAP
    assert gift_wrap.pubkey != alice.pubkey_hex  # signed by a fresh ephemeral key, not alice's real one
    assert gift_wrap.is_valid_signature()

    result = decrypt_private_message_gift_wrap(gift_wrap, bob)
    assert result is not None
    content, sender_pubkey, created_at = result
    assert content == "hi bob, over the internet"
    assert sender_pubkey == alice.pubkey_hex
    assert isinstance(created_at, int)


def test_gift_wrap_uses_a_different_ephemeral_key_each_time():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()

    first = create_private_message_gift_wrap("first", bob.pubkey_hex, alice)
    second = create_private_message_gift_wrap("second", bob.pubkey_hex, alice)
    assert first.pubkey != second.pubkey


def test_wrong_recipient_cannot_decrypt():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()
    mallory = NostrIdentity.generate()

    gift_wrap = create_private_message_gift_wrap("secret for bob", bob.pubkey_hex, alice)
    assert decrypt_private_message_gift_wrap(gift_wrap, mallory) is None


def test_rumor_is_never_signed():
    # NIP-59: the innermost event (the actual message) is deliberately left
    # unsigned -- only the seal wrapping it carries a real signature.
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()
    gift_wrap = create_private_message_gift_wrap("hi", bob.pubkey_hex, alice)

    from bitchat import nostr_crypto

    seal_json = nostr_crypto.decrypt(gift_wrap.content, gift_wrap.pubkey, bob.private_key)
    import json

    seal = NostrEvent.from_json_object(json.loads(seal_json))
    assert seal.kind == NostrKind.SEAL
    assert seal.sig is not None

    rumor_json = nostr_crypto.decrypt(seal.content, seal.pubkey, bob.private_key)
    rumor = NostrEvent.from_json_object(json.loads(rumor_json))
    assert rumor.sig is None


def test_to_json_object_omits_sig_key_entirely_when_unsigned():
    event = NostrEvent(pubkey="aa" * 32, created_at=1, kind=14, tags=[], content="hi")
    obj = event.to_json_object()
    assert "sig" not in obj  # must be omitted, not present as null -- see module docstring


def test_to_json_object_round_trips_through_from_json_object():
    identity = NostrIdentity.generate()
    event = NostrEvent(
        pubkey=identity.pubkey_hex, created_at=123, kind=1, tags=[["p", "abc"]], content="hello"
    ).sign(identity.private_key)

    restored = NostrEvent.from_json_object(event.to_json_object())
    assert restored == event
    assert restored.is_valid_signature()


def test_tampered_seal_signature_is_rejected():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()
    gift_wrap = create_private_message_gift_wrap("hi", bob.pubkey_hex, alice)

    # Re-seal with a tampered rumor content but keep the original signature --
    # simulates a MITM that can't re-sign as alice, and confirms the seal
    # signature check actually catches it rather than trusting the content.
    from bitchat import nostr_crypto
    import json

    seal_json = nostr_crypto.decrypt(gift_wrap.content, gift_wrap.pubkey, bob.private_key)
    seal = NostrEvent.from_json_object(json.loads(seal_json))
    tampered_seal = seal.__class__(
        pubkey=seal.pubkey,
        created_at=seal.created_at,
        kind=seal.kind,
        tags=seal.tags,
        content=seal.content + "tampered",
        id=seal.id,
        sig=seal.sig,
    )
    assert not tampered_seal.is_valid_signature()
