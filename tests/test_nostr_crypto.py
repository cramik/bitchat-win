import pytest
from coincurve import PrivateKey

from bitchat import nostr_crypto
from bitchat.nostr_identity import NostrIdentity


def test_nip44_encrypt_decrypt_round_trip():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()

    wire = nostr_crypto.encrypt("hello bob", bob.pubkey_hex, alice.private_key)
    assert wire.startswith("v2:")

    plaintext = nostr_crypto.decrypt(wire, alice.pubkey_hex, bob.private_key)
    assert plaintext == "hello bob"


def test_nip44_round_trip_with_unicode_content():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()
    message = "héllo 👋 世界"

    wire = nostr_crypto.encrypt(message, bob.pubkey_hex, alice.private_key)
    plaintext = nostr_crypto.decrypt(wire, alice.pubkey_hex, bob.private_key)
    assert plaintext == message


def test_nip44_decrypt_fails_with_wrong_key():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()
    mallory = NostrIdentity.generate()

    wire = nostr_crypto.encrypt("secret", bob.pubkey_hex, alice.private_key)
    with pytest.raises(nostr_crypto.Nip44Error):
        nostr_crypto.decrypt(wire, alice.pubkey_hex, mallory.private_key)


def test_nip44_decrypt_rejects_tampered_ciphertext():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()
    wire = nostr_crypto.encrypt("secret", bob.pubkey_hex, alice.private_key)

    # Flip a character in the middle, not the last one -- base64's trailing
    # character can carry unused padding bits that don't affect the decoded
    # bytes at all, which would make this test pass for the wrong reason.
    prefix, _, b64 = wire.partition(":")
    mid = len(b64) // 2
    tampered_char = "A" if b64[mid] != "A" else "B"
    tampered = f"{prefix}:{b64[:mid]}{tampered_char}{b64[mid + 1:]}"
    with pytest.raises(nostr_crypto.Nip44Error):
        nostr_crypto.decrypt(tampered, alice.pubkey_hex, bob.private_key)


def test_nip44_rejects_missing_version_prefix():
    with pytest.raises(nostr_crypto.Nip44Error, match="version prefix"):
        nostr_crypto.decrypt("not-a-v2-payload", "aa" * 32, PrivateKey())


def test_conversation_key_is_symmetric_between_both_parties():
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()

    # Encrypt side always assumes even-Y for the recipient's key; decrypt
    # tries both. Confirm the even-Y attempt from bob's side matches
    # whichever key alice actually used.
    alice_to_bob_key = nostr_crypto.derive_conversation_key(alice.private_key, bob.pubkey_hex, even_y=True)
    bob_even = nostr_crypto.derive_conversation_key(bob.private_key, alice.pubkey_hex, even_y=True)
    bob_odd = nostr_crypto.derive_conversation_key(bob.private_key, alice.pubkey_hex, even_y=False)
    assert alice_to_bob_key in (bob_even, bob_odd)


def test_event_id_and_signature_round_trip():
    identity = NostrIdentity.generate()
    pubkey_hex = identity.pubkey_hex
    created_at = 1_700_000_000
    kind = 1
    tags = [["p", "abc123"]]
    content = "hello world"

    event_id = nostr_crypto.compute_event_id(pubkey_hex, created_at, kind, tags, content)
    sig = nostr_crypto.sign_event_id(event_id, identity.private_key)

    assert nostr_crypto.verify_event_signature(
        pubkey_hex, created_at, kind, tags, content, event_id.hex(), sig.hex()
    )


def test_event_signature_rejects_tampered_content():
    identity = NostrIdentity.generate()
    pubkey_hex = identity.pubkey_hex
    created_at = 1_700_000_000
    kind = 1
    tags: list = []

    event_id = nostr_crypto.compute_event_id(pubkey_hex, created_at, kind, tags, "original")
    sig = nostr_crypto.sign_event_id(event_id, identity.private_key)

    assert not nostr_crypto.verify_event_signature(
        pubkey_hex, created_at, kind, tags, "tampered", event_id.hex(), sig.hex()
    )


def test_canonical_json_matches_expected_compact_no_html_escaping():
    value = [0, "pubkeyhex", 1700000000, 1, [["p", "abc"]], "notag"]
    serialized = nostr_crypto.canonical_json(value)
    assert ", " not in serialized  # no whitespace after a structural comma
    assert '": ' not in serialized  # no whitespace after a structural colon (n/a here, but be sure)
    assert serialized == '[0,"pubkeyhex",1700000000,1,[["p","abc"]],"notag"]'

    # HTML-unsafe characters in content stay literal -- Gson's
    # disableHtmlEscaping(), not the HTML-escaped default.
    tagged = nostr_crypto.canonical_json(["a <tag> & 'quote' / slash"])
    assert "\\u003c" not in tagged
    assert "<tag>" in tagged
    assert "&" in tagged
