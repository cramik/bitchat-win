from bitchat import geohash
from bitchat.nostr_event import NostrKind
from bitchat.nostr_identity import NostrIdentity


def test_is_valid_geohash_accepts_real_geohash_charset():
    assert geohash.is_valid_geohash("9q8yyk")
    assert geohash.is_valid_geohash("u4pruydqqvj")
    assert geohash.is_valid_geohash("0")


def test_is_valid_geohash_rejects_excluded_letters_and_bad_length():
    # geohash's base32 alphabet excludes a, i, l, o
    assert not geohash.is_valid_geohash("abcdef")
    assert not geohash.is_valid_geohash("")
    assert not geohash.is_valid_geohash("x" * 13)


def test_normalize_geohash_strips_and_lowercases():
    assert geohash.normalize_geohash("  9Q8YYK  ") == "9q8yyk"


def test_should_send_presence_matches_precision_privacy_rule():
    assert geohash.should_send_presence("9q8yy")  # 5 chars -- region/city, ok
    assert not geohash.should_send_presence("9q8yyk8")  # 7 chars -- too fine-grained


def test_presence_interval_is_within_spec_bounds():
    for _ in range(50):
        interval = geohash.next_presence_interval_seconds()
        assert geohash.PRESENCE_INTERVAL_MIN_SECONDS <= interval <= geohash.PRESENCE_INTERVAL_MAX_SECONDS


def test_ephemeral_event_has_g_and_teleport_tags_and_is_signed():
    identity = NostrIdentity.generate()
    event = geohash.create_ephemeral_geohash_event("hello channel", "9q8yyk", identity, nickname="alice")

    assert event.kind == NostrKind.EPHEMERAL_EVENT
    assert event.content == "hello channel"
    assert event.is_valid_signature()
    assert geohash.geohash_tag_value(event) == "9q8yyk"
    assert geohash.nickname_tag_value(event) == "alice"
    assert geohash.is_teleported(event)  # always true -- no GPS to claim otherwise


def test_ephemeral_event_omits_nickname_tag_when_none_given():
    identity = NostrIdentity.generate()
    event = geohash.create_ephemeral_geohash_event("hi", "9q8yyk", identity)
    assert geohash.nickname_tag_value(event) is None


def test_presence_event_has_empty_content_and_only_g_tag():
    identity = NostrIdentity.generate()
    event = geohash.create_geohash_presence_event("9q8yy", identity)

    assert event.kind == NostrKind.GEOHASH_PRESENCE
    assert event.content == ""
    assert event.tags == [["g", "9q8yy"]]
    assert event.is_valid_signature()


def test_ephemeral_and_presence_events_use_the_geohash_derived_identity_not_favorite_dm_identity():
    seed = b"\x01" * 32
    geo_identity = NostrIdentity.derive_for_geohash(seed, "9q8yyk")
    dm_identity = NostrIdentity.generate()

    event = geohash.create_ephemeral_geohash_event("hi", "9q8yyk", geo_identity)
    assert event.pubkey == geo_identity.pubkey_hex
    assert event.pubkey != dm_identity.pubkey_hex
