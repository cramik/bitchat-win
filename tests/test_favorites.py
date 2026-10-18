import asyncio

from bitchat.favorites import (
    FavoritesStore,
    encode_favorite_control_message,
    parse_favorite_control_message,
)
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine


def test_encode_matches_reference_bracket_format():
    assert encode_favorite_control_message(True, "npub1abc") == "[FAVORITED]:npub1abc"
    assert encode_favorite_control_message(False, None) == "[UNFAVORITED]:"


def test_parse_round_trips_encode():
    assert parse_favorite_control_message("[FAVORITED]:npub1abc") == (True, "npub1abc")
    assert parse_favorite_control_message("[UNFAVORITED]:") == (False, None)
    assert parse_favorite_control_message("just a normal message") is None


def test_parse_ignores_leading_trailing_whitespace():
    assert parse_favorite_control_message("  [FAVORITED]:npub1abc  ") == (True, "npub1abc")


def test_favorites_store_persists_across_instances(tmp_path):
    path = tmp_path / "favorites.json"
    store = FavoritesStore(path)
    store.set_we_favorited("aaaa1111aaaa1111", True, nickname="alice")
    store.record_their_notification("aaaa1111aaaa1111", True, "npub1xyz")

    reloaded = FavoritesStore(path)
    record = reloaded.get("aaaa1111aaaa1111")
    assert record is not None
    assert record.we_favorited is True
    assert record.they_favorited is True
    assert record.nostr_npub == "npub1xyz"
    assert record.is_mutual is True
    assert record.nickname == "alice"


def test_is_mutual_requires_both_sides(tmp_path):
    store = FavoritesStore(tmp_path / "favorites.json")
    store.set_we_favorited("bbbb2222bbbb2222", True)
    record = store.get("bbbb2222bbbb2222")
    assert record.is_mutual is False  # they haven't favorited us (yet)

    store.record_their_notification("bbbb2222bbbb2222", True, None)
    assert store.get("bbbb2222bbbb2222").is_mutual is True


def make_engine(nickname, favorites_path=None, on_favorite_notice=None, our_npub=None):
    identity = Identity.generate()
    private_messages = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda *a: None,
        on_private_message=lambda peer_id, sender, content: private_messages.append(
            (peer_id, sender, content)
        ),
        favorites=FavoritesStore(favorites_path) if favorites_path is not None else None,
        on_favorite_notice=on_favorite_notice,
        our_npub=our_npub,
    )
    return engine, private_messages


def link(engine_a: MeshEngine, engine_b: MeshEngine) -> None:
    async def a_to_b(raw: bytes, _exclude) -> None:
        await engine_b.handle_incoming(raw, link_id="a")

    async def b_to_a(raw: bytes, _exclude) -> None:
        await engine_a.handle_incoming(raw, link_id="b")

    engine_a.relay_sinks.append(a_to_b)
    engine_b.relay_sinks.append(b_to_a)


def test_favorite_notification_is_intercepted_not_delivered_as_private_message(tmp_path):
    alice, _ = make_engine("alice", our_npub="npub1alice")
    notices = []
    bob, bob_messages = make_engine(
        "bob",
        favorites_path=tmp_path / "bob_favorites.json",
        on_favorite_notice=lambda *a: notices.append(a),
    )
    link(alice, bob)
    asyncio.run(bob.handle_incoming(alice.build_announce_packet()[0], link_id="a"))

    asyncio.run(alice.send_favorite_notification(bob.identity.peer_id_hex, True))

    assert bob_messages == []  # never shows up as a normal DM
    assert len(notices) == 1
    peer_id, sender, is_favorite, is_mutual = notices[0]
    assert peer_id == alice.identity.peer_id_hex
    assert sender == "alice"
    assert is_favorite is True
    assert is_mutual is False  # bob hasn't favorited alice back yet

    record = bob.favorites.get(alice.identity.peer_id_hex)
    assert record.nostr_npub == "npub1alice"
    assert record.they_favorited is True


def test_mutual_favorite_detected_once_both_sides_notify(tmp_path):
    alice, _ = make_engine("alice", our_npub="npub1alice")
    notices = []
    bob, _ = make_engine(
        "bob",
        favorites_path=tmp_path / "bob_favorites.json",
        on_favorite_notice=lambda *a: notices.append(a),
    )
    link(alice, bob)

    # Bob already did his own local "/favorite alice" before her notice
    # arrives -- the two booleans are independent, order doesn't matter.
    bob.favorites.set_we_favorited(alice.identity.peer_id_hex, True, "alice")
    assert bob.favorites.get(alice.identity.peer_id_hex).is_mutual is False  # not yet -- alice hasn't notified

    asyncio.run(alice.send_favorite_notification(bob.identity.peer_id_hex, True))

    assert bob.favorites.get(alice.identity.peer_id_hex).is_mutual is True
    assert len(notices) == 1
    assert notices[0][3] is True  # is_mutual reported True on this notice


def test_favorites_disabled_falls_back_to_plain_private_message():
    # No FavoritesStore configured at all -- a control-message-shaped
    # content string is just delivered as ordinary DM text, matching how
    # the feature is fully opt-in (mirrors on_file_received etc.).
    alice, _ = make_engine("alice")
    bob, bob_messages = make_engine("bob")
    link(alice, bob)

    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "[FAVORITED]:npub1whatever"))

    assert len(bob_messages) == 1
    assert bob_messages[0][2] == "[FAVORITED]:npub1whatever"
