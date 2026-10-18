import asyncio

from bitchat.favorites import FavoritesStore
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine
from bitchat.nostr_event import decrypt_private_message_gift_wrap
from bitchat.nostr_identity import NostrIdentity
from bitchat.nostr_relay import NostrRelayPool


class CapturingRelayPool(NostrRelayPool):
    """A NostrRelayPool that never touches the network -- publish() just
    records events instead of sending them to a real relay."""

    def __init__(self, our_pubkey_hex):
        super().__init__(our_pubkey_hex, on_event=self._noop, relays=[])
        self.published = []

    async def _noop(self, event):
        pass

    async def publish(self, event):
        self.published.append(event)
        return 1


def make_engine(nickname, favorites_path=None, nostr_identity=None, nostr_relay_pool=None):
    identity = Identity.generate()
    private_messages = []
    favorite_notices = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda *a: None,
        on_private_message=lambda peer_id, sender, content: private_messages.append(
            (peer_id, sender, content)
        ),
        on_favorite_notice=lambda *a: favorite_notices.append(a),
        favorites=FavoritesStore(favorites_path) if favorites_path is not None else None,
        nostr_identity=nostr_identity,
        nostr_relay_pool=nostr_relay_pool,
    )
    return engine, private_messages, favorite_notices


def make_mutual_favorite_pair(tmp_path):
    """alice and bob, mutually favorited, each knowing the other's npub --
    the precondition for Nostr fallback to trigger at all."""
    alice_nostr = NostrIdentity.generate()
    bob_nostr = NostrIdentity.generate()
    alice_relay = CapturingRelayPool(alice_nostr.pubkey_hex)
    bob_relay = CapturingRelayPool(bob_nostr.pubkey_hex)

    alice, alice_msgs, alice_notices = make_engine(
        "alice", tmp_path / "alice_fav.json", nostr_identity=alice_nostr, nostr_relay_pool=alice_relay
    )
    bob, bob_msgs, bob_notices = make_engine(
        "bob", tmp_path / "bob_fav.json", nostr_identity=bob_nostr, nostr_relay_pool=bob_relay
    )

    alice.favorites.set_we_favorited(bob.identity.peer_id_hex, True, "bob")
    alice.favorites.record_their_notification(bob.identity.peer_id_hex, True, bob_nostr.npub, "bob")
    bob.favorites.set_we_favorited(alice.identity.peer_id_hex, True, "alice")
    bob.favorites.record_their_notification(alice.identity.peer_id_hex, True, alice_nostr.npub, "alice")

    return alice, bob, alice_relay, bob_relay, alice_msgs, bob_msgs, alice_notices, bob_notices


def test_send_private_message_uses_nostr_when_mutual_favorite_and_not_seen_on_mesh(tmp_path):
    alice, bob, alice_relay, bob_relay, alice_msgs, bob_msgs, _, _ = make_mutual_favorite_pair(tmp_path)

    # No BLE link between them at all -- alice has never seen bob on the mesh.
    assert bob.identity.peer_id_hex not in alice.peers
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi over the internet"))

    assert len(alice_relay.published) == 1
    gift_wrap = alice_relay.published[0]

    # Simulate bob's relay subscription delivering it back to him.
    asyncio.run(bob.handle_incoming_nostr_event(gift_wrap))
    assert len(bob_msgs) == 1
    peer_id, sender, content = bob_msgs[0]
    assert peer_id == alice.identity.peer_id_hex
    assert content == "hi over the internet"


def test_send_private_message_prefers_mesh_when_peer_already_seen(tmp_path):
    alice, bob, alice_relay, bob_relay, alice_msgs, bob_msgs, _, _ = make_mutual_favorite_pair(tmp_path)

    # Wire a direct mesh link and have bob announce -- now alice HAS seen
    # him on the mesh, so mesh should be preferred over Nostr even though
    # they're mutual favorites with known npubs.
    async def a_to_b(raw, _exclude):
        await bob.handle_incoming(raw, link_id="a")

    async def b_to_a(raw, _exclude):
        await alice.handle_incoming(raw, link_id="b")

    alice.relay_sinks.append(a_to_b)
    bob.relay_sinks.append(b_to_a)
    asyncio.run(alice.handle_incoming(bob.build_announce_packet()[0], link_id="b"))

    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi via mesh"))

    assert alice_relay.published == []  # Nostr was not used
    assert len(bob_msgs) == 1
    assert bob_msgs[0][2] == "hi via mesh"


def test_favorite_control_message_over_nostr_is_intercepted_not_delivered_as_text(tmp_path):
    alice, bob, alice_relay, bob_relay, alice_msgs, bob_msgs, alice_notices, bob_notices = (
        make_mutual_favorite_pair(tmp_path)
    )

    asyncio.run(alice.send_favorite_notification(bob.identity.peer_id_hex, True))
    assert len(alice_relay.published) == 1
    gift_wrap = alice_relay.published[0]

    asyncio.run(bob.handle_incoming_nostr_event(gift_wrap))
    assert bob_msgs == []
    assert len(bob_notices) == 1
    peer_id, sender, is_favorite, is_mutual = bob_notices[0]
    assert peer_id == alice.identity.peer_id_hex
    assert is_favorite is True
    assert is_mutual is True  # bob already favorited alice back in the fixture


def test_nostr_fallback_unavailable_without_mutual_favorite_falls_back_to_mesh(tmp_path):
    # No favorite relationship at all -- Nostr fallback must not fire even
    # though both sides have real Nostr identities/relay pools configured.
    alice_nostr = NostrIdentity.generate()
    bob_nostr = NostrIdentity.generate()
    alice_relay = CapturingRelayPool(alice_nostr.pubkey_hex)

    alice, _, _ = make_engine(
        "alice", tmp_path / "alice_fav.json", nostr_identity=alice_nostr, nostr_relay_pool=alice_relay
    )
    bob, bob_msgs, _ = make_engine("bob")

    sent = []

    async def capture(raw, _exclude):
        sent.append(raw)

    alice.relay_sinks.append(capture)
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi"))

    assert alice_relay.published == []
    assert len(sent) == 1  # fell back to the mesh (BLE handshake) path instead


def test_gift_wrap_actually_decrypts_with_the_intended_recipients_identity(tmp_path):
    # Sanity check that CapturingRelayPool's captured event is a real,
    # correctly-encrypted gift wrap, not a fixture standing in for one.
    alice, bob, alice_relay, _, _, _, _, _ = make_mutual_favorite_pair(tmp_path)
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "real crypto here"))

    gift_wrap = alice_relay.published[0]
    result = decrypt_private_message_gift_wrap(gift_wrap, bob.nostr_identity)
    assert result is not None
