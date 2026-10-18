import asyncio
import time

import pytest

from bitchat.geohash_channel import GeohashChannelManager
from bitchat.nostr_event import NostrEvent, NostrKind
from bitchat.nostr_identity import NostrIdentity
from bitchat.nostr_relay import NostrRelayPool


class CapturingRelayPool(NostrRelayPool):
    """A NostrRelayPool that never touches the network -- records calls
    instead of talking to real relays."""

    def __init__(self):
        super().__init__("aa" * 32, on_event=self._noop, relays=[])
        self.published = []
        self.subscriptions = []
        self.unsubscriptions = []

    async def _noop(self, event):
        pass

    async def publish(self, event):
        self.published.append(event)
        return 1

    async def subscribe(self, sub_id, filter_dict):
        self.subscriptions.append((sub_id, filter_dict))
        self._subscriptions[sub_id] = filter_dict

    async def unsubscribe(self, sub_id):
        self.unsubscriptions.append(sub_id)
        self._subscriptions.pop(sub_id, None)


def make_manager():
    seed = b"\x02" * 32
    relay = CapturingRelayPool()
    messages = []
    manager = GeohashChannelManager(seed, relay, on_message=lambda *a: messages.append(a))
    return manager, relay, messages


def test_join_normalizes_the_geohash():
    manager, _, _ = make_manager()
    joined = asyncio.run(manager.join("  9Q8YYK  "))
    assert joined == "9q8yyk"
    assert manager.current_geohash == "9q8yyk"


def test_join_rejects_an_invalid_geohash():
    manager, _, _ = make_manager()
    with pytest.raises(ValueError):
        asyncio.run(manager.join("not-a-geohash!"))
    assert manager.current_geohash is None


def test_join_subscribes_with_correct_filter():
    manager, relay, _ = make_manager()
    asyncio.run(manager.join("9q8yy"))

    assert len(relay.subscriptions) == 1
    sub_id, filter_dict = relay.subscriptions[0]
    assert sub_id == "geo-9q8yy"
    assert filter_dict == {"kinds": [NostrKind.EPHEMERAL_EVENT, NostrKind.GEOHASH_PRESENCE], "#g": ["9q8yy"]}


def test_join_sends_immediate_presence_for_coarse_geohash():
    manager, relay, _ = make_manager()
    asyncio.run(manager.join("9q8yy"))  # 5 chars -- coarse enough for presence

    assert len(relay.published) == 1
    assert relay.published[0].kind == NostrKind.GEOHASH_PRESENCE
    asyncio.run(manager.leave())  # tear down the background presence task cleanly


def test_join_does_not_send_presence_for_fine_grained_geohash():
    manager, relay, _ = make_manager()
    asyncio.run(manager.join("9q8yyk8"))  # 7 chars -- too fine-grained for presence
    assert relay.published == []


def test_join_switches_channels_leaving_the_previous_one():
    manager, relay, _ = make_manager()
    asyncio.run(manager.join("9q8yy"))
    asyncio.run(manager.join("u4pru"))

    assert relay.unsubscriptions == ["geo-9q8yy"]
    assert manager.current_geohash == "u4pru"
    sub_ids = [sub_id for sub_id, _ in relay.subscriptions]
    assert sub_ids == ["geo-9q8yy", "geo-u4pru"]


def test_leave_clears_state_and_unsubscribes():
    manager, relay, _ = make_manager()
    asyncio.run(manager.join("9q8yy"))
    asyncio.run(manager.leave())

    assert manager.current_geohash is None
    assert manager.identity is None
    assert relay.unsubscriptions == ["geo-9q8yy"]


def test_leave_when_not_joined_is_a_no_op():
    manager, relay, _ = make_manager()
    asyncio.run(manager.leave())
    assert relay.unsubscriptions == []


def test_send_publishes_an_ephemeral_event():
    manager, relay, _ = make_manager()
    asyncio.run(manager.join("9q8yyk8"))  # long geohash -- skip the presence event noise
    asyncio.run(manager.send("hello channel", nickname="alice"))

    assert len(relay.published) == 1
    event = relay.published[0]
    assert event.kind == NostrKind.EPHEMERAL_EVENT
    assert event.content == "hello channel"
    assert event.pubkey == manager.identity.pubkey_hex


def test_send_raises_when_not_in_a_channel():
    manager, _, _ = make_manager()
    with pytest.raises(RuntimeError):
        asyncio.run(manager.send("hi"))


def test_handle_incoming_event_dispatches_message_for_the_current_channel():
    manager, _, messages = make_manager()
    asyncio.run(manager.join("9q8yyk8"))

    sender = NostrIdentity.generate()
    from bitchat import geohash

    event = geohash.create_ephemeral_geohash_event("hi there", "9q8yyk8", sender, nickname="bob")
    asyncio.run(manager.handle_incoming_event(event))

    assert len(messages) == 1
    ghash, pubkey, nickname, content, teleported = messages[0]
    assert ghash == "9q8yyk8"
    assert pubkey == sender.pubkey_hex
    assert nickname == "bob"
    assert content == "hi there"
    assert teleported is True


def test_handle_incoming_event_ignores_a_different_channel():
    manager, _, messages = make_manager()
    asyncio.run(manager.join("9q8yyk8"))

    from bitchat import geohash

    sender = NostrIdentity.generate()
    event = geohash.create_ephemeral_geohash_event("wrong channel", "u4pruydq", sender)
    asyncio.run(manager.handle_incoming_event(event))

    assert messages == []


def test_handle_incoming_event_dedupes_the_same_event_id():
    manager, _, messages = make_manager()
    asyncio.run(manager.join("9q8yyk8"))

    from bitchat import geohash

    sender = NostrIdentity.generate()
    event = geohash.create_ephemeral_geohash_event("hi", "9q8yyk8", sender)
    asyncio.run(manager.handle_incoming_event(event))
    asyncio.run(manager.handle_incoming_event(event))

    assert len(messages) == 1


def test_handle_incoming_event_rejects_bad_signature():
    manager, _, messages = make_manager()
    asyncio.run(manager.join("9q8yyk8"))

    sender = NostrIdentity.generate()
    event = NostrEvent(
        pubkey=sender.pubkey_hex,
        created_at=int(time.time()),
        kind=NostrKind.EPHEMERAL_EVENT,
        tags=[["g", "9q8yyk8"]],
        content="forged",
        id="ff" * 32,
        sig="00" * 64,
    )
    asyncio.run(manager.handle_incoming_event(event))
    assert messages == []


def test_participant_count_reflects_the_online_window():
    manager, _, _ = make_manager()
    asyncio.run(manager.join("9q8yyk8"))

    from bitchat import geohash
    from bitchat.geohash_channel import Participant

    manager._participants["fresh"] = Participant(pubkey_hex="fresh", nickname=None, last_seen=time.time())
    manager._participants["stale"] = Participant(
        pubkey_hex="stale",
        nickname=None,
        last_seen=time.time() - geohash.PRESENCE_ONLINE_WINDOW_SECONDS - 10,
    )
    assert manager.participant_count() == 1
