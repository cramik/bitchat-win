import asyncio
import os

from bitchat.identity import Identity
from bitchat.mesh import MeshEngine


def make_engine(nickname):
    identity = Identity.generate()
    private_messages = []
    private_files = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda *a: None,
        on_private_message=lambda peer_id, sender, content: private_messages.append(
            (peer_id, sender, content)
        ),
        on_private_file_received=lambda peer_id, sender, name, mime, content: private_files.append(
            (peer_id, sender, name, mime, content)
        ),
    )
    return engine, private_messages, private_files


def link_via(near: MeshEngine, far: MeshEngine, link_id: str) -> None:
    """Wire `near` -> `far` one-directionally over a link identified by
    `link_id` -- a packet `near` received via this same link_id is never
    sent back out it, mirroring how a real transport never echoes a packet
    back the way it came. Call twice (swapped) for a bidirectional link."""

    async def sink(raw: bytes, exclude_link_id) -> None:
        if exclude_link_id == link_id:
            return
        await far.handle_incoming(raw, link_id=link_id)

    near.relay_sinks.append(sink)


def chain(alice: MeshEngine, relay: MeshEngine, bob: MeshEngine) -> None:
    """alice <-> relay <-> bob, with NO direct link between alice and bob --
    the only way a packet reaches bob from alice (or vice versa) is through
    relay's own _relay() forwarding."""
    link_via(alice, relay, "alice-relay")
    link_via(relay, alice, "alice-relay")
    link_via(relay, bob, "relay-bob")
    link_via(bob, relay, "relay-bob")


def test_private_message_reaches_bob_through_an_intermediate_relay_hop():
    alice, _, _ = make_engine("alice")
    relay, relay_inbox, _ = make_engine("relay")
    bob, bob_inbox, _ = make_engine("bob")
    chain(alice, relay, bob)

    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi bob, via relay"))

    assert alice._noise_sessions[bob.identity.peer_id_hex].established
    assert bob._noise_sessions[alice.identity.peer_id_hex].established

    assert len(bob_inbox) == 1
    peer_id, _, content = bob_inbox[0]
    assert peer_id == alice.identity.peer_id_hex
    assert content == "hi bob, via relay"

    # The intermediate hop forwards without ever decrypting/consuming it --
    # it never established a Noise session with either endpoint, and its own
    # callback never fired.
    assert relay.identity.peer_id_hex not in alice._noise_sessions
    assert relay._noise_sessions == {}
    assert relay_inbox == []


def test_private_file_reaches_bob_through_an_intermediate_relay_hop():
    alice, _, _ = make_engine("alice")
    relay, _, relay_files = make_engine("relay")
    bob, _, bob_files = make_engine("bob")
    chain(alice, relay, bob)

    # Establish the session first (mirrors send_private_file's own
    # no-queue-across-handshake contract, same as test_private_files.py).
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi"))
    assert bob._noise_sessions[alice.identity.peer_id_hex].established

    image_bytes = os.urandom(5_000)
    reason = asyncio.run(
        alice.send_private_file(bob.identity.peer_id_hex, image_bytes, file_name="x.jpg", mime_type="image/jpeg")
    )
    assert reason is None

    assert len(bob_files) == 1
    _, _, name, mime, content = bob_files[0]
    assert name == "x.jpg"
    assert mime == "image/jpeg"
    assert content == image_bytes
    assert relay_files == []  # the relay hop never reassembles this as "its own" delivery


def test_relay_stops_propagation_of_a_packet_addressed_to_itself():
    # White-box: exercise _relay() directly rather than through a full
    # handshake, since the interesting behavior is entirely inside that one
    # method -- everything upstream of it (dispatch, handlers) already has
    # its own coverage elsewhere.
    from bitchat.protocol import BitchatPacket, MessageType

    relay, _, _ = make_engine("relay")
    someone_else, _, _ = make_engine("someone_else")
    forwarded = []

    async def spy_sink(raw, exclude_link_id):
        forwarded.append(raw)

    relay.relay_sinks.append(spy_sink)

    addressed_to_relay = BitchatPacket(
        type=MessageType.NOISE_ENCRYPTED,
        sender_id=someone_else.identity.routing_id,
        recipient_id=relay.identity.routing_id,
        payload=b"whatever",
        timestamp_ms=1,
        ttl=7,
    )
    asyncio.run(relay._relay(addressed_to_relay, exclude_link_id="in"))
    assert forwarded == []  # already consumed by us -- do not keep flooding it

    addressed_to_someone_else = BitchatPacket(
        type=MessageType.NOISE_ENCRYPTED,
        sender_id=someone_else.identity.routing_id,
        recipient_id=os.urandom(8),
        payload=b"whatever",
        timestamp_ms=2,
        ttl=7,
    )
    asyncio.run(relay._relay(addressed_to_someone_else, exclude_link_id="in"))
    assert len(forwarded) == 1  # not for us -- flood it onward like anything else
