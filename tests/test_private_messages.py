import asyncio

from bitchat import protocol
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine


def make_engine(nickname):
    identity = Identity.generate()
    private_messages = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda *a: None,
        on_private_message=lambda peer_id, sender, content: private_messages.append(
            (peer_id, sender, content)
        ),
    )
    return engine, private_messages


def link(engine_a: MeshEngine, engine_b: MeshEngine) -> None:
    """Directly wires two engines' outbound packets into each other's
    handle_incoming, simulating a single direct BLE link between them."""

    async def a_to_b(raw: bytes, _exclude) -> None:
        await engine_b.handle_incoming(raw, link_id="a")

    async def b_to_a(raw: bytes, _exclude) -> None:
        await engine_a.handle_incoming(raw, link_id="b")

    engine_a.relay_sinks.append(a_to_b)
    engine_b.relay_sinks.append(b_to_a)


def test_dm_handshake_and_message_round_trip():
    alice, alice_inbox = make_engine("alice")
    bob, bob_inbox = make_engine("bob")
    link(alice, bob)

    # Realistic flow: nicknames are learned from an announce exchange
    # before a DM is ever sent, same as discovering someone in /peers.
    asyncio.run(bob.handle_incoming(alice.build_announce_packet()[0], link_id="a"))

    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi bob"))

    assert alice._noise_sessions[bob.identity.peer_id_hex].established
    assert bob._noise_sessions[alice.identity.peer_id_hex].established

    assert len(bob_inbox) == 1
    peer_id, sender, content = bob_inbox[0]
    assert peer_id == alice.identity.peer_id_hex
    assert sender == "alice"
    assert content == "hi bob"
    assert alice_inbox == []  # bob never replied


def test_dm_reply_after_session_established():
    alice, alice_inbox = make_engine("alice")
    bob, bob_inbox = make_engine("bob")
    link(alice, bob)

    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi bob"))
    asyncio.run(bob.send_private_message(alice.identity.peer_id_hex, "hi alice"))

    assert len(bob_inbox) == 1
    assert len(alice_inbox) == 1
    assert alice_inbox[0][2] == "hi alice"


def test_multiple_messages_queued_before_handshake_completes_all_flush():
    alice, _ = make_engine("alice")
    bob, bob_inbox = make_engine("bob")
    link(alice, bob)

    # Both queued before the handshake (triggered by the first call) completes.
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "first"))
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "second"))

    contents = [content for _, _, content in bob_inbox]
    assert contents == ["first", "second"]


def test_private_messages_are_not_delivered_as_public():
    alice, _ = make_engine("alice")
    bob, bob_inbox = make_engine("bob")
    public_messages = []
    bob.on_public_message = lambda *a: public_messages.append(a)
    link(alice, bob)

    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "secret"))

    assert len(bob_inbox) == 1
    assert public_messages == []


def test_small_noise_encrypted_packet_is_padded_but_public_message_is_not():
    # bitchat-android's BLEPacketPaddingPolicy: NOISE_HANDSHAKE/NOISE_ENCRYPTED
    # are padded to a block size when sent as a single (unfragmented) BLE
    # write; everything else (ANNOUNCE/MESSAGE/LEAVE/FILE_TRANSFER) is not.
    alice, _ = make_engine("alice")
    bob, bob_inbox = make_engine("bob")
    link(alice, bob)

    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi"))
    assert len(bob_inbox) == 1

    # The handshake-completion + DM send above produced several NOISE_*
    # packets on the wire; recover one by re-encoding a fresh DM the same way
    # and checking its length lands on a padding block boundary.
    alice._pending_dm_content.clear()
    sent = []

    async def capture(raw, _exclude):
        sent.append(raw)

    alice.relay_sinks.clear()
    alice.relay_sinks.append(capture)
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi again"))

    assert len(sent) == 1
    noise_packet = protocol.decode(sent[0])
    assert noise_packet.type == protocol.MessageType.NOISE_ENCRYPTED
    assert len(sent[0]) in protocol.PAD_BLOCK_SIZES

    public_raw = alice.build_public_message_packet("hi")[0]
    assert len(public_raw) not in protocol.PAD_BLOCK_SIZES
