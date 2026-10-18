import asyncio
import os

from bitchat import fragment, protocol
from bitchat.fragment import FragmentAssembler
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine
from bitchat.protocol import BitchatPacket, MessageType


def make_engine(nickname="me"):
    identity = Identity.generate()
    messages = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda peer_id, sender, content: messages.append((peer_id, sender, content)),
    )
    return engine, messages


def test_small_packet_is_not_fragmented():
    engine, _ = make_engine()
    packets = engine.build_public_message_packet("short message")
    assert len(packets) == 1


def test_large_message_is_fragmented_into_multiple_packets(monkeypatch):
    # Compression is a separate concern (test_compression.py); disabled here
    # so this deterministically exercises fragmentation regardless of how
    # compressible "x" * 2000 happens to be.
    monkeypatch.setattr(protocol.compression, "should_compress", lambda payload: False)
    engine, _ = make_engine()
    packets = engine.build_public_message_packet("x" * 2000)
    assert len(packets) > 1
    for raw in packets:
        pkt = protocol.decode(raw)
        assert pkt.type == MessageType.FRAGMENT
        assert pkt.signature is None  # fragments themselves are unsigned


def test_fragment_and_reassemble_round_trip():
    identity = Identity.generate()
    original = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=identity.routing_id,
        payload=os.urandom(1500),
        timestamp_ms=123456,
        ttl=7,
    )
    encoded = protocol.encode(original, padding=False)
    fragments = fragment.fragment_packet(original, encoded)
    assert len(fragments) > 1

    assembler = FragmentAssembler()
    result = None
    for raw in fragments:
        pkt = protocol.decode(raw)
        result = assembler.add(pkt)
    assert result is not None
    original_type, reassembled = result
    assert original_type == MessageType.MESSAGE
    assert reassembled == encoded

    decoded = protocol.decode(reassembled)
    assert decoded.payload == original.payload
    assert decoded.sender_id == original.sender_id


def test_reassembly_works_out_of_order():
    identity = Identity.generate()
    original = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=identity.routing_id,
        payload=os.urandom(1200),
        timestamp_ms=1,
        ttl=7,
    )
    encoded = protocol.encode(original, padding=False)
    fragments = fragment.fragment_packet(original, encoded)
    assert len(fragments) >= 3

    assembler = FragmentAssembler()
    packets = [protocol.decode(raw) for raw in fragments]
    shuffled = [packets[1], packets[0]] + packets[2:]

    result = None
    for pkt in shuffled:
        result = assembler.add(pkt)
    assert result is not None
    _, reassembled = result
    assert reassembled == encoded


def test_mesh_engine_reassembles_fragmented_public_message(monkeypatch):
    # Compression is a separate concern (test_compression.py); disabled here
    # so this test deterministically exercises fragmentation regardless of
    # how compressible the sample text happens to be.
    monkeypatch.setattr(protocol.compression, "should_compress", lambda payload: False)

    engine, messages = make_engine()
    other_engine, _ = make_engine("bob")
    asyncio.run(engine.handle_incoming(other_engine.build_announce_packet()[0], link_id="link-1"))

    long_content = "hello " * 200
    fragments = other_engine.build_public_message_packet(long_content)
    assert len(fragments) > 1

    for raw in fragments:
        asyncio.run(engine.handle_incoming(raw, link_id="link-1"))

    assert len(messages) == 1
    _, sender, content = messages[0]
    assert sender == "bob"
    assert content == long_content


def test_fragments_of_same_message_are_not_deduped_against_each_other(monkeypatch):
    monkeypatch.setattr(protocol.compression, "should_compress", lambda payload: False)

    engine, messages = make_engine()
    other_engine, _ = make_engine("bob")
    fragments = other_engine.build_public_message_packet("y" * 1500)
    assert len(fragments) > 1

    keys = {engine._dedup_key(protocol.decode(raw)) for raw in fragments}
    assert len(keys) == len(fragments)  # every fragment gets a distinct dedup key


def test_reassembled_message_is_not_relayed_as_a_second_whole_packet(monkeypatch):
    monkeypatch.setattr(protocol.compression, "should_compress", lambda payload: False)

    engine, messages = make_engine()
    other_engine, _ = make_engine("bob")
    asyncio.run(engine.handle_incoming(other_engine.build_announce_packet()[0], link_id="link-1"))

    relayed = []

    async def fake_relay(raw, exclude_link_id):
        relayed.append(protocol.decode(raw))

    engine.relay_sinks.append(fake_relay)

    fragments = other_engine.build_public_message_packet("z" * 1500)
    for raw in fragments:
        asyncio.run(engine.handle_incoming(raw, link_id="link-1"))

    assert len(messages) == 1
    # Every relayed packet should be a FRAGMENT (relayed piecewise) --
    # never the reassembled MESSAGE type relayed again as a whole.
    assert all(pkt.type == MessageType.FRAGMENT for pkt in relayed)
