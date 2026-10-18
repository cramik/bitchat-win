import asyncio
import os

from bitchat.identity import Identity
from bitchat.mesh import MeshEngine


def make_engine(nickname):
    identity = Identity.generate()
    files_received = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda *a: None,
        on_file_received=lambda peer_id, sender, name, mime, content: files_received.append(
            (peer_id, sender, name, mime, content)
        ),
    )
    return engine, files_received


def link(engine_a: MeshEngine, engine_b: MeshEngine) -> None:
    async def a_to_b(raw: bytes, _exclude) -> None:
        await engine_b.handle_incoming(raw, link_id="a")

    engine_a.relay_sinks.append(a_to_b)


def test_small_file_is_not_fragmented():
    engine, _ = make_engine("me")
    packets = engine.build_file_transfer_packet(b"tiny", file_name="a.txt", mime_type="text/plain")
    assert packets is not None
    assert len(packets) == 1


def test_realistic_image_size_requires_fragmentation_and_arrives_intact():
    alice, _ = make_engine("alice")
    bob, bob_files = make_engine("bob")
    link(alice, bob)

    # Incompressible (random) binary, like a real JPEG -- big enough that it
    # must fragment even after the (futile) compression attempt.
    image_bytes = os.urandom(50_000)
    packets = alice.build_file_transfer_packet(image_bytes, file_name="img_test.jpg", mime_type="image/jpeg")
    assert packets is not None
    assert len(packets) > 1

    for raw in packets:
        asyncio.run(bob.handle_incoming(raw, link_id="a"))

    assert len(bob_files) == 1
    peer_id, sender, name, mime, content = bob_files[0]
    assert peer_id == alice.identity.peer_id_hex
    assert sender == "anon" + alice.identity.peer_id_hex[:4]  # bob never saw an announce
    assert name == "img_test.jpg"
    assert mime == "image/jpeg"
    assert content == image_bytes


def test_file_transfer_uses_nickname_when_announce_seen_first():
    alice, _ = make_engine("alice")
    bob, bob_files = make_engine("bob")
    link(alice, bob)

    asyncio.run(bob.handle_incoming(alice.build_announce_packet()[0], link_id="a"))
    packets = alice.build_file_transfer_packet(os.urandom(1000), file_name="x.bin")
    for raw in packets:
        asyncio.run(bob.handle_incoming(raw, link_id="a"))

    assert bob_files[0][1] == "alice"


def test_oversized_content_is_rejected_before_sending():
    from bitchat.file_packet import MAX_PAYLOAD_BYTES

    engine, _ = make_engine("me")
    assert engine.build_file_transfer_packet(b"x" * (MAX_PAYLOAD_BYTES + 1)) is None
