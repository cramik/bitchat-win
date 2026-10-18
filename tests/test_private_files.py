import asyncio
import os

from bitchat.identity import Identity
from bitchat.mesh import MeshEngine


def make_engine(nickname):
    identity = Identity.generate()
    private_files = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda *a: None,
        on_private_file_received=lambda peer_id, sender, name, mime, content: private_files.append(
            (peer_id, sender, name, mime, content)
        ),
    )
    return engine, private_files


def link(engine_a: MeshEngine, engine_b: MeshEngine) -> None:
    async def a_to_b(raw: bytes, _exclude) -> None:
        await engine_b.handle_incoming(raw, link_id="a")

    async def b_to_a(raw: bytes, _exclude) -> None:
        await engine_a.handle_incoming(raw, link_id="b")

    engine_a.relay_sinks.append(a_to_b)
    engine_b.relay_sinks.append(b_to_a)


def establish_session(alice: MeshEngine, bob: MeshEngine) -> None:
    # Realistic flow: nicknames are learned from an announce exchange before
    # any DM, same as discovering someone in /peers.
    asyncio.run(bob.handle_incoming(alice.build_announce_packet()[0], link_id="a"))
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi"))
    assert alice._noise_sessions[bob.identity.peer_id_hex].established
    assert bob._noise_sessions[alice.identity.peer_id_hex].established


def test_small_private_file_round_trip_after_handshake():
    alice, _ = make_engine("alice")
    bob, bob_files = make_engine("bob")
    link(alice, bob)
    establish_session(alice, bob)

    reason = asyncio.run(alice.send_private_file(bob.identity.peer_id_hex, b"tiny", file_name="a.txt"))
    assert reason is None
    assert len(bob_files) == 1
    peer_id, sender, name, mime, content = bob_files[0]
    assert peer_id == alice.identity.peer_id_hex
    assert sender == "alice"
    assert name == "a.txt"
    assert content == b"tiny"


def test_realistic_image_size_private_dm_requires_fragmentation_and_arrives_intact():
    alice, _ = make_engine("alice")
    bob, bob_files = make_engine("bob")
    link(alice, bob)
    establish_session(alice, bob)

    image_bytes = os.urandom(50_000)
    reason = asyncio.run(
        alice.send_private_file(bob.identity.peer_id_hex, image_bytes, file_name="img.jpg", mime_type="image/jpeg")
    )
    assert reason is None
    assert len(bob_files) == 1
    _, _, name, mime, content = bob_files[0]
    assert name == "img.jpg"
    assert mime == "image/jpeg"
    assert content == image_bytes


def test_private_file_before_handshake_initiates_handshake_instead_of_queuing():
    alice, _ = make_engine("alice")
    bob, bob_files = make_engine("bob")
    link(alice, bob)

    reason = asyncio.run(alice.send_private_file(bob.identity.peer_id_hex, b"too early"))
    assert reason is not None
    assert "handshake" in reason.lower()
    # Unlike send_private_message, the file itself is never queued/auto-flushed --
    # the handshake alone completes, but nothing is delivered to bob.
    assert alice._noise_sessions[bob.identity.peer_id_hex].established
    assert bob._noise_sessions[alice.identity.peer_id_hex].established
    assert bob_files == []


def test_oversized_private_file_is_rejected_after_handshake():
    alice, _ = make_engine("alice")
    bob, bob_files = make_engine("bob")
    link(alice, bob)
    establish_session(alice, bob)

    huge = os.urandom(400_000)
    reason = asyncio.run(alice.send_private_file(bob.identity.peer_id_hex, huge))
    assert reason is not None
    assert "256" in reason or "fragment" in reason.lower()
    assert bob_files == []


def test_private_file_not_delivered_as_public_message_or_private_text():
    alice, _ = make_engine("alice")
    bob, bob_files = make_engine("bob")
    link(alice, bob)
    establish_session(alice, bob)

    # Wire up tracking only after the handshake's own "hi" text message has
    # already gone through, so it doesn't count against the assertion below.
    public_messages = []
    private_messages = []
    bob.on_public_message = lambda *a: public_messages.append(a)
    bob.on_private_message = lambda *a: private_messages.append(a)

    asyncio.run(alice.send_private_file(bob.identity.peer_id_hex, b"secret bytes", file_name="s.bin"))

    assert len(bob_files) == 1
    assert public_messages == []
    assert private_messages == []
