import asyncio

from bitchat import protocol
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine


def make_engine(nickname="me"):
    identity = Identity.generate()
    messages = []
    joined = []
    left = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda peer_id, sender, content: messages.append((peer_id, sender, content)),
        on_peer_joined=lambda peer_id, nick: joined.append((peer_id, nick)),
        on_peer_left=lambda peer_id, nick: left.append((peer_id, nick)),
    )
    return engine, messages, joined, left


def test_announce_registers_peer_and_fires_join():
    engine, messages, joined, left = make_engine()
    other = Identity.generate()

    other_engine, _, _, _ = make_engine("other")
    other_engine.identity = other
    announce_raw = other_engine.build_announce_packet()[0]

    asyncio.run(engine.handle_incoming(announce_raw, link_id="link-1"))

    assert other.peer_id_hex in engine.peers
    assert engine.peers[other.peer_id_hex] == "other"
    assert joined == [(other.peer_id_hex, "other")]


def test_public_message_dispatches_callback():
    # Sender nickname comes from the peer registry (learned via announce),
    # not from the message payload itself -- the wire payload is just raw
    # UTF-8 content (see build_public_message_packet docstring). So the
    # sender must announce first, matching what a real client does.
    engine, messages, joined, left = make_engine()
    other_engine, _, _, _ = make_engine("bob")
    asyncio.run(engine.handle_incoming(other_engine.build_announce_packet()[0], link_id="link-1"))

    msg_raw = other_engine.build_public_message_packet("hello there")[0]
    asyncio.run(engine.handle_incoming(msg_raw, link_id="link-1"))

    assert len(messages) == 1
    peer_id, sender, content = messages[0]
    assert sender == "bob"
    assert content == "hello there"
    assert peer_id == other_engine.identity.peer_id_hex


def test_public_message_from_unannounced_sender_uses_fallback_nickname():
    engine, messages, joined, left = make_engine()
    other_engine, _, _, _ = make_engine("bob")
    msg_raw = other_engine.build_public_message_packet("hi from a stranger")[0]

    asyncio.run(engine.handle_incoming(msg_raw, link_id="link-1"))

    assert len(messages) == 1
    _, sender, content = messages[0]
    assert content == "hi from a stranger"
    assert sender.startswith("anon")


def test_channel_tagged_message_dispatches_to_on_channel_message_not_on_public_message():
    identity = Identity.generate()
    channel_messages = []
    public_messages = []
    engine = MeshEngine(
        identity,
        "me",
        on_public_message=lambda peer_id, sender, content: public_messages.append((peer_id, sender, content)),
        on_channel_message=lambda peer_id, sender, channel, content: channel_messages.append(
            (peer_id, sender, channel, content)
        ),
    )
    other_engine, _, _, _ = make_engine("bob")
    asyncio.run(engine.handle_incoming(other_engine.build_announce_packet()[0], link_id="link-1"))

    msg_raw = other_engine.build_public_message_packet("hello everyone", channel="#general")[0]
    asyncio.run(engine.handle_incoming(msg_raw, link_id="link-1"))

    assert public_messages == []
    assert len(channel_messages) == 1
    peer_id, sender, channel, content = channel_messages[0]
    assert sender == "bob"
    assert channel == "#general"
    assert content == "hello everyone"


def test_channel_tagged_message_falls_back_to_on_public_message_when_channels_unwired():
    # No on_channel_message callback given -- exactly what a client with no
    # idea of this convention (a real phone, or bitchat-win before this
    # feature existed) sees: the prefix stays visible in plain content.
    engine, messages, joined, left = make_engine()
    other_engine, _, _, _ = make_engine("bob")
    asyncio.run(engine.handle_incoming(other_engine.build_announce_packet()[0], link_id="link-1"))

    msg_raw = other_engine.build_public_message_packet("hello everyone", channel="#general")[0]
    asyncio.run(engine.handle_incoming(msg_raw, link_id="link-1"))

    assert len(messages) == 1
    _, sender, content = messages[0]
    assert sender == "bob"
    assert content == "#general: hello everyone"


def test_duplicate_packet_is_dropped_and_not_relayed_twice():
    engine, messages, joined, left = make_engine()
    other_engine, _, _, _ = make_engine("bob")
    msg_raw = other_engine.build_public_message_packet("hi")[0]

    relayed = []

    async def fake_relay(raw, exclude_link_id):
        relayed.append((raw, exclude_link_id))

    engine.relay_sinks.append(fake_relay)

    asyncio.run(engine.handle_incoming(msg_raw, link_id="link-1"))
    asyncio.run(engine.handle_incoming(msg_raw, link_id="link-1"))

    assert len(messages) == 1
    assert len(relayed) == 1


def test_relay_decrements_ttl_and_excludes_origin_link():
    engine, messages, joined, left = make_engine()
    other_engine, _, _, _ = make_engine("bob")
    msg_raw = other_engine.build_public_message_packet("hi")[0]
    original_ttl = protocol.decode(msg_raw).ttl

    relayed = []

    async def fake_relay(raw, exclude_link_id):
        relayed.append((raw, exclude_link_id))

    engine.relay_sinks.append(fake_relay)
    asyncio.run(engine.handle_incoming(msg_raw, link_id="link-1"))

    assert len(relayed) == 1
    raw_out, exclude = relayed[0]
    assert exclude == "link-1"
    assert protocol.decode(raw_out).ttl == original_ttl - 1


def test_own_packets_are_not_processed():
    engine, messages, joined, left = make_engine()
    own_raw = engine.build_public_message_packet("echo of myself")[0]
    asyncio.run(engine.handle_incoming(own_raw, link_id="link-1"))
    assert messages == []


def test_ttl_of_zero_is_not_relayed():
    import dataclasses

    engine, messages, joined, left = make_engine()
    other_engine, _, _, _ = make_engine("bob")
    msg_raw = other_engine.build_public_message_packet("hi")[0]
    pkt = protocol.decode(msg_raw)
    pkt = dataclasses.replace(pkt, ttl=0)
    raw = protocol.encode(pkt, padding=False)

    relayed = []

    async def fake_relay(raw_, exclude_link_id):
        relayed.append(raw_)

    engine.relay_sinks.append(fake_relay)
    asyncio.run(engine.handle_incoming(raw, link_id="link-1"))
    assert relayed == []


def test_ttl_of_one_is_relayed_with_ttl_decremented_to_zero():
    # Matches bitchat-android's PacketRelayManager exactly: only ttl==0 is
    # dropped, so a packet arrives with one more hop of reach than the
    # off-by-one we originally had here (ttl<=1 dropped, verified wrong
    # against the reference while implementing multi-hop directed relay).
    import dataclasses

    engine, messages, joined, left = make_engine()
    other_engine, _, _, _ = make_engine("bob")
    msg_raw = other_engine.build_public_message_packet("hi")[0]
    pkt = protocol.decode(msg_raw)
    pkt = dataclasses.replace(pkt, ttl=1)
    raw = protocol.encode(pkt, padding=False)

    relayed = []

    async def fake_relay(raw_, exclude_link_id):
        relayed.append(protocol.decode(raw_))

    engine.relay_sinks.append(fake_relay)
    asyncio.run(engine.handle_incoming(raw, link_id="link-1"))
    assert len(relayed) == 1
    assert relayed[0].ttl == 0
