import asyncio

from bitchat import groups
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine


def make_engine(nickname, group_manager_path=None):
    identity = Identity.generate()
    group_messages = []
    group_notices = []
    engine = MeshEngine(
        identity,
        nickname,
        on_public_message=lambda *a: None,
        group_manager=groups.GroupManager(group_manager_path) if group_manager_path is not None else None,
        on_group_message=lambda *a: group_messages.append(a),
        on_group_notice=lambda *a: group_notices.append(a),
    )
    return engine, group_messages, group_notices


def link(engine_a: MeshEngine, engine_b: MeshEngine) -> None:
    async def a_to_b(raw: bytes, _exclude) -> None:
        await engine_b.handle_incoming(raw, link_id="a")

    async def b_to_a(raw: bytes, _exclude) -> None:
        await engine_a.handle_incoming(raw, link_id="b")

    engine_a.relay_sinks.append(a_to_b)
    engine_b.relay_sinks.append(b_to_a)


def establish(alice: MeshEngine, bob: MeshEngine) -> None:
    """Announce exchange (populates verified peer_identities on both sides)
    plus a DM handshake (establishes the Noise session invite_to_group
    requires) -- the two real-world prerequisites for inviting someone."""
    asyncio.run(bob.handle_incoming(alice.build_announce_packet()[0], link_id="a"))
    asyncio.run(alice.handle_incoming(bob.build_announce_packet()[0], link_id="b"))
    asyncio.run(alice.send_private_message(bob.identity.peer_id_hex, "hi"))


def test_full_group_lifecycle_create_invite_message_remove(tmp_path):
    alice, _, _ = make_engine("alice", tmp_path / "alice_groups.json")
    bob, bob_msgs, bob_notices = make_engine("bob", tmp_path / "bob_groups.json")
    link(alice, bob)
    establish(alice, bob)

    group = asyncio.run(alice.create_group("my group"))
    assert group is not None
    assert group.epoch == 1
    assert len(group.members) == 1

    reason = asyncio.run(alice.invite_to_group(group.group_id, bob.identity.peer_id_hex))
    assert reason is None

    # Bob got a real invite: notice fired, and he's now a member locally.
    assert len(bob_notices) == 1
    assert "added to my group" in bob_notices[0][2]
    bob_group = bob.group_manager.group(group.group_id)
    assert bob_group is not None
    assert bob_group.epoch == 2  # invite always rotates, even for adds
    assert len(bob_group.members) == 2

    # Alice's own local copy also reflects the rotation.
    alice_group = alice.group_manager.group(group.group_id)
    assert alice_group.epoch == 2

    reason = asyncio.run(alice.send_group_message(group.group_id, "hello group"))
    assert reason is None
    assert len(bob_msgs) == 1
    group_peer_id, group_name, sender, content = bob_msgs[0]
    assert group_peer_id == group.peer_id_hex
    assert group_name == "my group"
    assert sender == "alice"
    assert content == "hello group"

    reason = asyncio.run(alice.remove_from_group(group.group_id, bob.identity.peer_id_hex))
    assert reason is None
    assert bob.group_manager.group(group.group_id) is None  # bob dropped it locally
    assert any("removed from" in n[2] for n in bob_notices)
    assert alice.group_manager.group(group.group_id).epoch == 3


def test_only_creator_can_invite(tmp_path):
    alice, _, _ = make_engine("alice", tmp_path / "alice_groups.json")
    bob, _, _ = make_engine("bob", tmp_path / "bob_groups.json")
    carol, _, _ = make_engine("carol", tmp_path / "carol_groups.json")
    link(alice, bob)
    link(bob, carol)
    establish(alice, bob)
    establish(bob, carol)

    group = asyncio.run(alice.create_group("g"))
    asyncio.run(alice.invite_to_group(group.group_id, bob.identity.peer_id_hex))

    # Bob is now a member but not the creator -- his own invite attempt
    # must be rejected even though he has a real, valid copy of the group.
    bob_group = bob.group_manager.group(group.group_id)
    reason = asyncio.run(bob.invite_to_group(bob_group.group_id, carol.identity.peer_id_hex))
    assert reason is not None
    assert "creator" in reason.lower()


def test_only_creator_can_remove(tmp_path):
    alice, _, _ = make_engine("alice", tmp_path / "alice_groups.json")
    bob, _, _ = make_engine("bob", tmp_path / "bob_groups.json")
    link(alice, bob)
    establish(alice, bob)

    group = asyncio.run(alice.create_group("g"))
    asyncio.run(alice.invite_to_group(group.group_id, bob.identity.peer_id_hex))
    bob_group = bob.group_manager.group(group.group_id)

    reason = asyncio.run(bob.remove_from_group(bob_group.group_id, "alice"))
    assert reason is not None
    assert "creator" in reason.lower()


def test_cannot_invite_without_established_noise_session(tmp_path):
    alice, _, _ = make_engine("alice", tmp_path / "alice_groups.json")
    bob, _, _ = make_engine("bob", tmp_path / "bob_groups.json")
    link(alice, bob)
    # Announce only -- no DM handshake, so no established Noise session.
    asyncio.run(bob.handle_incoming(alice.build_announce_packet()[0], link_id="a"))
    asyncio.run(alice.handle_incoming(bob.build_announce_packet()[0], link_id="b"))

    group = asyncio.run(alice.create_group("g"))
    reason = asyncio.run(alice.invite_to_group(group.group_id, bob.identity.peer_id_hex))
    assert reason is not None
    assert "session" in reason.lower()


def test_three_member_group_key_update_reaches_existing_member(tmp_path):
    alice, _, _ = make_engine("alice", tmp_path / "alice_groups.json")
    bob, bob_msgs, bob_notices = make_engine("bob", tmp_path / "bob_groups.json")
    carol, carol_msgs, carol_notices = make_engine("carol", tmp_path / "carol_groups.json")
    link(alice, bob)
    link(alice, carol)
    establish(alice, bob)
    establish(alice, carol)

    group = asyncio.run(alice.create_group("g"))
    asyncio.run(alice.invite_to_group(group.group_id, bob.identity.peer_id_hex))
    asyncio.run(alice.invite_to_group(group.group_id, carol.identity.peer_id_hex))

    # Bob (already a member) should have received a key-update distributing
    # carol's addition too, without a fresh "added to" notice for himself.
    bob_group = bob.group_manager.group(group.group_id)
    assert bob_group.epoch == 3  # 1 (create) -> 2 (bob invited) -> 3 (carol invited)
    assert len(bob_group.members) == 3
    assert len([n for n in bob_notices if "added to" in n[2]]) == 1  # only his own original invite

    asyncio.run(alice.send_group_message(group.group_id, "hi all"))
    assert len(bob_msgs) == 1
    assert len(carol_msgs) == 1
    assert bob_msgs[0][3] == "hi all"
    assert carol_msgs[0][3] == "hi all"


def test_group_message_from_non_member_intermediate_hop_is_not_readable(tmp_path):
    # relay has no group_manager at all -- confirms it just floods the
    # GROUP_MESSAGE broadcast (like any other packet) without ever being
    # able to decrypt/attribute it, matching the "non-members relay but
    # never read" design.
    alice, _, _ = make_engine("alice", tmp_path / "alice_groups.json")
    relay, relay_msgs, _ = make_engine("relay")  # no group_manager
    bob, bob_msgs, _ = make_engine("bob", tmp_path / "bob_groups.json")

    async def a_to_relay(raw, _exclude):
        await relay.handle_incoming(raw, link_id="a")

    async def relay_to_bob(raw, _exclude):
        await bob.handle_incoming(raw, link_id="relay")

    alice.relay_sinks.append(a_to_relay)
    relay.relay_sinks.append(relay_to_bob)

    # bob needs to already be a member for this test -- link directly to
    # set it up, then rewire through the relay-only path for the message.
    link(alice, bob)
    establish(alice, bob)
    group = asyncio.run(alice.create_group("g"))
    asyncio.run(alice.invite_to_group(group.group_id, bob.identity.peer_id_hex))

    asyncio.run(alice.send_group_message(group.group_id, "via relay"))
    assert len(bob_msgs) == 1
    assert bob_msgs[0][3] == "via relay"
    assert relay_msgs == []  # relay has no group_manager -- never even tries


def test_groups_disabled_is_a_safe_no_op():
    engine, _, _ = make_engine("solo")  # no group_manager_path -> group_manager=None
    assert asyncio.run(engine.create_group("g")) is None
    assert asyncio.run(engine.send_group_message(b"\x00" * 16, "hi")) == "groups are disabled"
    assert asyncio.run(engine.invite_to_group(b"\x00" * 16, "someone")) == "groups are disabled"
    assert engine.list_groups() == []
