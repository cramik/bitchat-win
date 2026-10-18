from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bitchat import groups


def make_member(nickname="alice", signing_key=None):
    priv = Ed25519PrivateKey.generate()
    pub = signing_key or priv.public_key().public_bytes_raw()
    fingerprint = ("aa" * 32)  # placeholder overwritten by callers that need real ones
    return priv, groups.GroupMember(fingerprint=os_urandom_hex(), signing_key=pub, nickname=nickname)


def os_urandom_hex():
    import os

    return os.urandom(32).hex()


def make_group(name="test group", n_members=1):
    creator_priv = Ed25519PrivateKey.generate()
    creator_pub = creator_priv.public_key().public_bytes_raw()
    creator_fp = os_urandom_hex()
    members = [groups.GroupMember(fingerprint=creator_fp, signing_key=creator_pub, nickname="creator")]
    for i in range(n_members - 1):
        _, member = make_member(nickname=f"member{i}")
        members.append(member)
    group = groups.BitchatGroup(
        group_id=os_urandom_bytes(16), name=name, epoch=1, members=members, creator_fingerprint=creator_fp
    )
    return group, creator_priv


def os_urandom_bytes(n):
    import os

    return os.urandom(n)


def test_roster_encode_decode_round_trip():
    group, _ = make_group(n_members=3)
    blob = groups.GroupRosterCoding.encode(group.members)
    assert blob is not None
    decoded = groups.GroupRosterCoding.decode(blob)
    assert decoded == group.members


def test_roster_encode_rejects_over_member_cap():
    _, member = make_member()
    too_many = [member] * (groups.MAX_MEMBERS + 1)
    assert groups.GroupRosterCoding.encode(too_many) is None


def test_roster_truncates_long_nicknames_on_a_character_boundary():
    long_nick = "x" * 100
    _, member = make_member(nickname=long_nick)
    member.fingerprint = os_urandom_hex()
    blob = groups.GroupRosterCoding.encode([member])
    decoded = groups.GroupRosterCoding.decode(blob)
    assert len(decoded[0].nickname.encode("utf-8")) <= groups.MAX_NICKNAME_BYTES
    assert decoded[0].nickname == "x" * groups.MAX_NICKNAME_BYTES


def test_group_state_payload_round_trip_and_signature_verifies():
    group, creator_priv = make_group(n_members=2)
    key = os_urandom_bytes(32)
    state = groups.GroupStatePayload.make_signed(group, key, creator_priv)
    assert state is not None

    encoded = state.encode()
    assert encoded is not None
    decoded = groups.GroupStatePayload.decode(encoded)
    assert decoded is not None
    assert decoded.group_id == group.group_id
    assert decoded.name == group.name
    assert decoded.key == key
    assert decoded.epoch == group.epoch
    assert decoded.creator_fingerprint == group.creator_fingerprint
    assert decoded.verify_creator_signature()


def test_group_state_payload_rejects_tampered_key():
    group, creator_priv = make_group()
    key = os_urandom_bytes(32)
    state = groups.GroupStatePayload.make_signed(group, key, creator_priv)
    tampered = groups.GroupStatePayload(
        group_id=state.group_id,
        name=state.name,
        key=os_urandom_bytes(32),  # different key, same signature
        epoch=state.epoch,
        members=state.members,
        creator_fingerprint=state.creator_fingerprint,
        signature=state.signature,
    )
    assert not tampered.verify_creator_signature()


def test_group_state_payload_rejects_signature_from_non_creator():
    group, _ = make_group(n_members=2)
    key = os_urandom_bytes(32)
    impostor_priv = Ed25519PrivateKey.generate()
    # Signed by a member who is NOT the creator -- signing_content matches,
    # but verify_creator_signature checks against creator_fingerprint's own
    # pinned key, so an impostor's signature must not verify.
    state = groups.GroupStatePayload.make_signed(group, key, impostor_priv)
    assert not state.verify_creator_signature()


def test_as_group_round_trips_the_group_fields():
    group, creator_priv = make_group(n_members=2)
    key = os_urandom_bytes(32)
    state = groups.GroupStatePayload.make_signed(group, key, creator_priv)
    restored = state.as_group
    assert restored.group_id == group.group_id
    assert restored.epoch == group.epoch
    assert restored.members == group.members
    assert restored.creator_fingerprint == group.creator_fingerprint


def test_seal_and_open_message_round_trip():
    group, _ = make_group(n_members=2)
    key = os_urandom_bytes(32)
    sender_priv = Ed25519PrivateKey.generate()
    sender_pub = sender_priv.public_key().public_bytes_raw()

    payload = groups.seal_message(
        content="hello group",
        message_id="msg-1",
        sender_nickname="alice",
        sender_signing_key=sender_pub,
        timestamp_ms=1_700_000_000_000,
        group_id=group.group_id,
        epoch=group.epoch,
        key=key,
        signing_private_key=sender_priv,
    )
    envelope = groups.GroupMessageEnvelope.decode(payload)
    assert envelope is not None
    assert envelope.group_id == group.group_id
    assert envelope.epoch == group.epoch

    plaintext = groups.open_message(envelope, key)
    assert plaintext.content == "hello group"
    assert plaintext.sender_nickname == "alice"
    assert plaintext.sender_signing_key == sender_pub
    assert plaintext.message_id == "msg-1"


def test_open_message_rejects_wrong_key():
    group, _ = make_group()
    key = os_urandom_bytes(32)
    wrong_key = os_urandom_bytes(32)
    sender_priv = Ed25519PrivateKey.generate()
    payload = groups.seal_message(
        "secret", "id", "alice", sender_priv.public_key().public_bytes_raw(),
        1, group.group_id, group.epoch, key, sender_priv,
    )
    envelope = groups.GroupMessageEnvelope.decode(payload)
    try:
        groups.open_message(envelope, wrong_key)
        assert False, "expected GroupCryptoError"
    except groups.GroupCryptoError:
        pass


def test_open_message_rejects_wrong_epoch_via_aad_binding():
    # Same key, but the envelope claims a different epoch than what was
    # actually sealed under -- AAD binding must make this fail, not silently
    # decrypt under the "wrong" epoch label.
    group, _ = make_group()
    key = os_urandom_bytes(32)
    sender_priv = Ed25519PrivateKey.generate()
    payload = groups.seal_message(
        "secret", "id", "alice", sender_priv.public_key().public_bytes_raw(),
        1, group.group_id, group.epoch, key, sender_priv,
    )
    envelope = groups.GroupMessageEnvelope.decode(payload)
    tampered_envelope = groups.GroupMessageEnvelope(
        group_id=envelope.group_id, epoch=envelope.epoch + 1, nonce=envelope.nonce, ciphertext=envelope.ciphertext
    )
    try:
        groups.open_message(tampered_envelope, key)
        assert False, "expected GroupCryptoError"
    except groups.GroupCryptoError:
        pass


def test_open_message_rejects_tampered_ciphertext():
    group, _ = make_group()
    key = os_urandom_bytes(32)
    sender_priv = Ed25519PrivateKey.generate()
    payload = groups.seal_message(
        "secret", "id", "alice", sender_priv.public_key().public_bytes_raw(),
        1, group.group_id, group.epoch, key, sender_priv,
    )
    envelope = groups.GroupMessageEnvelope.decode(payload)
    tampered_ct = bytearray(envelope.ciphertext)
    tampered_ct[0] ^= 0xFF
    tampered_envelope = groups.GroupMessageEnvelope(
        group_id=envelope.group_id, epoch=envelope.epoch, nonce=envelope.nonce, ciphertext=bytes(tampered_ct)
    )
    try:
        groups.open_message(tampered_envelope, key)
        assert False, "expected GroupCryptoError"
    except groups.GroupCryptoError:
        pass


def test_message_envelope_round_trip():
    envelope = groups.GroupMessageEnvelope(
        group_id=os_urandom_bytes(16), epoch=5, nonce=os_urandom_bytes(12), ciphertext=b"ciphertext+tag"
    )
    encoded = envelope.encode()
    decoded = groups.GroupMessageEnvelope.decode(encoded)
    assert decoded == envelope


def test_group_peer_id_hex_is_stable_and_group_prefixed():
    group, _ = make_group()
    assert group.peer_id_hex.startswith("group_")
    assert group.peer_id_hex == "group_" + group.group_id.hex()


def test_group_id_from_peer_id_round_trips():
    group, _ = make_group()
    assert groups.group_id_from_peer_id(group.peer_id_hex) == group.group_id
    assert groups.group_id_from_peer_id("not-a-group-peer-id") is None
    assert groups.group_id_from_peer_id("group_not-hex") is None


def test_manager_create_group_persists_and_reloads(tmp_path):
    path = tmp_path / "groups.json"
    manager = groups.GroupManager(path)
    creator_priv = Ed25519PrivateKey.generate()
    creator = groups.GroupMember(
        fingerprint=os_urandom_hex(), signing_key=creator_priv.public_key().public_bytes_raw(), nickname="me"
    )
    group = manager.create_group("my group", creator)
    assert group is not None
    assert group.epoch == 1
    assert manager.key(group.group_id) is not None

    reloaded = groups.GroupManager(path)
    restored = reloaded.group(group.group_id)
    assert restored == group
    assert reloaded.key(group.group_id) == manager.key(group.group_id)


def test_manager_group_for_peer_id():
    manager = groups.GroupManager(_unused_path())
    creator = groups.GroupMember(fingerprint=os_urandom_hex(), signing_key=os_urandom_bytes(32), nickname="me")
    group = manager.create_group("g", creator)
    assert manager.group_for_peer_id(group.peer_id_hex) == group
    assert manager.group_for_peer_id("group_" + os_urandom_bytes(16).hex()) is None


def test_manager_rotate_key_bumps_epoch_and_changes_key():
    manager = groups.GroupManager(_unused_path())
    creator = groups.GroupMember(fingerprint=os_urandom_hex(), signing_key=os_urandom_bytes(32), nickname="me")
    group = manager.create_group("g", creator)
    original_key = manager.key(group.group_id)

    _, new_member = make_member(nickname="bob")
    rotated, new_key = manager.rotate_key(group.group_id, [creator, new_member])
    assert rotated.epoch == 2
    assert new_key != original_key
    assert manager.key(group.group_id) == new_key
    assert manager.group(group.group_id).members == [creator, new_member]


def test_manager_update_roster_requires_creator_present():
    manager = groups.GroupManager(_unused_path())
    creator = groups.GroupMember(fingerprint=os_urandom_hex(), signing_key=os_urandom_bytes(32), nickname="me")
    group = manager.create_group("g", creator)

    _, other = make_member(nickname="bob")
    assert manager.update_roster(group.group_id, [other]) is None  # creator missing -- rejected
    assert manager.update_roster(group.group_id, [creator, other]) is not None


def test_manager_remove_group_drops_it_and_its_key():
    manager = groups.GroupManager(_unused_path())
    creator = groups.GroupMember(fingerprint=os_urandom_hex(), signing_key=os_urandom_bytes(32), nickname="me")
    group = manager.create_group("g", creator)

    manager.remove_group(group.group_id)
    assert manager.group(group.group_id) is None
    assert manager.key(group.group_id) is None


def test_manager_wipe_clears_everything(tmp_path):
    path = tmp_path / "groups.json"
    manager = groups.GroupManager(path)
    creator = groups.GroupMember(fingerprint=os_urandom_hex(), signing_key=os_urandom_bytes(32), nickname="me")
    manager.create_group("g", creator)
    assert path.exists()

    manager.wipe()
    assert manager.groups == []
    assert not path.exists()


def test_manager_upsert_rejects_malformed_group():
    manager = groups.GroupManager(_unused_path())
    bad_group = groups.BitchatGroup(
        group_id=os_urandom_bytes(16), name="g", epoch=1, members=[], creator_fingerprint=os_urandom_hex()
    )
    assert manager.upsert(bad_group, os_urandom_bytes(32)) is False


def _unused_path():
    import tempfile
    from pathlib import Path

    return Path(tempfile.mkdtemp()) / "groups.json"
