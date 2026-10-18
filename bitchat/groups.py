"""Creator-managed E2EE private groups: wire formats and crypto.

Ported byte-exact from bitchat-reference (iOS)'s
`Services/Groups/GroupProtocol.swift`, this feature does not exist in
bitchat-android at all (confirmed: its `MessageType` enum has no group
value), so iOS is the sole source of truth here, not something we can
cross-check against a second reference implementation the way almost
everything else in this port has been.

Design in one paragraph: a group is a random 16-byte ID plus a 32-byte
ChaCha20-Poly1305 symmetric key, both known only to members. The creator
signs (Ed25519) every roster/key change ("group state") and distributes it
1:1 over each member's existing Noise session; a state's signature is
verified against the *creator's* signing key as pinned inside the roster
itself, and the Noise session peer must independently authenticate as that
same creator fingerprint, a member can't forge state on the creator's
behalf even with a compromised roster blob. Every roster change (add OR
remove) bumps the epoch and gets a fresh key, so a removed member's old key
can't decrypt anything from that point on. Chat messages are ChaCha20-
Poly1305-sealed with the current epoch key and broadcast like a public
message (MessageType.GROUP_MESSAGE, 0x25), but non-obviously, that outer
packet is deliberately UNSIGNED (see build_group_message_packet's
docstring): authenticity comes from the Ed25519 signature *inside* the
ciphertext instead, verified against the sender's roster-pinned signing
key, which, unlike an outer signature tied to a since-expired announce,
stays verifiable indefinitely, so a store-and-forward/gossip-sync copy
delivered long after the fact still checks out.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256, Hash

MAX_MEMBERS = 16
GROUP_ID_LENGTH = 16
KEY_LENGTH = 32
FINGERPRINT_LENGTH = 32  # SHA-256 fingerprint, raw bytes (64 hex chars)
SIGNING_KEY_LENGTH = 32  # Ed25519 public key
MAX_NICKNAME_BYTES = 64
NONCE_LENGTH = 12  # standard ChaCha20-Poly1305, not XChaCha, 12-byte nonce

SIGNING_DOMAIN = b"bitchat-group-v1"
MESSAGE_SIGNING_DOMAIN = b"bitchat-group-msg-v1"


class GroupTLVError(Exception):
    """A TLV value exceeded the 16-bit length field."""


def _sha256(data: bytes) -> bytes:
    digest = Hash(SHA256())
    digest.update(data)
    return digest.finalize()


def _tlv_put(out: bytearray, field_type: int, value: bytes) -> None:
    if len(value) > 0xFFFF:
        raise GroupTLVError(f"value too long for a 16-bit TLV length field: {len(value)} bytes")
    out.append(field_type)
    out += len(value).to_bytes(2, "big")
    out += value


def _tlv_parse(data: bytes) -> Optional[List[Tuple[int, bytes]]]:
    fields: List[Tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 3:
            return None
        field_type = data[offset]
        length = int.from_bytes(data[offset + 1 : offset + 3], "big")
        offset += 3
        if len(data) - offset < length:
            return None
        fields.append((field_type, data[offset : offset + length]))
        offset += length
    return fields


def _truncate_nickname(nickname: str) -> bytes:
    """UTF-8 bytes of `nickname`, trimmed to at most MAX_NICKNAME_BYTES,
    dropping whole characters so the result is never split mid-codepoint."""
    candidate = nickname
    while len(candidate.encode("utf-8")) > MAX_NICKNAME_BYTES:
        candidate = candidate[:-1]
    return candidate.encode("utf-8")


@dataclass
class GroupMember:
    fingerprint: str  # 64 hex chars (32-byte SHA-256 fingerprint)
    signing_key: bytes  # 32-byte Ed25519 public key
    nickname: str


@dataclass
class BitchatGroup:
    group_id: bytes  # 16 random bytes
    name: str
    epoch: int  # bumps on every key rotation
    members: List[GroupMember]
    creator_fingerprint: str  # 64 hex chars; the only identity allowed to sign state

    @property
    def peer_id_hex(self) -> str:
        """Virtual conversation ID, matches PeerID(groupID:), used to key
        this group's chat the same way a 1:1 DM's peer_id_hex does."""
        return "group_" + self.group_id.hex()

    @property
    def creator(self) -> Optional[GroupMember]:
        return next((m for m in self.members if m.fingerprint == self.creator_fingerprint), None)

    def is_member(self, fingerprint: str) -> bool:
        return any(m.fingerprint == fingerprint for m in self.members)

    def member_with_signing_key(self, signing_key: bytes) -> Optional[GroupMember]:
        return next((m for m in self.members if m.signing_key == signing_key), None)


class GroupRosterCoding:
    """Deterministic roster blob: count byte, then per member the raw
    32-byte fingerprint, 32-byte signing key, and length-prefixed UTF-8
    nickname. The creator signature covers the SHA-256 of these exact
    bytes, so this encoding must be reproduced identically to verify."""

    @staticmethod
    def encode(members: List[GroupMember]) -> Optional[bytes]:
        if len(members) > MAX_MEMBERS:
            return None
        out = bytearray([len(members)])
        for member in members:
            try:
                fingerprint_bytes = bytes.fromhex(member.fingerprint)
            except ValueError:
                return None
            if len(fingerprint_bytes) != FINGERPRINT_LENGTH or len(member.signing_key) != SIGNING_KEY_LENGTH:
                return None
            out += fingerprint_bytes
            out += member.signing_key
            nickname_bytes = _truncate_nickname(member.nickname)
            out.append(len(nickname_bytes))
            out += nickname_bytes
        return bytes(out)

    @staticmethod
    def decode(data: bytes) -> Optional[List[GroupMember]]:
        if not data or data[0] > MAX_MEMBERS:
            return None
        count = data[0]
        members: List[GroupMember] = []
        offset = 1
        for _ in range(count):
            fixed = FINGERPRINT_LENGTH + SIGNING_KEY_LENGTH + 1
            if len(data) - offset < fixed:
                return None
            fingerprint = data[offset : offset + FINGERPRINT_LENGTH].hex()
            offset += FINGERPRINT_LENGTH
            signing_key = data[offset : offset + SIGNING_KEY_LENGTH]
            offset += SIGNING_KEY_LENGTH
            nick_length = data[offset]
            offset += 1
            if len(data) - offset < nick_length:
                return None
            try:
                nickname = data[offset : offset + nick_length].decode("utf-8")
            except UnicodeDecodeError:
                return None
            offset += nick_length
            members.append(GroupMember(fingerprint=fingerprint, signing_key=signing_key, nickname=nickname))
        if offset != len(data):
            return None
        return members


@dataclass
class GroupStatePayload:
    """Creator-signed group state, the same wire form serves invites
    (NoisePayloadType 0x06) and key updates (0x07), sent as the payload of
    an ordinary NOISE_ENCRYPTED packet (i.e. through an already-established
    Noise session, same as a private text message, see noise_payload.py).
    Receivers verify the creator signature against the creator's signing
    key pinned in the roster, and separately require the authenticated
    Noise session peer to BE that same creator."""

    group_id: bytes
    name: str
    key: bytes  # 32-byte ChaCha20-Poly1305 group key for `epoch`
    epoch: int
    members: List[GroupMember]
    creator_fingerprint: str
    signature: bytes  # 64-byte Ed25519 signature by the creator

    _FIELD_GROUP_ID = 0x01
    _FIELD_NAME = 0x02
    _FIELD_KEY = 0x03
    _FIELD_EPOCH = 0x04
    _FIELD_ROSTER = 0x05
    _FIELD_CREATOR_FINGERPRINT = 0x06
    _FIELD_SIGNATURE = 0x07

    @staticmethod
    def signing_content(group_id: bytes, epoch: int, key: bytes, roster_blob: bytes, name: str) -> bytes:
        return (
            SIGNING_DOMAIN
            + group_id
            + epoch.to_bytes(4, "big")
            + _sha256(key)
            + _sha256(roster_blob)
            + _sha256(name.encode("utf-8"))
        )

    @classmethod
    def make_signed(cls, group: BitchatGroup, key: bytes, signing_key: Ed25519PrivateKey) -> Optional["GroupStatePayload"]:
        roster_blob = GroupRosterCoding.encode(group.members)
        if roster_blob is None:
            return None
        content = cls.signing_content(group.group_id, group.epoch, key, roster_blob, group.name)
        signature = signing_key.sign(content)
        return cls(
            group_id=group.group_id,
            name=group.name,
            key=key,
            epoch=group.epoch,
            members=group.members,
            creator_fingerprint=group.creator_fingerprint,
            signature=signature,
        )

    def encode(self) -> Optional[bytes]:
        roster_blob = GroupRosterCoding.encode(self.members)
        try:
            fingerprint_bytes = bytes.fromhex(self.creator_fingerprint)
        except ValueError:
            return None
        if roster_blob is None or len(fingerprint_bytes) != FINGERPRINT_LENGTH:
            return None
        out = bytearray()
        try:
            _tlv_put(out, self._FIELD_GROUP_ID, self.group_id)
            _tlv_put(out, self._FIELD_NAME, self.name.encode("utf-8"))
            _tlv_put(out, self._FIELD_KEY, self.key)
            _tlv_put(out, self._FIELD_EPOCH, self.epoch.to_bytes(4, "big"))
            _tlv_put(out, self._FIELD_ROSTER, roster_blob)
            _tlv_put(out, self._FIELD_CREATOR_FINGERPRINT, fingerprint_bytes)
            _tlv_put(out, self._FIELD_SIGNATURE, self.signature)
        except GroupTLVError:
            return None
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> Optional["GroupStatePayload"]:
        fields = _tlv_parse(data)
        if fields is None:
            return None
        group_id = name = key = creator_fingerprint = signature = None
        epoch: Optional[int] = None
        members: Optional[List[GroupMember]] = None

        for field_type, value in fields:
            if field_type == cls._FIELD_GROUP_ID and len(value) == GROUP_ID_LENGTH:
                group_id = value
            elif field_type == cls._FIELD_NAME:
                try:
                    name = value.decode("utf-8")
                except UnicodeDecodeError:
                    pass
            elif field_type == cls._FIELD_KEY and len(value) == KEY_LENGTH:
                key = value
            elif field_type == cls._FIELD_EPOCH and len(value) == 4:
                epoch = int.from_bytes(value, "big")
            elif field_type == cls._FIELD_ROSTER:
                members = GroupRosterCoding.decode(value)
            elif field_type == cls._FIELD_CREATOR_FINGERPRINT and len(value) == FINGERPRINT_LENGTH:
                creator_fingerprint = value.hex()
            elif field_type == cls._FIELD_SIGNATURE and len(value) == 64:
                signature = value
            # else: unknown TLV type, forward compatible, ignore

        if not all([group_id, name is not None, key, epoch is not None, members, creator_fingerprint, signature]):
            return None
        return cls(
            group_id=group_id,
            name=name,
            key=key,
            epoch=epoch,
            members=members,
            creator_fingerprint=creator_fingerprint,
            signature=signature,
        )

    def verify_creator_signature(self) -> bool:
        if len(self.members) > MAX_MEMBERS:
            return False
        creator = next((m for m in self.members if m.fingerprint == self.creator_fingerprint), None)
        if creator is None:
            return False
        roster_blob = GroupRosterCoding.encode(self.members)
        if roster_blob is None:
            return False
        content = self.signing_content(self.group_id, self.epoch, self.key, roster_blob, self.name)
        try:
            Ed25519PublicKey.from_public_bytes(creator.signing_key).verify(self.signature, content)
            return True
        except InvalidSignature:
            return False

    @property
    def as_group(self) -> BitchatGroup:
        return BitchatGroup(
            group_id=self.group_id,
            name=self.name,
            epoch=self.epoch,
            members=self.members,
            creator_fingerprint=self.creator_fingerprint,
        )


@dataclass
class GroupMessageEnvelope:
    """Cleartext framing of a group message broadcast (the payload of a
    MessageType.GROUP_MESSAGE / 0x25 packet). Only the group ID, epoch, and
    nonce are visible to relays; everything else, sender, content,
    timestamp, is inside the ChaCha20-Poly1305 ciphertext."""

    group_id: bytes
    epoch: int
    nonce: bytes
    ciphertext: bytes  # ChaCha20-Poly1305 ciphertext || 16-byte tag

    _FIELD_GROUP_ID = 0x01
    _FIELD_EPOCH = 0x02
    _FIELD_NONCE = 0x03
    _FIELD_CIPHERTEXT = 0x04

    def encode(self) -> bytes:
        out = bytearray()
        _tlv_put(out, self._FIELD_GROUP_ID, self.group_id)
        _tlv_put(out, self._FIELD_EPOCH, self.epoch.to_bytes(4, "big"))
        _tlv_put(out, self._FIELD_NONCE, self.nonce)
        _tlv_put(out, self._FIELD_CIPHERTEXT, self.ciphertext)
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> Optional["GroupMessageEnvelope"]:
        fields = _tlv_parse(data)
        if fields is None:
            return None
        group_id = nonce = ciphertext = None
        epoch: Optional[int] = None
        for field_type, value in fields:
            if field_type == cls._FIELD_GROUP_ID and len(value) == GROUP_ID_LENGTH:
                group_id = value
            elif field_type == cls._FIELD_EPOCH and len(value) == 4:
                epoch = int.from_bytes(value, "big")
            elif field_type == cls._FIELD_NONCE and len(value) == NONCE_LENGTH:
                nonce = value
            elif field_type == cls._FIELD_CIPHERTEXT and len(value) > 0:
                ciphertext = value
        if not all([group_id, epoch is not None, nonce, ciphertext]):
            return None
        return cls(group_id=group_id, epoch=epoch, nonce=nonce, ciphertext=ciphertext)


@dataclass
class GroupMessagePlaintext:
    message_id: str
    sender_signing_key: bytes
    sender_nickname: str
    timestamp_ms: int
    content: str


class GroupCryptoError(Exception):
    pass


_INNER_FIELD_MESSAGE_ID = 0x01
_INNER_FIELD_SENDER_SIGNING_KEY = 0x02
_INNER_FIELD_SENDER_NICKNAME = 0x03
_INNER_FIELD_TIMESTAMP = 0x04
_INNER_FIELD_CONTENT = 0x05
_INNER_FIELD_SIGNATURE = 0x06


def message_signing_content(group_id: bytes, epoch: int, message_id: str, timestamp_ms: int, content: str) -> bytes:
    """Bytes the sender signs: domain | groupID | epoch | messageID |
    timestamp | content. Covering the epoch stops a current member from
    re-sealing another member's decrypted inner bytes under a later epoch
    key, the signature would no longer verify."""
    return (
        MESSAGE_SIGNING_DOMAIN
        + group_id
        + epoch.to_bytes(4, "big")
        + message_id.encode("utf-8")
        + timestamp_ms.to_bytes(8, "big")
        + content.encode("utf-8")
    )


def seal_message(
    content: str,
    message_id: str,
    sender_nickname: str,
    sender_signing_key: bytes,
    timestamp_ms: int,
    group_id: bytes,
    epoch: int,
    key: bytes,
    signing_private_key: Ed25519PrivateKey,
) -> bytes:
    """Seals a group message: builds the signed inner TLV and encrypts it
    with the epoch key. The cleartext group ID and epoch are bound into the
    AEAD as associated data so ciphertext cannot be replayed across groups
    or epochs. Returns the encoded 0x25 packet payload (a GroupMessageEnvelope)."""
    signing_content = message_signing_content(group_id, epoch, message_id, timestamp_ms, content)
    signature = signing_private_key.sign(signing_content)

    inner = bytearray()
    _tlv_put(inner, _INNER_FIELD_MESSAGE_ID, message_id.encode("utf-8"))
    _tlv_put(inner, _INNER_FIELD_SENDER_SIGNING_KEY, sender_signing_key)
    _tlv_put(inner, _INNER_FIELD_SENDER_NICKNAME, sender_nickname.encode("utf-8"))
    _tlv_put(inner, _INNER_FIELD_TIMESTAMP, timestamp_ms.to_bytes(8, "big"))
    _tlv_put(inner, _INNER_FIELD_CONTENT, content.encode("utf-8"))
    _tlv_put(inner, _INNER_FIELD_SIGNATURE, signature)

    aad = group_id + epoch.to_bytes(4, "big")
    nonce = _random_nonce()
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, bytes(inner), aad)  # ciphertext || tag, per the cryptography library

    envelope = GroupMessageEnvelope(group_id=group_id, epoch=epoch, nonce=nonce, ciphertext=ciphertext)
    return envelope.encode()


def open_message(envelope: GroupMessageEnvelope, key: bytes) -> GroupMessagePlaintext:
    """Opens a group message envelope with the epoch key: decrypts, parses
    the inner TLV, and verifies the sender's Ed25519 signature. Roster
    membership of the sender is the CALLER's check, this function only
    proves the payload was authored by whoever holds `sender_signing_key`."""
    aad = envelope.group_id + envelope.epoch.to_bytes(4, "big")
    try:
        aead = ChaCha20Poly1305(key)
        inner = aead.decrypt(envelope.nonce, envelope.ciphertext, aad)
    except Exception as exc:  # noqa: BLE001 - the cryptography lib raises InvalidTag etc.
        raise GroupCryptoError("decryption failed") from exc

    fields = _tlv_parse(inner)
    if fields is None:
        raise GroupCryptoError("malformed inner payload")

    message_id = sender_signing_key = sender_nickname = content = signature = None
    timestamp_ms: Optional[int] = None
    for field_type, value in fields:
        if field_type == _INNER_FIELD_MESSAGE_ID:
            try:
                message_id = value.decode("utf-8")
            except UnicodeDecodeError:
                pass
        elif field_type == _INNER_FIELD_SENDER_SIGNING_KEY and len(value) == SIGNING_KEY_LENGTH:
            sender_signing_key = value
        elif field_type == _INNER_FIELD_SENDER_NICKNAME:
            try:
                sender_nickname = value.decode("utf-8")
            except UnicodeDecodeError:
                pass
        elif field_type == _INNER_FIELD_TIMESTAMP and len(value) == 8:
            timestamp_ms = int.from_bytes(value, "big")
        elif field_type == _INNER_FIELD_CONTENT:
            try:
                content = value.decode("utf-8")
            except UnicodeDecodeError:
                pass
        elif field_type == _INNER_FIELD_SIGNATURE and len(value) == 64:
            signature = value

    if not all([message_id, sender_signing_key, sender_nickname is not None, timestamp_ms is not None, content is not None, signature]):
        raise GroupCryptoError("malformed inner payload")

    signing_content = message_signing_content(envelope.group_id, envelope.epoch, message_id, timestamp_ms, content)
    try:
        Ed25519PublicKey.from_public_bytes(sender_signing_key).verify(signature, signing_content)
    except InvalidSignature as exc:
        raise GroupCryptoError("bad sender signature") from exc

    return GroupMessagePlaintext(
        message_id=message_id,
        sender_signing_key=sender_signing_key,
        sender_nickname=sender_nickname,
        timestamp_ms=timestamp_ms,
        content=content,
    )


def _random_nonce() -> bytes:
    return os.urandom(NONCE_LENGTH)


GROUP_PEER_ID_PREFIX = "group_"


def group_id_from_peer_id(peer_id_hex: str) -> Optional[bytes]:
    if not peer_id_hex.startswith(GROUP_PEER_ID_PREFIX):
        return None
    try:
        return bytes.fromhex(peer_id_hex[len(GROUP_PEER_ID_PREFIX) :])
    except ValueError:
        return None


class GroupManager:
    """Local persistent store for groups this device is a member of,
    metadata (roster, name, epoch) and the current symmetric key together,
    matching bitchat-reference's `GroupStore.swift` in shape.

    One real, deliberate deviation worth flagging: iOS keeps the symmetric
    key in the OS Keychain (hardware-backed on real devices) separately
    from the JSON metadata, specifically so the key gets extra at-rest
    protection. Windows has no directly equivalent, zero-extra-dependency
    facility we already use elsewhere in this port, so, matching how
    `identity.json`/`favorites.json`/`nostr_identity.json` already store
    private key material as plain local JSON throughout this project,
    the group key is stored the same way here: on disk, unencrypted beyond
    the filesystem's own permissions. This is a real, weaker-than-iOS
    security posture for this specific piece of state, not an oversight;
    a future improvement would be wiring this through Windows DPAPI."""

    def __init__(self, path: "str | os.PathLike[str]") -> None:
        self._path = path
        self._groups: dict = {}  # group_id.hex() -> BitchatGroup
        self._keys: dict = {}  # group_id.hex() -> current epoch key (bytes)
        self._load()

    @property
    def groups(self) -> List[BitchatGroup]:
        return list(self._groups.values())

    def group(self, group_id: bytes) -> Optional[BitchatGroup]:
        return self._groups.get(group_id.hex())

    def group_for_peer_id(self, peer_id_hex: str) -> Optional[BitchatGroup]:
        group_id = group_id_from_peer_id(peer_id_hex)
        if group_id is None:
            return None
        return self.group(group_id)

    def key(self, group_id: bytes) -> Optional[bytes]:
        return self._keys.get(group_id.hex())

    def create_group(self, name: str, creator: GroupMember) -> Optional[BitchatGroup]:
        group_id = os.urandom(GROUP_ID_LENGTH)
        key = os.urandom(KEY_LENGTH)
        group = BitchatGroup(
            group_id=group_id, name=name, epoch=1, members=[creator], creator_fingerprint=creator.fingerprint
        )
        if not self.upsert(group, key):
            return None
        return group

    def upsert(self, group: BitchatGroup, key: bytes) -> bool:
        if (
            len(group.group_id) != GROUP_ID_LENGTH
            or len(key) != KEY_LENGTH
            or not group.members
            or len(group.members) > MAX_MEMBERS
            or group.creator is None
        ):
            return False
        self._groups[group.group_id.hex()] = group
        self._keys[group.group_id.hex()] = key
        self._save()
        return True

    def update_roster(self, group_id: bytes, members: List[GroupMember]) -> Optional[BitchatGroup]:
        existing = self.group(group_id)
        if (
            existing is None
            or not members
            or len(members) > MAX_MEMBERS
            or not any(m.fingerprint == existing.creator_fingerprint for m in members)
        ):
            return None
        existing.members = members
        self._save()
        return existing

    def rotate_key(self, group_id: bytes, members: List[GroupMember]) -> Optional[Tuple[BitchatGroup, bytes]]:
        existing = self.group(group_id)
        if existing is None:
            return None
        new_key = os.urandom(KEY_LENGTH)
        rotated = BitchatGroup(
            group_id=existing.group_id,
            name=existing.name,
            epoch=existing.epoch + 1,
            members=members,
            creator_fingerprint=existing.creator_fingerprint,
        )
        if not self.upsert(rotated, new_key):
            return None
        return rotated, new_key

    def remove_group(self, group_id: bytes) -> None:
        self._groups.pop(group_id.hex(), None)
        self._keys.pop(group_id.hex(), None)
        self._save()

    def wipe(self) -> None:
        self._groups.clear()
        self._keys.clear()
        self._save()

    # persistence

    def _save(self) -> None:
        path = Path(self._path)
        if not self._groups:
            if path.exists():
                path.unlink()
            return
        data = {
            "groups": [
                {
                    "group_id": group.group_id.hex(),
                    "name": group.name,
                    "epoch": group.epoch,
                    "creator_fingerprint": group.creator_fingerprint,
                    "members": [
                        {"fingerprint": m.fingerprint, "signing_key": m.signing_key.hex(), "nickname": m.nickname}
                        for m in group.members
                    ],
                    "key": self._keys[group.group_id.hex()].hex(),
                }
                for group in self._groups.values()
            ]
        }
        path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        path = Path(self._path)
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return
        for entry in data.get("groups", []):
            try:
                group = BitchatGroup(
                    group_id=bytes.fromhex(entry["group_id"]),
                    name=entry["name"],
                    epoch=entry["epoch"],
                    members=[
                        GroupMember(
                            fingerprint=m["fingerprint"],
                            signing_key=bytes.fromhex(m["signing_key"]),
                            nickname=m["nickname"],
                        )
                        for m in entry["members"]
                    ],
                    creator_fingerprint=entry["creator_fingerprint"],
                )
                key = bytes.fromhex(entry["key"])
            except (KeyError, ValueError):
                continue
            self._groups[group.group_id.hex()] = group
            self._keys[group.group_id.hex()] = key
