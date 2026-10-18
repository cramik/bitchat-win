"""Mesh relay engine: dedup + TTL-decrementing rebroadcast + public chat state.

BLE-agnostic on purpose (see plan), ble_central.py feeds raw notification
bytes in via `handle_incoming` and this module calls back out through
`relay_fn` to push relayed bytes to every other connected link. This mirrors
bitchat's own mesh behavior: every peer is a relay, not just a leaf.
"""
from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
import uuid
from collections import OrderedDict
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import channel_prefix, fragment, groups, noise_payload, nostr_bridge, nostr_event, protocol
from .announce import AnnouncementPacket
from .favorites import FavoritesStore, encode_favorite_control_message, parse_favorite_control_message
from .file_packet import MAX_PAYLOAD_BYTES, BitchatFilePacket
from .identity import Identity, derive_fingerprint_hex
from .noise_session import NoiseSession, NoiseSessionError
from .nostr_identity import NostrIdentity, npub_to_hex
from .nostr_relay import NostrRelayPool
from .protocol import BitchatPacket, DecodeError, MessageType

logger = logging.getLogger("bitchat.mesh")

DEFAULT_TTL = 7
_SEEN_CACHE_MAX = 4096

RelayFn = Callable[[bytes, Optional[str]], Awaitable[None]]
PublicMessageFn = Callable[[str, str, str], None]  # (peer_id_hex, nickname, content)
# (peer_id_hex, nickname, file_name, mime_type, content)
FileReceivedFn = Callable[[str, str, Optional[str], Optional[str], bytes], None]
PrivateMessageFn = Callable[[str, str, str], None]  # (peer_id_hex, nickname, content)
PeerEventFn = Callable[[str, str], None]  # (peer_id_hex, nickname) for join/leave
# (peer_id_hex, nickname, is_favorite, is_mutual)
FavoriteNoticeFn = Callable[[str, str, bool, bool], None]
# (group_peer_id_hex, group_name, sender_nickname, content)
GroupMessageFn = Callable[[str, str, str, str], None]
# (group_peer_id_hex, group_name, notice_text)
GroupNoticeFn = Callable[[str, str, str], None]
# (peer_id_hex, nickname, channel, content), see channel_prefix.py
ChannelMessageFn = Callable[[str, str, str, str], None]


class MeshEngine:
    def __init__(
        self,
        identity: Identity,
        nickname: str,
        on_public_message: PublicMessageFn,
        on_peer_joined: Optional[PeerEventFn] = None,
        on_peer_left: Optional[PeerEventFn] = None,
        on_private_message: Optional[PrivateMessageFn] = None,
        on_file_received: Optional[FileReceivedFn] = None,
        on_private_file_received: Optional[FileReceivedFn] = None,
        favorites: Optional[FavoritesStore] = None,
        on_favorite_notice: Optional[FavoriteNoticeFn] = None,
        our_npub: Optional[str] = None,
        nostr_identity: Optional[NostrIdentity] = None,
        nostr_relay_pool: Optional[NostrRelayPool] = None,
        group_manager: Optional[groups.GroupManager] = None,
        on_group_message: Optional[GroupMessageFn] = None,
        on_group_notice: Optional[GroupNoticeFn] = None,
        on_channel_message: Optional[ChannelMessageFn] = None,
    ) -> None:
        self.identity = identity
        self.nickname = nickname
        self.on_public_message = on_public_message
        self.on_peer_joined = on_peer_joined
        self.on_peer_left = on_peer_left
        self.on_private_message = on_private_message
        self.on_file_received = on_file_received
        self.on_private_file_received = on_private_file_received
        # None disables the [FAVORITED]/[UNFAVORITED] control-message
        # handling entirely, favorite notifications just fall through to
        # on_private_message like any other DM (see favorites.py).
        self.favorites = favorites
        self.on_favorite_notice = on_favorite_notice
        # Nostr fallback: reach a mutual favorite over the internet (via
        # gift-wrapped relay events) when they haven't been seen on the
        # mesh this session. Both nostr_identity and nostr_relay_pool must
        # be provided for the fallback to actually fire on send; on
        # receive, handle_incoming_nostr_event() no-ops without an identity
        # to unwrap gift wraps with. our_npub defaults to nostr_identity's
        # own npub when given (so outgoing favorite notifications carry it
        # automatically), but can be set independently, e.g. tests that
        # only want the favorites side of this without real Nostr crypto.
        self.our_npub = our_npub or (nostr_identity.npub if nostr_identity is not None else None)
        self.nostr_identity = nostr_identity
        self.nostr_relay_pool = nostr_relay_pool

        # Private groups (see groups.py), entirely mesh-local, no Nostr
        # involvement. None disables the feature: incoming group traffic is
        # just silently ignored (matches the optional-feature pattern used
        # for favorites/files elsewhere in this class).
        self.group_manager = group_manager
        self.on_group_message = on_group_message
        self.on_group_notice = on_group_notice

        # "#channel"-tagged public messages (see channel_prefix.py), a
        # fork-only, plain-text-prefix convention, not a real wire feature.
        # None just means the caller never receives the channel/content
        # split and channel-tagged text falls back to on_public_message
        # with the prefix left visible, same as a client with no idea what
        # this convention is would see it.
        self.on_channel_message = on_channel_message

        self.peers: Dict[str, str] = {}  # peer_id_hex -> nickname
        # peer_id_hex -> (noise_public_key, signing_public_key), populated
        # only when the peer's ANNOUNCE signature actually verified against
        # its own claimed signing key (see _dispatch's ANNOUNCE branch).
        self.peer_identities: Dict[str, Tuple[bytes, bytes]] = {}
        self._seen: "OrderedDict[bytes, None]" = OrderedDict()
        self._fragments = fragment.FragmentAssembler()
        # Multiple transports (central connections, peripheral GATT server)
        # can each register a sink; every relay/broadcast fans out to all of them.
        self.relay_sinks: List[RelayFn] = []

        # Noise sessions, one per peer we've ever handshaken with or are
        # handshaking with. Messages typed before a session is established
        # queue here and flush once the handshake completes.
        self._noise_sessions: Dict[str, NoiseSession] = {}
        self._pending_dm_content: Dict[str, List[str]] = {}

    # outgoing packet builders

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def _sign(self, packet: BitchatPacket) -> BitchatPacket:
        """Ed25519-sign the packet the way real bitchat clients do (see
        NoiseEncryptionService.signPacket / BitchatPacket.toBinaryDataForSigning):
        sign over BinaryProtocol.encode() of the packet with ttl forced to 0
        and signature stripped, ttl is excluded because it mutates on every
        relay hop, and, non-obviously, that intermediate "signable" form
        IS padded (encode()'s padding=True default), even though the final
        signed wire packet is sent unpadded. Get this padding mismatch wrong
        and every packet you send is silently invalid: it decodes fine on
        the receiving end, but signature verification fails and the real
        app drops it without ever surfacing an error, which is exactly what
        happened here before this was fixed, confirmed by reproducing
        this construction byte-for-byte against a real captured announce
        packet's own signature and signing key."""
        signable = dataclasses.replace(packet, ttl=0, signature=None)
        signable_bytes = protocol.encode(signable, padding=True)
        signature = self.identity.signing_private.sign(signable_bytes)
        return dataclasses.replace(packet, signature=signature)

    @staticmethod
    def _verify_signature(packet: BitchatPacket, signing_public_key: bytes) -> bool:
        """The receive-side counterpart of _sign(): true only if `packet`
        was actually signed by `signing_public_key`. Used specifically to
        trust the noise/signing public keys embedded in an ANNOUNCE before
        using them for anything security-relevant (e.g. pinning a group
        member's identity), this port otherwise doesn't verify incoming
        signatures at all (harmless for chat display, since a forged
        announce just shows a wrong nickname; not harmless for who's
        allowed into an E2EE group's roster)."""
        if packet.signature is None:
            return False
        signable = dataclasses.replace(packet, ttl=0, signature=None)
        signable_bytes = protocol.encode(signable, padding=True)
        try:
            Ed25519PublicKey.from_public_bytes(signing_public_key).verify(packet.signature, signable_bytes)
            return True
        except (InvalidSignature, ValueError):
            return False

    def _finalize_for_wire(self, packet: BitchatPacket) -> List[bytes]:
        """Signs and encodes `packet`, fragmenting into MessageType.FRAGMENT
        wrapper packets (see fragment.py) if the encoded form is bigger than
        a single BLE write, mirrors BLEOutboundFragmentPlanner. Small
        packets (the overwhelming majority: announce, leave, ordinary chat
        messages) come back as a 1-element list.

        Every outgoing packet gets signed, including NOISE_HANDSHAKE and
        NOISE_ENCRYPTED, confirmed from bitchat-android's
        BluetoothMeshService, where every single send path (handshake
        init/response, private messages, read receipts, private media) runs
        through signPacketBeforeBroadcast before going out. We'd previously
        assumed those types went out unsigned since real clients'
        SecurityManager doesn't *require* a signature to accept them (the
        handshake's own mutual auth / AEAD tag already cover authenticity),
        but "not required to verify" isn't the same as "never sent", and
        since we don't verify incoming signatures ourselves either way,
        matching what real senders actually emit is a pure fidelity win.

        Raises ValueError if the packet needs more fragments than a real
        receiver will reassemble (see fragment.MAX_FRAGMENTS), callers that
        can produce arbitrarily large payloads (file transfer) should catch
        this and report it as "too large to send," not let it propagate.

        Padding: bitchat-android's `BLEPacketPaddingPolicy.shouldPadForBLE`
        pads NOISE_HANDSHAKE/NOISE_ENCRYPTED specifically when written as a
        single BLE packet, everything else (announce/message/leave/file
        transfer, and *every* FRAGMENT wrapper regardless of what type it's
        carrying) goes out unpadded. The fragmentation decision itself is
        always made on the unpadded encoding ("fragment the unpadded frame,"
        matching FragmentManager.createFragments), padding only gets
        applied to the one-and-only write when a Noise packet turns out
        small enough not to need fragmenting at all. We didn't apply this
        distinction before; harmless in practice since our own decode()
        already tries unpadded-then-strip-padding regardless of type, so
        nothing we've sent or received was actually misread, but it's a
        real wire-fidelity gap worth closing, found while matching exactly
        what NostrEmbeddedBitChat.encodePMForNostr encodes (that path always
        pads, a separate and simpler rule, see nostr_bridge.py)."""
        signed = self._sign(packet)
        unpadded = protocol.encode(signed, padding=False)
        if len(unpadded) <= fragment.FRAGMENT_SIZE_THRESHOLD:
            if packet.type in (MessageType.NOISE_HANDSHAKE, MessageType.NOISE_ENCRYPTED):
                return [protocol.encode(signed, padding=True)]
            return [unpadded]
        return fragment.fragment_packet(signed, unpadded)

    def _get_or_create_session(self, peer_id_hex: str, is_initiator: bool) -> NoiseSession:
        session = self._noise_sessions.get(peer_id_hex)
        if session is None:
            session = NoiseSession(self.identity, peer_id_hex, is_initiator=is_initiator)
            self._noise_sessions[peer_id_hex] = session
        return session

    async def send_private_message(self, peer_id_hex: str, content: str) -> None:
        """Send a private message to `peer_id_hex`. Mesh (Noise-encrypted
        over BLE, handshaking first if needed) is always the default,
        fire-and-forget, same as before Nostr fallback existed, since this
        port has no live connect/disconnect tracking at the mesh-engine
        layer to know for certain a peer is unreachable. Nostr (gift-wrapped,
        via nostr_bridge's "bitchat1:" mesh-packet embedding) is used instead
        only when we have positive evidence mesh delivery is unlikely to
        work: the peer is a mutual favorite with a known npub, AND we
        haven't seen them on the mesh this session (no announce, no
        in-flight/established Noise session), mirroring
        bitchat-android's MessageRouter preferring mesh whenever a live
        session exists and only reaching for Nostr otherwise."""
        npub = self._nostr_fallback_npub(peer_id_hex)
        seen_on_mesh = peer_id_hex in self.peers or peer_id_hex in self._noise_sessions
        if npub is not None and not seen_on_mesh:
            await self._send_private_message_via_nostr(peer_id_hex, content, npub)
            return
        await self._send_private_message_via_mesh(peer_id_hex, content)

    def _nostr_fallback_npub(self, peer_id_hex: str) -> Optional[str]:
        if self.nostr_identity is None or self.nostr_relay_pool is None or self.favorites is None:
            return None
        record = self.favorites.get(peer_id_hex)
        if record is None or not record.is_mutual or record.nostr_npub is None:
            return None
        return record.nostr_npub

    def _nostr_fallback_npub(self, peer_id_hex: str) -> Optional[str]:
        if self.nostr_identity is None or self.nostr_relay_pool is None or self.favorites is None:
            return None
        record = self.favorites.get(peer_id_hex)
        if record is None or not record.is_mutual or record.nostr_npub is None:
            return None
        return record.nostr_npub

    async def _send_private_message_via_mesh(self, peer_id_hex: str, content: str) -> None:
        session = self._noise_sessions.get(peer_id_hex)
        if session is not None and session.established:
            await self._send_encrypted_content(session, peer_id_hex, content)
            return

        self._pending_dm_content.setdefault(peer_id_hex, []).append(content)
        if session is not None:
            return  # handshake already in flight; message is queued above

        session = self._get_or_create_session(peer_id_hex, is_initiator=True)
        msg1 = session.start_handshake()
        packet = BitchatPacket(
            type=MessageType.NOISE_HANDSHAKE,
            sender_id=self.identity.routing_id,
            recipient_id=bytes.fromhex(peer_id_hex),
            payload=msg1,
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        await self.send_packets(self._finalize_for_wire(packet))

    async def _send_private_message_via_nostr(self, peer_id_hex: str, content: str, npub: str) -> None:
        bitchat1_content = nostr_bridge.encode_private_message_for_nostr(
            content,
            message_id=str(uuid.uuid4()),
            sender_routing_id=self.identity.routing_id,
            recipient_routing_id=bytes.fromhex(peer_id_hex),
            timestamp_ms=self._now_ms(),
        )
        if bitchat1_content is None:
            logger.warning("private message to %s too long for TLV framing, dropped", peer_id_hex)
            return
        recipient_pubkey_hex = npub_to_hex(npub)
        gift_wrap = nostr_event.create_private_message_gift_wrap(
            bitchat1_content, recipient_pubkey_hex, self.nostr_identity
        )
        await self.nostr_relay_pool.publish(gift_wrap)

    async def handle_incoming_nostr_event(self, event: nostr_event.NostrEvent) -> None:
        """Feed a gift-wrap event received from NostrRelayPool in here,
        unwraps it, decodes the embedded mesh packet, and dispatches through
        the same favorite-control-message/on_private_message path a
        BLE-delivered private message would use (see _dispatch_private_text)."""
        if self.nostr_identity is None:
            return
        result = nostr_event.decrypt_private_message_gift_wrap(event, self.nostr_identity)
        if result is None:
            return
        bitchat1_content, _sender_pubkey_hex, _created_at = result
        decoded = nostr_bridge.decode_private_message_from_nostr(bitchat1_content)
        if decoded is None:
            return
        sender_routing_id, recipient_routing_id, content = decoded
        if recipient_routing_id is not None and recipient_routing_id != self.identity.routing_id:
            return  # addressed to someone else, no relay concept over Nostr, just drop it
        self._dispatch_private_text(sender_routing_id.hex(), content)

    async def send_favorite_notification(self, peer_id_hex: str, is_favorite: bool) -> None:
        """Tells `peer_id_hex` we favorited (or unfavorited) them, just an
        ordinary private message whose content is the
        "[FAVORITED]:<npub>"/"[UNFAVORITED]:" control string (see
        favorites.py), sent over send_private_message's normal mesh/Nostr
        routing (handshaking over mesh first if needed). Uses self.our_npub,
        which may be None if a Nostr identity hasn't been set up yet,
        still a valid message, just without a way for the peer to reach us
        over Nostr."""
        content = encode_favorite_control_message(is_favorite, self.our_npub)
        await self.send_private_message(peer_id_hex, content)

    # private groups (see groups.py)

    async def create_group(self, name: str) -> Optional["groups.BitchatGroup"]:
        """Creates a new group locally with us as sole member/creator,
        purely local, no network activity. Members join via
        invite_to_group(). Returns None if groups are disabled."""
        if self.group_manager is None:
            return None
        creator = groups.GroupMember(
            fingerprint=self.identity.fingerprint_hex,
            signing_key=self.identity.signing_public_bytes,
            nickname=self.nickname,
        )
        return self.group_manager.create_group(name, creator)

    def _peer_group_identity(self, peer_id_hex: str) -> Optional[Tuple[str, bytes]]:
        """(fingerprint_hex, signing_key) for a peer whose ANNOUNCE
        signature we've verified, or None if we don't have one yet (they
        need to have announced, i.e. shown up in /peers, at least once)."""
        identity = self.peer_identities.get(peer_id_hex)
        if identity is None:
            return None
        noise_pubkey, signing_pubkey = identity
        return derive_fingerprint_hex(noise_pubkey), signing_pubkey

    def _connected_peer_id_for_fingerprint(self, fingerprint: str) -> Optional[str]:
        for peer_id_hex, (noise_pubkey, _signing_pubkey) in self.peer_identities.items():
            if derive_fingerprint_hex(noise_pubkey) == fingerprint:
                return peer_id_hex
        return None

    def _signed_group_state_payload(self, group: "groups.BitchatGroup", key: bytes) -> Optional[bytes]:
        state = groups.GroupStatePayload.make_signed(group, key, self.identity.signing_private)
        if state is None:
            return None
        return state.encode()

    async def _send_group_state(self, peer_id_hex: str, payload: bytes, is_invite: bool) -> None:
        session = self._noise_sessions.get(peer_id_hex)
        if session is None or not session.established:
            return
        payload_type = noise_payload.GROUP_INVITE if is_invite else noise_payload.GROUP_KEY_UPDATE
        plaintext = noise_payload.encode_noise_payload(payload_type, payload)
        ciphertext = session.encrypt(plaintext)
        packet = BitchatPacket(
            type=MessageType.NOISE_ENCRYPTED,
            sender_id=self.identity.routing_id,
            recipient_id=bytes.fromhex(peer_id_hex),
            payload=ciphertext,
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        await self.send_packets(self._finalize_for_wire(packet))

    async def _distribute_group_state(self, payload: bytes, group: "groups.BitchatGroup", exclude_fingerprints: set) -> None:
        """Sends `payload` to every connected roster member except us and
        `exclude_fingerprints`. Offline members simply don't get it,
        they catch up the next time the creator sends them state, matching
        the reference's own documented v1 limitation."""
        my_fingerprint = self.identity.fingerprint_hex
        for member in group.members:
            if member.fingerprint == my_fingerprint or member.fingerprint in exclude_fingerprints:
                continue
            peer_id_hex = self._connected_peer_id_for_fingerprint(member.fingerprint)
            if peer_id_hex is None:
                continue
            await self._send_group_state(peer_id_hex, payload, is_invite=False)

    async def invite_to_group(self, group_id: bytes, peer_id_hex: str) -> Optional[str]:
        """Creator-only: invites `peer_id_hex` into the group, rotating the
        key (epoch+1) as part of every roster change, including adds, not
        just removals, matching ChatGroupCoordinator.inviteMember exactly.
        Distributes the same rotated state to every other already-connected
        member too. Returns None on success, or a short reason on failure."""
        if self.group_manager is None:
            return "groups are disabled"
        group = self.group_manager.group(group_id)
        if group is None:
            return "unknown group"
        if group.creator_fingerprint != self.identity.fingerprint_hex:
            return "only the group creator can invite members"
        session = self._noise_sessions.get(peer_id_hex)
        if session is None or not session.established:
            return "no established Noise session with that peer, /dm them first"
        identity = self._peer_group_identity(peer_id_hex)
        if identity is None:
            return "peer's verified identity is unknown, they need to have announced (see /peers)"
        fingerprint, signing_key = identity
        if group.is_member(fingerprint):
            return "already a member"
        if len(group.members) >= groups.MAX_MEMBERS:
            return f"group is at the {groups.MAX_MEMBERS}-member cap"

        new_member = groups.GroupMember(
            fingerprint=fingerprint, signing_key=signing_key, nickname=self.peers.get(peer_id_hex, peer_id_hex)
        )
        members = group.members + [new_member]
        rotated_and_key = self.group_manager.rotate_key(group_id, members)
        if rotated_and_key is None:
            return "failed to rotate group key"
        rotated, key = rotated_and_key
        payload = self._signed_group_state_payload(rotated, key)
        if payload is None:
            return "failed to sign group state"

        await self._send_group_state(peer_id_hex, payload, is_invite=True)
        await self._distribute_group_state(payload, rotated, exclude_fingerprints={fingerprint})
        return None

    async def remove_from_group(self, group_id: bytes, peer_id_hex_or_nickname: str) -> Optional[str]:
        """Creator-only: rotates the group key (epoch+1) excluding the
        target member, distributes the new state to everyone remaining,
        and separately notifies the removed member with a throwaway
        all-zero key (never the real rotated key) so their own missing-self
        check fires and they deactivate the group locally."""
        if self.group_manager is None:
            return "groups are disabled"
        group = self.group_manager.group(group_id)
        if group is None:
            return "unknown group"
        if group.creator_fingerprint != self.identity.fingerprint_hex:
            return "only the group creator can remove members"

        fp_from_peer = self._peer_group_identity(peer_id_hex_or_nickname)
        target = None
        if fp_from_peer is not None:
            target = next((m for m in group.members if m.fingerprint == fp_from_peer[0]), None)
        if target is None:
            target = next(
                (m for m in group.members if m.nickname.lower() == peer_id_hex_or_nickname.lower()), None
            )
        if target is None:
            return "member not found in this group"
        if target.fingerprint == group.creator_fingerprint:
            return "cannot remove the creator"

        remaining = [m for m in group.members if m.fingerprint != target.fingerprint]
        rotated_and_key = self.group_manager.rotate_key(group_id, remaining)
        if rotated_and_key is None:
            return "failed to rotate group key"
        rotated, key = rotated_and_key
        payload = self._signed_group_state_payload(rotated, key)
        if payload is None:
            return "failed to sign group state"

        await self._distribute_group_state(payload, rotated, exclude_fingerprints=set())

        removed_peer_id = self._connected_peer_id_for_fingerprint(target.fingerprint)
        if removed_peer_id is not None:
            throwaway_key = bytes(groups.KEY_LENGTH)
            removal_payload = self._signed_group_state_payload(rotated, throwaway_key)
            if removal_payload is not None:
                await self._send_group_state(removed_peer_id, removal_payload, is_invite=False)
        return None

    def leave_group(self, group_id: bytes) -> Optional[str]:
        if self.group_manager is None:
            return "groups are disabled"
        if self.group_manager.group(group_id) is None:
            return "unknown group"
        self.group_manager.remove_group(group_id)
        return None

    def list_groups(self) -> List["groups.BitchatGroup"]:
        if self.group_manager is None:
            return []
        return self.group_manager.groups

    def _finalize_group_message_for_wire(self, packet: BitchatPacket) -> List[bytes]:
        """Like _finalize_for_wire but WITHOUT signing, GROUP_MESSAGE
        (0x25) packets are deliberately unsigned on the wire; see groups.py's
        module docstring for why (the inner Ed25519 signature is what
        actually authenticates the sender, and, unlike an outer signature
        tied to a since-expired announce, stays verifiable indefinitely,
        so a store-and-forward/gossip-sync copy still checks out)."""
        unpadded = protocol.encode(packet, padding=False)
        if len(unpadded) <= fragment.FRAGMENT_SIZE_THRESHOLD:
            return [unpadded]
        return fragment.fragment_packet(packet, unpadded)

    async def send_group_message(self, group_id: bytes, content: str) -> Optional[str]:
        """Fire-and-flood broadcast, no per-member acks, matches
        ChatGroupCoordinator.sendGroupMessage exactly."""
        if self.group_manager is None:
            return "groups are disabled"
        group = self.group_manager.group(group_id)
        key = self.group_manager.key(group_id)
        if group is None or key is None:
            return "unknown group"

        payload = groups.seal_message(
            content=content,
            message_id=str(uuid.uuid4()),
            sender_nickname=self.nickname,
            sender_signing_key=self.identity.signing_public_bytes,
            timestamp_ms=self._now_ms(),
            group_id=group.group_id,
            epoch=group.epoch,
            key=key,
            signing_private_key=self.identity.signing_private,
        )
        packet = BitchatPacket(
            type=MessageType.GROUP_MESSAGE,
            sender_id=self.identity.routing_id,
            payload=payload,
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        await self.send_packets(self._finalize_group_message_for_wire(packet))
        return None

    async def _handle_group_message(self, packet: BitchatPacket) -> None:
        """Decrypt-verify path for an incoming 0x25 broadcast. Drops
        silently for unknown groups (non-members relay but never read,
        the outer _relay() flood already happened regardless of this),
        wrong epochs, bad sender signatures, and senders missing from the
        pinned roster, matches handleGroupMessagePayload exactly."""
        if self.group_manager is None:
            return
        envelope = groups.GroupMessageEnvelope.decode(packet.payload)
        if envelope is None:
            return
        group = self.group_manager.group(envelope.group_id)
        if group is None:
            return
        if envelope.epoch != group.epoch:
            logger.debug("dropping group message with epoch %d (current %d)", envelope.epoch, group.epoch)
            return
        key = self.group_manager.key(envelope.group_id)
        if key is None:
            return

        try:
            plaintext = groups.open_message(envelope, key)
        except groups.GroupCryptoError as exc:
            logger.debug("failed to open group message: %s", exc)
            return

        member = group.member_with_signing_key(plaintext.sender_signing_key)
        if member is None:
            logger.debug("dropping group message from non-roster sender")
            return
        if plaintext.sender_signing_key == self.identity.signing_public_bytes:
            return  # our own broadcast, echoed back via relay
        if self.on_group_message is not None:
            sender_name = member.nickname or plaintext.sender_nickname
            self.on_group_message(group.peer_id_hex, group.name, sender_name, plaintext.content)

    async def _handle_group_state(self, sender_peer_hex: str, payload: bytes, is_invite: bool) -> None:
        """Accepts creator-signed group state (invite or key update)
        arriving over an established Noise session, matches
        applyGroupState exactly, including requiring the Noise-authenticated
        sender to BE the creator, never regressing the epoch, and treating
        a roster that no longer includes us as a removal notice."""
        if self.group_manager is None:
            return
        state = groups.GroupStatePayload.decode(payload)
        if state is None:
            logger.warning("malformed group state payload from %s", sender_peer_hex[:8])
            return

        session = self._noise_sessions.get(sender_peer_hex)
        if session is None or session.remote_static_public_key is None:
            return
        sender_fingerprint = derive_fingerprint_hex(session.remote_static_public_key)
        if sender_fingerprint != state.creator_fingerprint:
            logger.warning("dropping group state from non-creator %s", sender_peer_hex[:8])
            return
        if not state.verify_creator_signature():
            logger.warning("dropping group state with invalid creator signature")
            return

        my_fingerprint = self.identity.fingerprint_hex
        existing = self.group_manager.group(state.group_id)

        if not any(m.fingerprint == my_fingerprint for m in state.members):
            if existing is not None:
                self.group_manager.remove_group(existing.group_id)
                if self.on_group_notice is not None:
                    self.on_group_notice(existing.peer_id_hex, existing.name, f"you were removed from {existing.name}")
            return

        if existing is not None and state.epoch < existing.epoch:
            logger.warning("dropping stale group state (epoch %d < %d)", state.epoch, existing.epoch)
            return

        is_new_membership = existing is None
        if not self.group_manager.upsert(state.as_group, state.key):
            logger.error("failed to store group state for %s", state.name)
            return

        if is_new_membership and self.on_group_notice is not None:
            inviter = next((m.nickname for m in state.members if m.fingerprint == state.creator_fingerprint), None)
            inviter = inviter or self.peers.get(sender_peer_hex, "?")
            self.on_group_notice(state.as_group.peer_id_hex, state.name, f"added to {state.name} by {inviter}")

    async def _send_encrypted_content(self, session: NoiseSession, peer_id_hex: str, content: str) -> None:
        inner = noise_payload.PrivateMessagePacket(message_id=str(uuid.uuid4()), content=content)
        inner_bytes = inner.encode()
        if inner_bytes is None:
            logger.warning("private message to %s too long for TLV framing, dropped", peer_id_hex)
            return
        plaintext = noise_payload.encode_noise_payload(noise_payload.PRIVATE_MESSAGE, inner_bytes)
        ciphertext = session.encrypt(plaintext)
        packet = BitchatPacket(
            type=MessageType.NOISE_ENCRYPTED,
            sender_id=self.identity.routing_id,
            recipient_id=bytes.fromhex(peer_id_hex),
            payload=ciphertext,
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        await self.send_packets(self._finalize_for_wire(packet))

    async def send_private_file(
        self,
        peer_id_hex: str,
        content: bytes,
        file_name: Optional[str] = None,
        mime_type: Optional[str] = None,
    ) -> Optional[str]:
        """Send a file/image privately (Noise-encrypted) to `peer_id_hex`.
        Returns None on success, or a short human-readable reason it
        couldn't be sent.

        Unlike send_private_message, a file is never queued-and-retried
        across a handshake, mirrors bitchat-android's sendFilePrivate/
        PrivateMediaTransfer.prepare(), which on NeedsHandshake only
        *initiates* the handshake and leaves retrying the send to the
        caller, rather than holding arbitrary-sized binary content in memory
        waiting for a handshake that might never complete.

        Wire format: the BitchatFilePacket TLV is wrapped in a NoisePayload
        of type FILE_TRANSFER (0x20), encrypted, and sent as a NOISE_ENCRYPTED
        packet, same as a private text message, just a different inner
        payload type and (usually) needing fragmentation, since real photos
        are almost always bigger than one BLE write."""
        session = self._noise_sessions.get(peer_id_hex)
        if session is None or not session.established:
            if session is None:
                session = self._get_or_create_session(peer_id_hex, is_initiator=True)
                msg1 = session.start_handshake()
                packet = BitchatPacket(
                    type=MessageType.NOISE_HANDSHAKE,
                    sender_id=self.identity.routing_id,
                    recipient_id=bytes.fromhex(peer_id_hex),
                    payload=msg1,
                    timestamp_ms=self._now_ms(),
                    ttl=DEFAULT_TTL,
                )
                await self.send_packets(self._finalize_for_wire(packet))
            return "no Noise session yet with this peer, handshake initiated, retry once it completes"

        file_packet = BitchatFilePacket(content=content, file_name=file_name, mime_type=mime_type)
        encoded_file_packet = file_packet.encode()
        if encoded_file_packet is None:
            return f"file is too large to encode (over {MAX_PAYLOAD_BYTES} bytes)"

        plaintext = noise_payload.encode_noise_payload(noise_payload.FILE_TRANSFER, encoded_file_packet)
        ciphertext = session.encrypt(plaintext)
        packet = BitchatPacket(
            type=MessageType.NOISE_ENCRYPTED,
            sender_id=self.identity.routing_id,
            recipient_id=bytes.fromhex(peer_id_hex),
            payload=ciphertext,
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        try:
            packets = self._finalize_for_wire(packet)
        except ValueError:
            return "file is too large to fit within the mesh's 256-fragment delivery limit"
        await self.send_packets(packets)
        return None

    async def _flush_pending_dm(self, peer_id_hex: str, session: NoiseSession) -> None:
        pending = self._pending_dm_content.pop(peer_id_hex, [])
        for content in pending:
            await self._send_encrypted_content(session, peer_id_hex, content)

    def build_announce_packet(self) -> List[bytes]:
        ann = AnnouncementPacket(
            nickname=self.nickname,
            noise_public_key=self.identity.noise_public_bytes,
            signing_public_key=self.identity.signing_public_bytes,
        )
        packet = BitchatPacket(
            type=MessageType.ANNOUNCE,
            sender_id=self.identity.routing_id,
            payload=ann.encode(),
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        return self._finalize_for_wire(packet)

    def build_leave_packet(self) -> List[bytes]:
        packet = BitchatPacket(
            type=MessageType.LEAVE,
            sender_id=self.identity.routing_id,
            payload=b"",
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        return self._finalize_for_wire(packet)

    def build_public_message_packet(self, content: str, channel: Optional[str] = None) -> List[bytes]:
        # Public message payload is just the raw UTF-8 content, no
        # structure at all. Confirmed against the reference source
        # (BLEService.sendMessage: `payload: Data(content.utf8)`) after real
        # phones displayed garbled text from an earlier, over-structured
        # payload format that was never actually used on this wire path.
        # Sender nickname and timestamp come from the packet's own senderID
        # (resolved via the peer registry from their announce) and header
        # timestamp field, not from anything inside the payload.
        #
        # `channel` (if given) is folded into that same plain text via
        # channel_prefix.encode(), "#general: hello", rather than any
        # binary field, so this stays byte-for-byte what a real phone
        # expects on this wire path; see channel_prefix.py for why.
        wire_content = channel_prefix.encode(content, channel)
        packet = BitchatPacket(
            type=MessageType.MESSAGE,
            sender_id=self.identity.routing_id,
            payload=wire_content.encode("utf-8"),
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        return self._finalize_for_wire(packet)

    def build_file_transfer_packet(
        self, content: bytes, file_name: Optional[str] = None, mime_type: Optional[str] = None
    ) -> Optional[List[bytes]]:
        """Broadcast a file (image, etc.) publicly, same signing and
        fragmentation path as a public message (`FILE_TRANSFER` is in the
        same must-be-signed set as `MESSAGE` per the reference's
        SecurityManager), just with a richer TLV payload instead of raw
        UTF-8. Returns None if the content is too large to encode
        (file_packet.MAX_PAYLOAD_BYTES, 1 MiB) or, more restrictively, too
        large to actually *deliver*: real receivers hard-cap reassembly at
        fragment.MAX_FRAGMENTS (256) chunks, which, after header/TLV
        overhead, works out to a real-world ceiling well under 1 MiB (see
        fragment.py). Both cases return None rather than raising, since a
        user picking an oversized file is an expected, not exceptional,
        outcome."""
        file_packet = BitchatFilePacket(content=content, file_name=file_name, mime_type=mime_type)
        encoded_file_packet = file_packet.encode()
        if encoded_file_packet is None:
            return None
        packet = BitchatPacket(
            type=MessageType.FILE_TRANSFER,
            sender_id=self.identity.routing_id,
            payload=encoded_file_packet,
            timestamp_ms=self._now_ms(),
            ttl=DEFAULT_TTL,
        )
        try:
            return self._finalize_for_wire(packet)
        except ValueError:
            return None

    # incoming handling

    def _dedup_key(self, packet: BitchatPacket) -> bytes:
        if packet.type == MessageType.FRAGMENT:
            # All fragments of one message share sender+timestamp+type, so
            # the generic key below would collide every fragment after the
            # first together as "duplicates" of one another. Key on the
            # fragment's own id+index instead (first 10 payload bytes),
            # matches the real client's fragments-bypass-the-deduplicator
            # behavior, just via a fragment-granular key instead of no
            # dedup at all.
            if len(packet.payload) >= 10:
                return packet.sender_id + packet.payload[:10] + bytes([packet.type])
        return packet.sender_id + packet.timestamp_ms.to_bytes(8, "big") + bytes([packet.type])

    def _seen_before(self, key: bytes) -> bool:
        if key in self._seen:
            self._seen.move_to_end(key)
            return True
        self._seen[key] = None
        if len(self._seen) > _SEEN_CACHE_MAX:
            self._seen.popitem(last=False)
        return False

    async def handle_incoming(self, raw: bytes, link_id: str) -> None:
        logger.debug("raw packet from %s (%d bytes): %s", link_id, len(raw), raw.hex())
        try:
            packet = protocol.decode(raw)
        except DecodeError as exc:
            logger.debug("dropping undecodable packet from %s: %s", link_id, exc)
            return

        if packet.sender_id == self.identity.routing_id:
            return  # our own packet echoed back

        if self._seen_before(self._dedup_key(packet)):
            return

        sender_peer_hex = packet.sender_id.hex()

        if packet.type == MessageType.FRAGMENT:
            result = self._fragments.add(packet)
            if result is not None:
                original_type, reassembled = result
                try:
                    inner = protocol.decode(reassembled)
                except DecodeError as exc:
                    logger.debug(
                        "failed to decode reassembled packet (type=0x%02x): %s", original_type, exc
                    )
                else:
                    # Dispatch only, do NOT relay `inner` as a fresh whole
                    # packet. Each fragment already went through the normal
                    # relay path individually below (that's what
                    # `_relay(packet, ...)` at the bottom of this function
                    # does, for the *outer* fragment packet); relaying the
                    # reassembled packet too would send the whole message a
                    # second time.
                    await self._dispatch(inner, sender_peer_hex)
        else:
            await self._dispatch(packet, sender_peer_hex)

        await self._relay(packet, exclude_link_id=link_id)

    async def _dispatch(self, packet: BitchatPacket, sender_peer_hex: str) -> None:
        if packet.type == MessageType.ANNOUNCE:
            ann = AnnouncementPacket.decode(packet.payload)
            if ann is not None:
                is_new = sender_peer_hex not in self.peers
                self.peers[sender_peer_hex] = ann.nickname
                # Only trust the embedded noise/signing public keys for
                # anything security-relevant (currently: group membership)
                # if the announce packet's own signature actually verifies
                # against the claimed signing key, otherwise a forged
                # announce could pin an attacker's key into a group roster.
                if self._verify_signature(packet, ann.signing_public_key):
                    self.peer_identities[sender_peer_hex] = (ann.noise_public_key, ann.signing_public_key)
                else:
                    self.peer_identities.pop(sender_peer_hex, None)
                if is_new and self.on_peer_joined:
                    self.on_peer_joined(sender_peer_hex, ann.nickname)
        elif packet.type == MessageType.LEAVE:
            nickname = self.peers.pop(sender_peer_hex, None)
            if nickname and self.on_peer_left:
                self.on_peer_left(sender_peer_hex, nickname)
        elif packet.type == MessageType.MESSAGE:
            try:
                content = packet.payload.decode("utf-8")
            except UnicodeDecodeError:
                content = None
            if content:
                nickname = self.peers.get(sender_peer_hex, f"anon{sender_peer_hex[:4]}")
                channel, unprefixed_content = channel_prefix.decode(content)
                if channel is not None and self.on_channel_message is not None:
                    self.on_channel_message(sender_peer_hex, nickname, channel, unprefixed_content)
                else:
                    # No channel support wired up, or this wasn't a
                    # channel-tagged message, same behavior a real phone
                    # (or any client that doesn't know this convention)
                    # would show: plain text, prefix visible if present.
                    self.on_public_message(sender_peer_hex, nickname, content)
        elif packet.type == MessageType.FILE_TRANSFER:
            file_packet = BitchatFilePacket.decode(packet.payload)
            if file_packet is not None and self.on_file_received is not None:
                nickname = self.peers.get(sender_peer_hex, f"anon{sender_peer_hex[:4]}")
                self.on_file_received(
                    sender_peer_hex,
                    nickname,
                    file_packet.file_name,
                    file_packet.mime_type,
                    file_packet.content,
                )
        elif packet.type == MessageType.NOISE_HANDSHAKE:
            await self._handle_noise_handshake(packet, sender_peer_hex)
        elif packet.type == MessageType.NOISE_ENCRYPTED:
            await self._handle_noise_encrypted(packet, sender_peer_hex)
        elif packet.type == MessageType.GROUP_MESSAGE:
            await self._handle_group_message(packet)
        else:
            logger.debug("ignoring unsupported message type 0x%02x", packet.type)

    async def _handle_noise_handshake(self, packet: BitchatPacket, sender_peer_hex: str) -> None:
        if packet.recipient_id != self.identity.routing_id:
            return  # not addressed to us, nothing to process locally; _relay() still floods it onward
        session = self._noise_sessions.get(sender_peer_hex)
        if session is None:
            session = self._get_or_create_session(sender_peer_hex, is_initiator=False)
        try:
            response = session.process_handshake_message(packet.payload)
        except NoiseSessionError as exc:
            logger.warning("Noise handshake with %s failed: %s", sender_peer_hex, exc)
            self._noise_sessions.pop(sender_peer_hex, None)
            return

        if response is not None:
            response_packet = BitchatPacket(
                type=MessageType.NOISE_HANDSHAKE,
                sender_id=self.identity.routing_id,
                recipient_id=packet.sender_id,
                payload=response,
                timestamp_ms=self._now_ms(),
                ttl=DEFAULT_TTL,
            )
            await self.send_packets(self._finalize_for_wire(response_packet))

        if session.established:
            logger.info("Noise session established with %s", sender_peer_hex)
            await self._flush_pending_dm(sender_peer_hex, session)

    def _dispatch_private_text(self, sender_peer_hex: str, content: str) -> None:
        """Shared by both private-message transports (BLE Noise and Nostr
        gift-wrap): intercepts [FAVORITED]/[UNFAVORITED] control messages
        (see favorites.py) before they ever reach on_private_message,
        updating the favorites store and firing on_favorite_notice instead
        of surfacing them as a normal DM."""
        nickname = self.peers.get(sender_peer_hex, f"anon{sender_peer_hex[:4]}")
        control = parse_favorite_control_message(content) if self.favorites is not None else None
        if control is not None:
            is_favorite, npub = control
            record = self.favorites.record_their_notification(sender_peer_hex, is_favorite, npub, nickname)
            if self.on_favorite_notice is not None:
                self.on_favorite_notice(sender_peer_hex, nickname, is_favorite, record.is_mutual)
        elif self.on_private_message is not None:
            self.on_private_message(sender_peer_hex, nickname, content)

    async def _handle_noise_encrypted(self, packet: BitchatPacket, sender_peer_hex: str) -> None:
        if packet.recipient_id != self.identity.routing_id:
            return  # not addressed to us, nothing to process locally; _relay() still floods it onward
        session = self._noise_sessions.get(sender_peer_hex)
        if session is None or not session.established:
            logger.debug("dropping Noise-encrypted packet from %s: no established session", sender_peer_hex)
            return
        try:
            plaintext = session.decrypt(packet.payload)
        except NoiseSessionError as exc:
            logger.warning("failed to decrypt private message from %s: %s", sender_peer_hex, exc)
            return

        decoded = noise_payload.decode_noise_payload(plaintext)
        if decoded is None:
            return
        payload_type, data = decoded
        if payload_type == noise_payload.PRIVATE_MESSAGE:
            inner = noise_payload.PrivateMessagePacket.decode(data)
            if inner is None:
                return
            self._dispatch_private_text(sender_peer_hex, inner.content)
        elif payload_type == noise_payload.FILE_TRANSFER:
            inner_file = BitchatFilePacket.decode(data)
            if inner_file is not None and self.on_private_file_received is not None:
                nickname = self.peers.get(sender_peer_hex, f"anon{sender_peer_hex[:4]}")
                self.on_private_file_received(
                    sender_peer_hex,
                    nickname,
                    inner_file.file_name,
                    inner_file.mime_type,
                    inner_file.content,
                )
        elif payload_type == noise_payload.GROUP_INVITE:
            await self._handle_group_state(sender_peer_hex, data, is_invite=True)
        elif payload_type == noise_payload.GROUP_KEY_UPDATE:
            await self._handle_group_state(sender_peer_hex, data, is_invite=False)

    async def _relay(self, packet: BitchatPacket, exclude_link_id: str) -> None:
        """Flood-relay `packet` to every other connected link, TTL permitting.

        Directed (recipient_id-set) packets ARE relayed here too, same as
        broadcast, confirmed from bitchat-android's PacketRelayManager:
        there's no separate "addressed relay" path, a node just floods
        everything and each hop independently decides whether the packet
        was meant for it. The only thing that stops propagation is the
        packet actually being addressed to *us* specifically (we already
        consumed it via _dispatch by the time _relay runs), anything
        addressed to someone else, or genuinely broadcast (recipient_id is
        None, or the explicit all-FF broadcast placeholder some real
        clients send instead of omitting the field), keeps flooding
        outward. This is what makes multi-hop delivery of DMs/private files
        work at all: we have no source routing, so "relay everything except
        what's ours" is the entire routing algorithm."""
        if packet.recipient_id is not None and packet.recipient_id == self.identity.routing_id:
            return  # addressed to us, already consumed, stop propagating it further
        if packet.ttl == 0:
            return
        if not self.relay_sinks:
            return
        # Only ttl changes, the original signature (if any) still covers
        # everything else and stays valid, since signing excludes ttl (see
        # _sign). We're relaying, not authoring, so we can't and shouldn't
        # re-sign with our own key.
        relayed = dataclasses.replace(packet, ttl=packet.ttl - 1)
        raw_out = protocol.encode(relayed, padding=False)
        for sink in self.relay_sinks:
            await sink(raw_out, exclude_link_id)

    async def broadcast_to_all(self, raw: bytes) -> None:
        """Send a packet we authored ourselves (not a relay) to every transport."""
        for sink in self.relay_sinks:
            await sink(raw, None)

    async def send_packets(self, packets: List[bytes]) -> None:
        """Send the (possibly multi-fragment) output of a build_*_packet()
        call, pacing writes between fragments so we don't blast a BLE link
        faster than it can drain (see fragment.FRAGMENT_SPACING_SECONDS)."""
        for index, raw in enumerate(packets):
            if index > 0:
                await asyncio.sleep(fragment.FRAGMENT_SPACING_SECONDS)
            await self.broadcast_to_all(raw)
