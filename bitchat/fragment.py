"""Packet fragmentation for payloads too large for a single BLE write.

Ported from bitchat-reference/bitchat/Services/BLE/BLEOutboundFragmentPlanner.swift
(send side) and BLEFragmentHandler.swift / BLEFragmentAssemblyBuffer.swift
(receive side).

A fragment is an ordinary MessageType.FRAGMENT (0x20) BitchatPacket whose
payload is:
    fragmentID(8) index(2, BE) total(2, BE) originalType(1) chunk(variable)

The *encoded, already-signed* original packet's raw bytes are what gets
chopped into chunks, not just its payload, so reassembling the chunks
and running them back through BinaryProtocol.decode() recovers the original
packet (signature included) exactly.

Deliberately not ported: the real assembly buffer's stalled-transfer
REQUEST_SYNC recovery and eviction-under-memory-pressure policy (out of
scope for this port; see plan). Basic sanity bounds are kept so a malicious
or corrupt fragment can't grow an assembly buffer unbounded.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from . import protocol
from .protocol import BitchatPacket, MessageType

FRAGMENT_ID_LENGTH = 8
FRAGMENT_HEADER_LENGTH = FRAGMENT_ID_LENGTH + 2 + 2 + 1  # id + index + total + originalType

# AppConstants.Fragmentation.FRAGMENT_SIZE_THRESHOLD, iOS/Android decide
# whether to fragment at all by comparing the *unpadded* encoded packet
# against a flat 512, regardless of broadcast vs directed. This is a
# separate question from the per-fragment chunk size below (which is
# smaller than 512 to leave room for the fragment wrapper's own overhead).
FRAGMENT_SIZE_THRESHOLD = 512

# iOS TransportConfig.bleDefaultFragmentSize, ceiling on the per-fragment
# chunk size regardless of computed overhead.
_MAX_FRAGMENT_SIZE = 469

# bitchat-android's FragmentManager.createFragments() computes its outbound
# chunk size dynamically per packet:
#   512 - (headerSize=13 + senderSize=8 + recipientSize + routeSize
#          + fragmentHeaderSize=13 + paddingBuffer=16)
# capped at _MAX_FRAGMENT_SIZE. recipientSize is 8 only when the *original*
# packet carries a recipientID (directed/private), the fragment wrapper
# packet copies that recipientID too, so a directed packet's fragments must
# be built 8 bytes smaller (454) than a broadcast packet's (462) to end up
# the same total wire size. We don't support source routes, so routeSize is
# always 0 here. Getting this wrong for the broadcast case (guessing 469,
# the iOS constant, instead of computing 462) previously caused a real
# bitchat Android receiver to reject our reassembled+signed message with
# "Signature INVALID" despite our own byte-for-byte reconstruction verifying
# correctly, the mismatch was in what the far side's BLE/GATT write path
# does with a write a few bytes bigger than its own sender ever produces.
# Matching their number exactly removes that variable; the same reasoning
# is why the directed case needs its own smaller number, not reuse of 462.
_V1_HEADER_SIZE = 13
_SENDER_ID_SIZE = 8
_RECIPIENT_ID_SIZE = 8
_PADDING_BUFFER = 16

# Broadcast chunk size, also used as this module's public "typical chunk
# size" for callers that just need an estimate (BLE write-size comments etc).
FRAGMENT_CHUNK_SIZE = min(
    512 - (_V1_HEADER_SIZE + _SENDER_ID_SIZE + 0 + FRAGMENT_HEADER_LENGTH + _PADDING_BUFFER),
    _MAX_FRAGMENT_SIZE,
)


def _chunk_size_for(packet: BitchatPacket) -> int:
    recipient_size = _RECIPIENT_ID_SIZE if packet.recipient_id is not None else 0
    overhead = _V1_HEADER_SIZE + _SENDER_ID_SIZE + recipient_size + FRAGMENT_HEADER_LENGTH + _PADDING_BUFFER
    return min(512 - overhead, _MAX_FRAGMENT_SIZE)


# TransportConfig.bleFragmentSpacingMs, pacing between broadcast fragment
# writes so we don't blast a BLE link faster than it can drain.
FRAGMENT_SPACING_SECONDS = 0.030

# bitchat-android's MAX_FRAGMENTS_PER_ID (AppConstants.Fragmentation),
# confirmed (via FragmentManager.handleFragment and
# FragmentingPacketSender.packetsForTransport) to be a *universal* cap, both
# send and receive, for every fragmented packet type, not, as we first
# assumed, something specific to private-media-v1 transfers. A real receiver
# rejects any fragment set claiming a total above this ("Rejecting fragment
# with excessive total count") regardless of what type the reassembled
# packet is, so anything we build that would need more than this many
# 462-byte chunks (~118 KB) is simply undeliverable and must be rejected
# before sending rather than silently dropped on the other end.
MAX_FRAGMENTS = 256

# Sanity ceiling for a reassembled packet. With MAX_FRAGMENTS=256 and
# 462-byte chunks, a legitimate sender can never actually produce more than
# ~118 KB of reassembled bytes, this is defense-in-depth against a bogus
# `total` claim from a malicious/corrupt sender, not a real limit we expect
# to hit.
MAX_REASSEMBLED_BYTES = 200_000

# How many concurrent partial reassemblies to track at once, oldest evicted
# first, bounds memory from stalled or bogus fragment streams.
MAX_IN_FLIGHT_ASSEMBLIES = 32


def fragment_packet(packet: BitchatPacket, encoded: bytes, fragment_id: Optional[bytes] = None) -> List[bytes]:
    """Split an already-encoded, already-signed packet into one or more
    wire-ready MessageType.FRAGMENT packets. Returns encoded bytes for each
    fragment, ready to write directly, fragments are never padded (same
    rule as everything else on this wire, see protocol.py)."""
    if fragment_id is None:
        fragment_id = os.urandom(FRAGMENT_ID_LENGTH)

    chunk_size = _chunk_size_for(packet)
    chunks = [encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)]
    total = len(chunks)
    if total == 0:
        return []
    if total > MAX_FRAGMENTS:
        raise ValueError(f"packet needs {total} fragments, exceeding the {MAX_FRAGMENTS}-fragment wire limit")

    out = []
    for index, chunk in enumerate(chunks):
        payload = (
            fragment_id
            + index.to_bytes(2, "big")
            + total.to_bytes(2, "big")
            + bytes([packet.type])
            + chunk
        )
        fragment = BitchatPacket(
            type=MessageType.FRAGMENT,
            sender_id=packet.sender_id,
            recipient_id=packet.recipient_id,
            timestamp_ms=packet.timestamp_ms,
            payload=payload,
            signature=None,
            ttl=packet.ttl,
        )
        out.append(protocol.encode(fragment, padding=False))
    return out


def parse_fragment_header(packet: BitchatPacket) -> Optional[Tuple[bytes, int, int, int, bytes]]:
    """Returns (fragment_id, index, total, original_type, chunk) or None if
    `packet` isn't a well-formed fragment payload."""
    if len(packet.payload) < FRAGMENT_HEADER_LENGTH:
        return None
    fragment_id = packet.payload[:FRAGMENT_ID_LENGTH]
    offset = FRAGMENT_ID_LENGTH
    index = int.from_bytes(packet.payload[offset : offset + 2], "big")
    offset += 2
    total = int.from_bytes(packet.payload[offset : offset + 2], "big")
    offset += 2
    original_type = packet.payload[offset]
    offset += 1
    chunk = packet.payload[offset:]

    if not (0 < total <= MAX_FRAGMENTS and 0 <= index < total):
        return None
    return fragment_id, index, total, original_type, chunk


class FragmentAssembler:
    """Reassembles MessageType.FRAGMENT packets back into their original
    encoded packet bytes. One instance per MeshEngine (i.e. per local
    identity), tracking in-flight reassemblies across all senders."""

    def __init__(self) -> None:
        self._buffers: Dict[Tuple[bytes, bytes], Dict[int, bytes]] = {}
        self._totals: Dict[Tuple[bytes, bytes], int] = {}

    def add(self, packet: BitchatPacket) -> Optional[Tuple[int, bytes]]:
        """Feed in one received FRAGMENT packet. Returns
        (original_type, reassembled_bytes) once every fragment of that
        stream has arrived, else None."""
        parsed = parse_fragment_header(packet)
        if parsed is None:
            return None
        fragment_id, index, total, original_type, chunk = parsed

        key = (packet.sender_id, fragment_id)
        buf = self._buffers.get(key)
        if buf is None:
            if len(self._buffers) >= MAX_IN_FLIGHT_ASSEMBLIES:
                oldest_key = next(iter(self._buffers))
                del self._buffers[oldest_key]
                del self._totals[oldest_key]
            buf = {}
            self._buffers[key] = buf
            self._totals[key] = total

        projected_size = sum(len(v) for v in buf.values()) + len(chunk)
        if projected_size > MAX_REASSEMBLED_BYTES:
            del self._buffers[key]
            del self._totals[key]
            return None

        buf[index] = chunk
        if len(buf) < total:
            return None

        reassembled = b"".join(buf[i] for i in range(total))
        del self._buffers[key]
        del self._totals[key]
        return original_type, reassembled
