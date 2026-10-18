"""BitChat BinaryProtocol wire format (v1 only).

Ported from bitchat-reference/localPackages/BitFoundation/Sources/BitFoundation/
BinaryProtocol.swift, BitchatPacket.swift and MessagePadding.swift.

v1 header (14 bytes), all multi-byte fields big-endian:
    version(1) type(1) ttl(1) timestamp(8, ms) flags(1) payloadLen(2)
followed by:
    senderID(8) [recipientID(8) if flags & HAS_RECIPIENT]
    payload(payloadLen) , if HAS_COMPRESSED, first lengthFieldBytes(2) of
                             payloadLen are the *original* (decompressed) size
    [signature(64) if flags & HAS_SIGNATURE]

We only ever emit v1, unsigned (at this layer, mesh.py signs separately),
no-route packets, compressing the payload automatically when beneficial
(see compression.py) same as real clients. Decode accepts v1 with any flag
combination bitchat itself would send (v2/route is explicitly out of
scope, see plan).

Gotcha: bitchat's "isCompressed" payload is Apple's COMPRESSION_ZLIB, which
despite the name is *raw DEFLATE* (RFC 1951, no zlib/gzip wrapper), decode
with zlib.decompressobj(wbits=-15).
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass
from typing import Optional

from . import compression

V1_HEADER_SIZE = 14
SENDER_ID_SIZE = 8
RECIPIENT_ID_SIZE = 8
SIGNATURE_SIZE = 64
LENGTH_FIELD_SIZE_V1 = 2

MAX_FRAMED_BYTES = 1_200_000  # generous sanity ceiling; see FileTransferLimits.swift

PAD_BLOCK_SIZES = (256, 512, 1024, 2048)


class Flags:
    HAS_RECIPIENT = 0x01
    HAS_SIGNATURE = 0x02
    IS_COMPRESSED = 0x04
    HAS_ROUTE = 0x08  # v2 only
    IS_RSR = 0x10


class MessageType:
    ANNOUNCE = 0x01
    MESSAGE = 0x02
    LEAVE = 0x03
    COURIER_ENVELOPE = 0x04
    NOISE_HANDSHAKE = 0x10
    NOISE_ENCRYPTED = 0x11
    FRAGMENT = 0x20
    REQUEST_SYNC = 0x21
    FILE_TRANSFER = 0x22
    BOARD_POST = 0x23
    PREKEY_BUNDLE = 0x24
    GROUP_MESSAGE = 0x25
    PING = 0x26
    PONG = 0x27
    NOSTR_CARRIER = 0x28
    VOICE_FRAME = 0x29
    ANNOUNCE_V2 = 0x2C


class DecodeError(ValueError):
    pass


@dataclass
class BitchatPacket:
    type: int
    sender_id: bytes  # exactly 8 bytes on the wire; shorter is zero-padded on encode
    payload: bytes
    timestamp_ms: int
    ttl: int = 7
    recipient_id: Optional[bytes] = None
    signature: Optional[bytes] = None
    version: int = 1

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError("only protocol v1 is supported")


def _pad8(data: bytes, size: int) -> bytes:
    if len(data) >= size:
        return data[:size]
    return data + b"\x00" * (size - len(data))


def optimal_block_size(data_len: int) -> Optional[int]:
    """Mirrors MessagePadding.optimalBlockSize, accounts for a 16-byte AEAD
    tag headroom even though we never encrypt; returns None if no standard
    block fits (caller should send unpadded)."""
    total = data_len + 16
    for block in PAD_BLOCK_SIZES:
        if total <= block:
            return block
    return None


def pad(data: bytes, target_size: int) -> bytes:
    if len(data) >= target_size:
        return data
    needed = target_size - len(data)
    if not (0 < needed <= 255):
        return data
    return data + bytes([needed]) * needed


def unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if not (0 < pad_len <= len(data)):
        return data
    tail = data[-pad_len:]
    if any(b != pad_len for b in tail):
        return data
    return data[:-pad_len]


def encode(packet: BitchatPacket, padding: bool = True) -> bytes:
    """Encode a v1 packet. Never attaches a route. Compresses the payload
    automatically when compression.should_compress() says it's worth it,
    matching real clients, and done unconditionally (not gated by a
    parameter) because that's what they do: compression happens inside
    encode() itself, before any fragmentation-size decision downstream, so
    a compressible payload (e.g. ordinary English text) often never needs
    fragmenting at all. Confirmed live: a real bitchat client echoed a
    451-byte test message back as a single 383-byte compressed,
    unfragmented packet."""
    payload = packet.payload
    is_compressed = False
    original_size: Optional[int] = None
    if compression.should_compress(payload) and len(payload) <= 0xFFFF:
        candidate = compression.compress(payload)
        if candidate is not None and len(candidate) + LENGTH_FIELD_SIZE_V1 <= 0xFFFF:
            original_size = len(payload)
            payload = candidate
            is_compressed = True

    payload_len = len(payload) + (LENGTH_FIELD_SIZE_V1 if is_compressed else 0)
    if payload_len > 0xFFFF:
        raise ValueError("payload too large for v1 16-bit length field")

    flags = 0
    if packet.recipient_id is not None:
        flags |= Flags.HAS_RECIPIENT
    if packet.signature is not None:
        flags |= Flags.HAS_SIGNATURE
    if is_compressed:
        flags |= Flags.IS_COMPRESSED

    out = bytearray()
    out.append(1)  # version
    out.append(packet.type & 0xFF)
    out.append(packet.ttl & 0xFF)
    out += packet.timestamp_ms.to_bytes(8, "big")
    out.append(flags)
    out += payload_len.to_bytes(2, "big")
    out += _pad8(packet.sender_id, SENDER_ID_SIZE)
    if packet.recipient_id is not None:
        out += _pad8(packet.recipient_id, RECIPIENT_ID_SIZE)
    if is_compressed:
        out += original_size.to_bytes(LENGTH_FIELD_SIZE_V1, "big")
    out += payload
    if packet.signature is not None:
        out += packet.signature[:SIGNATURE_SIZE]

    data = bytes(out)
    if padding:
        target = optimal_block_size(len(data))
        if target is not None:
            data = pad(data, target)
    return data


def decode(data: bytes) -> BitchatPacket:
    """Try decoding as-is; if that fails, strip PKCS#7 padding and retry,
    mirrors BinaryProtocol.decode's fallback order."""
    try:
        return _decode_core(data)
    except DecodeError:
        pass
    unpadded = unpad(data)
    if unpadded == data:
        raise DecodeError("not a valid bitchat packet")
    return _decode_core(unpadded)


def _decode_core(raw: bytes) -> BitchatPacket:
    if len(raw) < V1_HEADER_SIZE + SENDER_ID_SIZE:
        raise DecodeError("too short")

    offset = 0

    def take(n: int) -> bytes:
        nonlocal offset
        if offset + n > len(raw):
            raise DecodeError("truncated")
        chunk = raw[offset : offset + n]
        offset += n
        return chunk

    version = take(1)[0]
    if version != 1:
        raise DecodeError(f"unsupported version {version} (only v1 decoded)")

    pkt_type = take(1)[0]
    ttl = take(1)[0]
    timestamp_ms = int.from_bytes(take(8), "big")
    flags = take(1)[0]
    payload_len = int.from_bytes(take(2), "big")

    has_recipient = bool(flags & Flags.HAS_RECIPIENT)
    has_signature = bool(flags & Flags.HAS_SIGNATURE)
    is_compressed = bool(flags & Flags.IS_COMPRESSED)

    if payload_len > MAX_FRAMED_BYTES:
        raise DecodeError("payload length exceeds sanity ceiling")

    sender_id = take(SENDER_ID_SIZE)

    recipient_id = take(RECIPIENT_ID_SIZE) if has_recipient else None

    if is_compressed:
        if payload_len < LENGTH_FIELD_SIZE_V1:
            raise DecodeError("compressed payload too short for size preamble")
        original_size = int.from_bytes(take(LENGTH_FIELD_SIZE_V1), "big")
        if not (0 <= original_size <= MAX_FRAMED_BYTES):
            raise DecodeError("bad decompressed size")
        compressed_size = payload_len - LENGTH_FIELD_SIZE_V1
        if compressed_size <= 0:
            raise DecodeError("empty compressed body")
        compressed = take(compressed_size)
        if compressed_size and original_size / compressed_size > 50_000.0:
            raise DecodeError("suspicious compression ratio")
        try:
            payload = zlib.decompressobj(wbits=-15).decompress(compressed, original_size)
        except zlib.error as exc:
            raise DecodeError(f"raw-deflate decompress failed: {exc}") from exc
        if len(payload) != original_size:
            raise DecodeError("decompressed size mismatch")
    else:
        payload = take(payload_len)

    signature = take(SIGNATURE_SIZE) if has_signature else None

    return BitchatPacket(
        type=pkt_type,
        sender_id=sender_id,
        payload=payload,
        timestamp_ms=timestamp_ms,
        ttl=ttl,
        recipient_id=recipient_id,
        signature=signature,
        version=1,
    )
