"""Optional payload compression for outgoing packets.

Ported from CompressionUtil.swift (mirrored by bitchat-android's own
CompressionUtil.kt). Real clients decide independently, per outgoing
packet, whether compressing is worth it, and critically, compression is
attempted *before* the fragmentation-size check (BinaryProtocol.encode()
runs first, fragmentation only chops what encode() produces). Ordinary
English chat text compresses well enough with this heuristic that it
usually never needs fragmenting at all, which is why implementing this
(rather than chasing the fragmentation path further) is the practical fix
for long-message delivery, confirmed live: a real bitchat client echoed
our own 451-byte test message back as a single 383-byte *compressed*,
*unfragmented* packet.

Gotcha carried over from protocol.py: this is raw DEFLATE (RFC 1951, no
zlib/gzip wrapper), matching Apple's COMPRESSION_ZLIB naming despite what
it sounds like.

No cross-platform canonicalization is needed to interoperate: a receiver
never re-compresses to verify a signature (see bitchat-android's
WirePayload docstring), it reuses the sender's exact compressed bytes.
This is purely a local, deterministic size-shrinking step.
"""
from __future__ import annotations

import zlib
from typing import Optional

COMPRESSION_THRESHOLD_BYTES = 100


def should_compress(payload: bytes) -> bool:
    """Matches CompressionUtil.shouldCompress: too-small payloads aren't
    worth the framing overhead, and a payload sampled as already
    high-entropy (e.g. already compressed, or encrypted) won't shrink."""
    if len(payload) < COMPRESSION_THRESHOLD_BYTES:
        return False
    sample = payload[: min(len(payload), 256)]
    unique_ratio = len(set(sample)) / len(sample)
    return unique_ratio < 0.9


def compress(payload: bytes) -> Optional[bytes]:
    """Returns compressed bytes, or None if compression didn't actually
    shrink the payload (matches CompressionUtil.compress's own bail-out,
    callers should fall back to sending uncompressed, not force a larger
    "compressed" payload onto the wire)."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    compressed = compressor.compress(payload) + compressor.flush()
    if not compressed or len(compressed) >= len(payload):
        return None
    return compressed
