"""bitchat1: mesh-packet embedding for Nostr transport.

Ported from bitchat-android's `NostrEmbeddedBitChat.kt`, the actual
message content that gets NIP-17 gift-wrapped isn't the plain DM text
directly, it's a full `BitchatPacket` (NOISE_ENCRYPTED type, base64url
-encoded and prefixed "bitchat1:"), letting a receiving bitchat client
reuse the exact same NoisePayload/PrivateMessagePacket decode path it
already has for real BLE-delivered private messages.

Two non-obvious things confirmed from the reference source, both easy to
get wrong by assuming this path looks like a normal BLE NOISE_ENCRYPTED
packet:

1. The payload is **unencrypted at the Noise layer**, just
   `[NoisePayloadType byte] + TLV`, no ChaCha20-Poly1305 applied. There's no
   live Noise session to encrypt with over this path in the first place;
   the outer NIP-44 gift-wrap (see nostr_event.py) is the only encryption
   this message gets, end to end.
2. `signature = null` and `packet.toBinaryData()` is called with its
   *default* argument (`padding = true`), unlike a real BLE send which uses
   `BLEPacketPaddingPolicy` to decide padding per type, this one path
   always pads, unconditionally, regardless of packet type.
"""
from __future__ import annotations

import base64
from typing import Optional, Tuple

from . import noise_payload, protocol
from .protocol import BitchatPacket, DecodeError, MessageType

BITCHAT1_PREFIX = "bitchat1:"
MESSAGE_TTL_HOPS = 7


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def encode_private_message_for_nostr(
    content: str,
    message_id: str,
    sender_routing_id: bytes,
    recipient_routing_id: bytes,
    timestamp_ms: int,
) -> Optional[str]:
    """Returns the "bitchat1:..." string to use as a gift-wrap rumor's
    content, or None if `content` doesn't fit the TLV framing."""
    inner = noise_payload.PrivateMessagePacket(message_id=message_id, content=content)
    tlv = inner.encode()
    if tlv is None:
        return None
    payload = bytes([noise_payload.PRIVATE_MESSAGE]) + tlv
    packet = BitchatPacket(
        type=MessageType.NOISE_ENCRYPTED,
        sender_id=sender_routing_id,
        recipient_id=recipient_routing_id,
        payload=payload,
        signature=None,
        timestamp_ms=timestamp_ms,
        ttl=MESSAGE_TTL_HOPS,
    )
    data = protocol.encode(packet, padding=True)
    return BITCHAT1_PREFIX + _base64url_encode(data)


def decode_private_message_from_nostr(payload: str) -> Optional[Tuple[bytes, Optional[bytes], str]]:
    """Returns (sender_routing_id, recipient_routing_id, content) or None if
    `payload` isn't a well-formed "bitchat1:" private message."""
    if not payload.startswith(BITCHAT1_PREFIX):
        return None
    encoded = payload[len(BITCHAT1_PREFIX) :]
    try:
        data = _base64url_decode(encoded)
        packet = protocol.decode(data)
    except (ValueError, DecodeError):
        return None
    if packet.type != MessageType.NOISE_ENCRYPTED:
        return None
    decoded = noise_payload.decode_noise_payload(packet.payload)
    if decoded is None:
        return None
    payload_type, data_bytes = decoded
    if payload_type != noise_payload.PRIVATE_MESSAGE:
        return None
    inner = noise_payload.PrivateMessagePacket.decode(data_bytes)
    if inner is None:
        return None
    return packet.sender_id, packet.recipient_id, inner.content
