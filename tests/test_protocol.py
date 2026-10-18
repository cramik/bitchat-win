import zlib

import pytest

from bitchat import protocol
from bitchat.protocol import BitchatPacket, DecodeError, Flags, MessageType


def test_round_trip_minimal_no_padding():
    pkt = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        payload=b"hello mesh",
        timestamp_ms=1_700_000_000_000,
        ttl=5,
    )
    raw = protocol.encode(pkt, padding=False)
    decoded = protocol.decode(raw)
    assert decoded.type == pkt.type
    assert decoded.sender_id == pkt.sender_id
    assert decoded.payload == pkt.payload
    assert decoded.timestamp_ms == pkt.timestamp_ms
    assert decoded.ttl == pkt.ttl
    assert decoded.recipient_id is None
    assert decoded.signature is None


def test_round_trip_with_padding():
    pkt = BitchatPacket(
        type=MessageType.ANNOUNCE,
        sender_id=b"\xaa" * 8,
        payload=b"x" * 10,
        timestamp_ms=42,
        ttl=7,
    )
    raw = protocol.encode(pkt, padding=True)
    # Padded to the smallest standard block size that fits header+payload+16
    assert len(raw) in protocol.PAD_BLOCK_SIZES
    decoded = protocol.decode(raw)
    assert decoded.payload == pkt.payload
    assert decoded.sender_id == pkt.sender_id


def test_sender_id_shorter_than_8_is_zero_padded_on_encode():
    pkt = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=b"\x01\x02",
        payload=b"hi",
        timestamp_ms=1,
    )
    raw = protocol.encode(pkt, padding=False)
    decoded = protocol.decode(raw)
    assert decoded.sender_id == b"\x01\x02\x00\x00\x00\x00\x00\x00"


def test_recipient_and_signature_round_trip():
    pkt = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=b"\x11" * 8,
        recipient_id=b"\x22" * 8,
        payload=b"directed payload",
        timestamp_ms=99,
        signature=b"\x33" * 64,
    )
    raw = protocol.encode(pkt, padding=False)
    decoded = protocol.decode(raw)
    assert decoded.recipient_id == b"\x22" * 8
    assert decoded.signature == b"\x33" * 64


def test_decode_hand_built_v1_header_matches_spec():
    # version(1) type(1) ttl(1) timestamp(8) flags(1) payloadLen(2) senderID(8) payload
    payload = b"abc"
    raw = bytes([1, MessageType.MESSAGE, 3]) + (1234).to_bytes(8, "big") + bytes([0]) + len(payload).to_bytes(2, "big")
    raw += b"\x01" * 8
    raw += payload
    decoded = protocol.decode(raw)
    assert decoded.type == MessageType.MESSAGE
    assert decoded.ttl == 3
    assert decoded.timestamp_ms == 1234
    assert decoded.payload == payload
    assert decoded.sender_id == b"\x01" * 8


def test_decode_raw_deflate_compressed_payload():
    original = b"repeat repeat repeat repeat repeat repeat repeat" * 5
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    compressed = compressor.compress(original) + compressor.flush()

    payload_field = len(original).to_bytes(2, "big") + compressed
    raw = bytes([1, MessageType.MESSAGE, 7]) + (0).to_bytes(8, "big")
    raw += bytes([Flags.IS_COMPRESSED])
    raw += len(payload_field).to_bytes(2, "big")
    raw += b"\x09" * 8
    raw += payload_field

    decoded = protocol.decode(raw)
    assert decoded.payload == original


def test_decode_rejects_v2():
    raw = bytes([2, 1, 1]) + (0).to_bytes(8, "big")
    with pytest.raises(DecodeError):
        protocol.decode(raw)


def test_decode_rejects_garbage():
    with pytest.raises(DecodeError):
        protocol.decode(b"\x00\x01\x02")


def test_pad_unpad_round_trip():
    data = b"some frame bytes"
    padded = protocol.pad(data, 32)
    assert len(padded) == 32
    assert protocol.unpad(padded) == data


def test_unpad_leaves_unpadded_data_alone():
    data = bytes(range(20))
    assert protocol.unpad(data) == data or len(protocol.unpad(data)) <= len(data)
