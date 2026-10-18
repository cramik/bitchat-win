import os

from bitchat.file_packet import MAX_PAYLOAD_BYTES, BitchatFilePacket


def test_round_trip_with_all_fields():
    pkt = BitchatFilePacket(content=b"fake jpeg bytes", file_name="photo.jpg", mime_type="image/jpeg")
    encoded = pkt.encode()
    assert encoded is not None
    decoded = BitchatFilePacket.decode(encoded)
    assert decoded is not None
    assert decoded.content == b"fake jpeg bytes"
    assert decoded.file_name == "photo.jpg"
    assert decoded.mime_type == "image/jpeg"
    assert decoded.file_size == len(b"fake jpeg bytes")


def test_round_trip_content_only():
    pkt = BitchatFilePacket(content=b"just bytes, no metadata")
    encoded = pkt.encode()
    decoded = BitchatFilePacket.decode(encoded)
    assert decoded is not None
    assert decoded.content == b"just bytes, no metadata"
    assert decoded.file_name is None
    assert decoded.mime_type is None


def test_round_trip_real_sized_binary_content():
    content = os.urandom(50_000)  # incompressible, like a real image
    pkt = BitchatFilePacket(content=content, file_name="img_test.jpg", mime_type="image/jpeg")
    encoded = pkt.encode()
    assert encoded is not None
    decoded = BitchatFilePacket.decode(encoded)
    assert decoded is not None
    assert decoded.content == content


def test_encode_rejects_oversized_content():
    pkt = BitchatFilePacket(content=b"x" * (MAX_PAYLOAD_BYTES + 1))
    assert pkt.encode() is None


def test_decode_rejects_empty_content():
    assert BitchatFilePacket.decode(b"") is None


def test_decode_ignores_unknown_tlv_type():
    pkt = BitchatFilePacket(content=b"hello")
    encoded = bytearray(pkt.encode())
    # Append an unknown TLV (type 0x99, 2-byte length=2, value="hi")
    encoded += bytes([0x99]) + (2).to_bytes(2, "big") + b"hi"
    decoded = BitchatFilePacket.decode(bytes(encoded))
    assert decoded is not None
    assert decoded.content == b"hello"


def test_decode_truncated_data_returns_none():
    pkt = BitchatFilePacket(content=b"hello world")
    encoded = pkt.encode()
    assert BitchatFilePacket.decode(encoded[:-3]) is None
