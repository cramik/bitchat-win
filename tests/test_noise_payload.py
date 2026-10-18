from bitchat import noise_payload
from bitchat.noise_payload import PrivateMessagePacket


def test_noise_payload_round_trip():
    encoded = noise_payload.encode_noise_payload(noise_payload.PRIVATE_MESSAGE, b"hello")
    decoded = noise_payload.decode_noise_payload(encoded)
    assert decoded == (noise_payload.PRIVATE_MESSAGE, b"hello")


def test_noise_payload_decode_empty_returns_none():
    assert noise_payload.decode_noise_payload(b"") is None


def test_private_message_packet_round_trip():
    pkt = PrivateMessagePacket(message_id="abc-123", content="hello there")
    encoded = pkt.encode()
    assert encoded is not None
    decoded = PrivateMessagePacket.decode(encoded)
    assert decoded == pkt


def test_private_message_packet_rejects_oversized_field():
    pkt = PrivateMessagePacket(message_id="x" * 300, content="hi")
    assert pkt.encode() is None


def test_private_message_packet_decode_incomplete_returns_none():
    assert PrivateMessagePacket.decode(b"\x00\x03ab") is None  # length says 3, only 2 bytes present
