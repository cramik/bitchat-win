from bitchat.announce import AnnouncementPacket


def test_round_trip():
    ann = AnnouncementPacket(
        nickname="derek",
        noise_public_key=b"\x01" * 32,
        signing_public_key=b"\x02" * 32,
    )
    encoded = ann.encode()
    decoded = AnnouncementPacket.decode(encoded)
    assert decoded is not None
    assert decoded.nickname == "derek"
    assert decoded.noise_public_key == b"\x01" * 32
    assert decoded.signing_public_key == b"\x02" * 32


def test_decode_ignores_unknown_trailing_tlv():
    ann = AnnouncementPacket(
        nickname="x",
        noise_public_key=b"\xaa" * 32,
        signing_public_key=b"\xbb" * 32,
    )
    encoded = bytearray(ann.encode())
    # Append an unknown TLV (type 0x99, len 2, "hi") -- must be ignored, not fatal.
    encoded += bytes([0x99, 2]) + b"hi"
    decoded = AnnouncementPacket.decode(bytes(encoded))
    assert decoded is not None
    assert decoded.nickname == "x"


def test_decode_missing_required_field_returns_none():
    # Only a nickname TLV, no keys.
    payload = bytes([0x01, 1]) + b"a"
    assert AnnouncementPacket.decode(payload) is None


def test_decode_truncated_returns_none():
    assert AnnouncementPacket.decode(bytes([0x01, 200]) + b"short") is None
