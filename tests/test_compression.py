import os

from bitchat import compression, protocol
from bitchat.protocol import BitchatPacket, Flags, MessageType


def test_should_compress_false_for_small_payload():
    assert compression.should_compress(b"short") is False


def test_should_compress_true_for_long_low_entropy_text():
    payload = ("the quick brown fox jumps over the lazy dog " * 5).encode("utf-8")
    assert len(payload) >= compression.COMPRESSION_THRESHOLD_BYTES
    assert compression.should_compress(payload) is True


def test_compress_returns_none_when_not_beneficial():
    # should_compress is a cheap approximate heuristic (byte-collision math
    # means truly random data still often passes it -- 256 uniform draws
    # over 256 values average ~63% unique, comfortably under the 90%
    # cutoff), so the real "don't bother" guarantee lives in compress()
    # itself, which bails out unless deflate actually shrinks the input.
    assert compression.compress(os.urandom(500)) is None


def test_compress_round_trips_via_protocol_decode():
    text = ("This is a long English sentence, repeated. " * 10).encode("utf-8")
    packet = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=b"\x01" * 8,
        payload=text,
        timestamp_ms=1,
        ttl=7,
    )
    raw = protocol.encode(packet, padding=False)
    decoded = protocol.decode(raw)
    assert decoded.payload == text


def test_encode_sets_compressed_flag_when_beneficial():
    text = ("English text compresses well when repeated. " * 10).encode("utf-8")
    packet = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=b"\x02" * 8,
        payload=text,
        timestamp_ms=1,
        ttl=7,
    )
    raw = protocol.encode(packet, padding=False)
    # Byte 11 is the flags field in the v1 header (see protocol.py docstring).
    assert raw[11] & Flags.IS_COMPRESSED != 0
    assert len(raw) < len(text)  # compression actually shrank the wire size


def test_encode_leaves_incompressible_payload_uncompressed():
    payload = os.urandom(500)
    packet = BitchatPacket(
        type=MessageType.MESSAGE,
        sender_id=b"\x03" * 8,
        payload=payload,
        timestamp_ms=1,
        ttl=7,
    )
    raw = protocol.encode(packet, padding=False)
    assert raw[11] & Flags.IS_COMPRESSED == 0


def test_real_captured_compressed_packet_decodes_correctly():
    # A real bitchat-android client echoing our own 451-byte test message
    # back as a single compressed, unfragmented packet -- captured live.
    # Confirms our decode-side decompression interoperates with a real
    # sender's compressor, not just our own.
    raw = bytes.fromhex(
        "010206000001a01c05d08207012100f310a55614efa0ffffffffffffffff01c3"
        "3591d16dc3300c4457b90182ecd0026951a0e94791056489b689ca9441d289bd"
        "7da91405f4214177c777d26d6643ac84429507d2e4540fd426139cccb190599a"
        "08de403b6966238c9aa685c4937313a4accd0ccb569dd74a78fdbce0a11cee33"
        "3e1c4254acdb07c2836a45bb93626c9b62dea4281518ef7e405808c3113e5883"
        "cf042329a14dd9b75483cad6ca1eb80e9608348aa45471fd43bc1d2be1edfbe5"
        "fd7af9ba614df987ba58cc2915b4f119c7d12bfca937b63804ef26ff7d02e509"
        "7e4225f72edd0c3183c7237892432999d132044b14ef884a99f8dea5715731b0"
        "e72ecc95230fabb6b2e528d4a5b4471134e58925a44ebbe3c13e439acf3da168"
        "5b572a27b86e92e32362db34829bc633041cc74c4d625120aa3cbf44caf91747"
        "3ff383d352a58ec3928cbb22fad4fa6afc3926f20fedb4b13043805447b52f2c"
        "520b437d2aa4b269026bf1380ca3fe1f07ab7eca5f833f724c0dc6bc5ab808"
    )
    pkt = protocol.decode(raw)
    assert pkt.type == MessageType.MESSAGE
    assert pkt.recipient_id == b"\xff" * 8
    assert pkt.signature is not None
    content = pkt.payload.decode("utf-8")
    assert content.startswith("This is a deliberately long test message")
    assert content.endswith("end to end.")
