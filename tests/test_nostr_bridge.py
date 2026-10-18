from bitchat import protocol
from bitchat.identity import Identity
from bitchat.nostr_bridge import (
    decode_private_message_from_nostr,
    encode_private_message_for_nostr,
)


def test_bitchat1_round_trip():
    alice = Identity.generate()
    bob = Identity.generate()

    wire = encode_private_message_for_nostr(
        "hello over the internet",
        message_id="msg-1",
        sender_routing_id=alice.routing_id,
        recipient_routing_id=bob.routing_id,
        timestamp_ms=1_700_000_000_000,
    )
    assert wire is not None
    assert wire.startswith("bitchat1:")

    decoded = decode_private_message_from_nostr(wire)
    assert decoded is not None
    sender_id, recipient_id, content = decoded
    assert sender_id == alice.routing_id
    assert recipient_id == bob.routing_id
    assert content == "hello over the internet"


def test_bitchat1_payload_is_padded_and_unsigned_and_unencrypted():
    # Confirms the two easy-to-miss deviations from a normal BLE
    # NOISE_ENCRYPTED send: always padded regardless of type, never signed,
    # and the payload is the raw NoisePayload TLV -- not Noise-ciphertext.
    alice = Identity.generate()
    bob = Identity.generate()

    wire = encode_private_message_for_nostr(
        "hi", "id", alice.routing_id, bob.routing_id, timestamp_ms=1
    )
    from bitchat.nostr_bridge import _base64url_decode

    raw = _base64url_decode(wire[len("bitchat1:") :])
    assert len(raw) in protocol.PAD_BLOCK_SIZES

    packet = protocol.decode(raw)
    assert packet.signature is None
    assert packet.type == protocol.MessageType.NOISE_ENCRYPTED
    # payload[0] is the NoisePayloadType.PRIVATE_MESSAGE marker byte, and the
    # rest is a plain TLV -- readable without any Noise session at all.
    assert packet.payload[0] == 0x01


def test_decode_rejects_non_bitchat1_strings():
    assert decode_private_message_from_nostr("just some text") is None
    assert decode_private_message_from_nostr("bitchat1:not-valid-base64!!!") is None


def test_encode_rejects_oversized_content():
    alice = Identity.generate()
    bob = Identity.generate()
    huge = "x" * 300  # PrivateMessagePacket TLV caps fields at 255 bytes
    result = encode_private_message_for_nostr(huge, "id", alice.routing_id, bob.routing_id, timestamp_ms=1)
    assert result is None
