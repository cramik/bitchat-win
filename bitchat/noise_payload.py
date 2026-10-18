"""Inner payload framing carried inside Noise-encrypted private messages.

Ported from bitchat-android-reference/app/src/main/java/com/bitchat/android/
model/NoiseEncrypted.kt (NoisePayload / PrivateMessagePacket), which that
file's own docstring says matches iOS exactly. This layer only exists
*after* NoiseSession.decrypt(), it's plaintext framing on top of the
already-authenticated-and-decrypted bytes, not wire security.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

PRIVATE_MESSAGE = 0x01
READ_RECEIPT = 0x02
DELIVERED = 0x03
GROUP_INVITE = 0x06  # creator-signed group state (invite), see groups.py
GROUP_KEY_UPDATE = 0x07  # creator-signed group state (key rotation/roster update)
FILE_TRANSFER = 0x20


def encode_noise_payload(payload_type: int, data: bytes) -> bytes:
    """[type_byte][data]"""
    return bytes([payload_type]) + data


def decode_noise_payload(data: bytes) -> Optional[Tuple[int, bytes]]:
    if not data:
        return None
    return data[0], data[1:]


@dataclass
class PrivateMessagePacket:
    message_id: str
    content: str

    def encode(self) -> Optional[bytes]:
        """TLV: [type(1)][len(1)][value] for messageID(0x00) then content(0x01).
        Length is a single byte (max 255) per field, matching the reference
        exactly, long private messages truncate at the field level here,
        same constraint real clients have."""
        id_bytes = self.message_id.encode("utf-8")
        content_bytes = self.content.encode("utf-8")
        if len(id_bytes) > 255 or len(content_bytes) > 255:
            return None
        out = bytearray()
        out.append(0x00)
        out.append(len(id_bytes))
        out += id_bytes
        out.append(0x01)
        out.append(len(content_bytes))
        out += content_bytes
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> Optional["PrivateMessagePacket"]:
        offset = 0
        message_id: Optional[str] = None
        content: Optional[str] = None
        while offset + 2 <= len(data):
            tlv_type = data[offset]
            offset += 1
            length = data[offset]
            offset += 1
            if offset + length > len(data):
                return None
            value = data[offset : offset + length]
            offset += length
            if tlv_type == 0x00:
                message_id = value.decode("utf-8", errors="replace")
            elif tlv_type == 0x01:
                content = value.decode("utf-8", errors="replace")
        if message_id is None or content is None:
            return None
        return cls(message_id=message_id, content=content)
