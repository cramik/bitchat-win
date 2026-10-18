"""BitchatFilePacket TLV: images, generic files, and voice notes carried
over the mesh as MessageType.FILE_TRANSFER (0x22).

Ported from bitchat-reference/bitchat/Protocols/BitchatFilePacket.swift,
which itself mirrors bitchat-android's BitchatFilePacket.kt "to ensure
cross-platform interoperability" (its own docstring's words), unlike
fragmentation and compression, this format was correct on the first real
test, since we'd already learned the general lesson (compress first,
canonical framing, TOFU trust) from public messages and DMs.

Sent exactly like a public message (broadcast, Ed25519-signed, fragmented
if the encoded+signed packet doesn't fit a single BLE write), the only
difference is what's inside the payload: this TLV instead of raw UTF-8.

v2 canonical TLV layout: [type(1)][length][value], big-endian lengths.
fileName/mimeType use a 2-byte length; fileSize is a fixed 4-byte value;
content uses a 4-byte length (the one field expected to exceed 65535
bytes). Deliberately not ported: the reference's legacy-format fallback
decoding (8-byte fileSize, 2-byte content length) kept only for backward
compatibility with old client builds, there's no old build of *this*
client to be compatible with, so we always encode canonical v2 and only
decode-tolerate the one fallback (2-byte content length) cheaply.

Also deliberately not ported: `PrivateMediaMessageIdentity`'s stable-ID
derivation for Noise-encrypted private media receipts, read receipts for
private media aren't implemented, though private media transfer itself is
(see mesh.py's send_private_file).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

FILE_NAME = 0x01
FILE_SIZE = 0x02
MIME_TYPE = 0x03
CONTENT = 0x04

# FileTransferLimits.maxPayloadBytes
MAX_PAYLOAD_BYTES = 1024 * 1024


@dataclass
class BitchatFilePacket:
    content: bytes
    file_name: Optional[str] = None
    mime_type: Optional[str] = None
    file_size: Optional[int] = None

    def encode(self) -> Optional[bytes]:
        resolved_size = self.file_size if self.file_size is not None else len(self.content)
        if resolved_size > MAX_PAYLOAD_BYTES or len(self.content) > MAX_PAYLOAD_BYTES:
            return None

        out = bytearray()

        if self.file_name is not None:
            name_bytes = self.file_name.encode("utf-8")
            if len(name_bytes) <= 0xFFFF:
                out.append(FILE_NAME)
                out += len(name_bytes).to_bytes(2, "big")
                out += name_bytes

        out.append(FILE_SIZE)
        out += (4).to_bytes(2, "big")
        out += resolved_size.to_bytes(4, "big")

        if self.mime_type is not None:
            mime_bytes = self.mime_type.encode("utf-8")
            if len(mime_bytes) <= 0xFFFF:
                out.append(MIME_TYPE)
                out += len(mime_bytes).to_bytes(2, "big")
                out += mime_bytes

        out.append(CONTENT)
        out += len(self.content).to_bytes(4, "big")
        out += self.content

        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> Optional["BitchatFilePacket"]:
        offset = 0
        file_name: Optional[str] = None
        file_size: Optional[int] = None
        mime_type: Optional[str] = None
        content = bytearray()

        while offset < len(data):
            tlv_type = data[offset]
            offset += 1
            if offset + 2 > len(data):
                return None

            if tlv_type == CONTENT:
                # Try the canonical 4-byte length first; fall back to the
                # legacy 2-byte length only if the 4-byte reading doesn't
                # fit what's left (cheap decode-only compatibility, we
                # never emit the legacy form ourselves).
                if offset + 4 <= len(data) and int.from_bytes(
                    data[offset : offset + 4], "big"
                ) <= len(data) - offset - 4:
                    length = int.from_bytes(data[offset : offset + 4], "big")
                    offset += 4
                else:
                    length = int.from_bytes(data[offset : offset + 2], "big")
                    offset += 2
            else:
                length = int.from_bytes(data[offset : offset + 2], "big")
                offset += 2

            if offset + length > len(data):
                return None
            value = data[offset : offset + length]
            offset += length

            if tlv_type == FILE_NAME:
                file_name = value.decode("utf-8", errors="replace")
            elif tlv_type == FILE_SIZE:
                if len(value) in (4, 8):
                    size = int.from_bytes(value, "big")
                    if size > MAX_PAYLOAD_BYTES:
                        return None
                    file_size = size
            elif tlv_type == MIME_TYPE:
                mime_type = value.decode("utf-8", errors="replace")
            elif tlv_type == CONTENT:
                if len(content) + len(value) > MAX_PAYLOAD_BYTES:
                    return None
                content += value
            # unknown TLV types are ignored, matching the reference's `case nil: continue`

        if not content:
            return None
        return cls(
            content=bytes(content),
            file_name=file_name,
            mime_type=mime_type,
            file_size=file_size if file_size is not None else len(content),
        )
