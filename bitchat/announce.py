"""Announce packet TLV payload (MessageType.ANNOUNCE / 0x01).

Ported from bitchat-reference/bitchat/Protocols/Packets.swift `AnnouncementPacket`.
We encode only nickname + noisePublicKey + signingPublicKey (the fields every
client requires); directNeighbors/capabilities/bridgeGeohash are optional on
the wire and safe to omit in both directions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

TLV_NICKNAME = 0x01
TLV_NOISE_PUBLIC_KEY = 0x02
TLV_SIGNING_PUBLIC_KEY = 0x03
TLV_DIRECT_NEIGHBORS = 0x04
TLV_CAPABILITIES = 0x05
TLV_BRIDGE_GEOHASH = 0x06


@dataclass
class AnnouncementPacket:
    nickname: str
    noise_public_key: bytes
    signing_public_key: bytes

    def encode(self) -> bytes:
        nickname_bytes = self.nickname.encode("utf-8")
        if len(nickname_bytes) > 255:
            raise ValueError("nickname too long")
        if len(self.noise_public_key) > 255 or len(self.signing_public_key) > 255:
            raise ValueError("key too long for a single-byte TLV length")

        out = bytearray()
        out.append(TLV_NICKNAME)
        out.append(len(nickname_bytes))
        out += nickname_bytes

        out.append(TLV_NOISE_PUBLIC_KEY)
        out.append(len(self.noise_public_key))
        out += self.noise_public_key

        out.append(TLV_SIGNING_PUBLIC_KEY)
        out.append(len(self.signing_public_key))
        out += self.signing_public_key

        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> Optional["AnnouncementPacket"]:
        offset = 0
        nickname: Optional[str] = None
        noise_public_key: Optional[bytes] = None
        signing_public_key: Optional[bytes] = None

        while offset + 2 <= len(data):
            tlv_type = data[offset]
            offset += 1
            length = data[offset]
            offset += 1
            if offset + length > len(data):
                return None
            value = data[offset : offset + length]
            offset += length

            if tlv_type == TLV_NICKNAME:
                try:
                    nickname = value.decode("utf-8")
                except UnicodeDecodeError:
                    return None
            elif tlv_type == TLV_NOISE_PUBLIC_KEY:
                noise_public_key = bytes(value)
            elif tlv_type == TLV_SIGNING_PUBLIC_KEY:
                signing_public_key = bytes(value)
            # directNeighbors / capabilities / bridgeGeohash: ignored, not needed

        if nickname is None or noise_public_key is None or signing_public_key is None:
            return None
        return cls(
            nickname=nickname,
            noise_public_key=noise_public_key,
            signing_public_key=signing_public_key,
        )
