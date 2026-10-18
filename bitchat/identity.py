"""Local peer identity: Noise static key + Ed25519 signing key + derived PeerID.

Mirrors bitchat-reference/localPackages/BitFoundation/Sources/BitFoundation/PeerID.swift
(`init(publicKey:)`) and Data+SHA256.swift's `sha256Fingerprint()`.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NO_ENC = serialization.NoEncryption()


def derive_peer_id_hex(noise_public_key: bytes) -> str:
    """16-hex PeerID = first 16 hex chars of sha256(noise static pubkey)."""
    return hashlib.sha256(noise_public_key).hexdigest()[:16]


def derive_fingerprint_hex(noise_public_key: bytes) -> str:
    """Full 64-hex SHA-256 fingerprint (the un-truncated form of the above)
   , used to identify a group's creator/members by groups.py."""
    return hashlib.sha256(noise_public_key).hexdigest()


def peer_id_to_routing_bytes(peer_id_hex: str) -> bytes:
    """The 8 raw bytes carried as `senderID`/`recipientID` on the wire."""
    return bytes.fromhex(peer_id_hex)


@dataclass
class Identity:
    noise_private: X25519PrivateKey
    noise_public: X25519PublicKey
    signing_private: Ed25519PrivateKey
    signing_public: Ed25519PublicKey
    peer_id_hex: str
    routing_id: bytes  # 8 bytes, == wire senderID

    @property
    def noise_public_bytes(self) -> bytes:
        return self.noise_public.public_bytes(_RAW, _RAW_PUB)

    @property
    def signing_public_bytes(self) -> bytes:
        return self.signing_public.public_bytes(_RAW, _RAW_PUB)

    @property
    def fingerprint_hex(self) -> str:
        """Full 64-hex SHA-256 fingerprint of the Noise static key, used
        by groups.py's GroupMember, distinct from peer_id_hex (the first 16
        hex chars of the same hash used as the wire routing ID)."""
        return derive_fingerprint_hex(self.noise_public_bytes)

    @classmethod
    def generate(cls) -> "Identity":
        return cls._from_private_keys(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())

    @classmethod
    def _from_private_keys(
        cls, noise_priv: X25519PrivateKey, sign_priv: Ed25519PrivateKey
    ) -> "Identity":
        noise_pub = noise_priv.public_key()
        sign_pub = sign_priv.public_key()
        noise_pub_bytes = noise_pub.public_bytes(_RAW, _RAW_PUB)
        peer_id_hex = derive_peer_id_hex(noise_pub_bytes)
        return cls(
            noise_private=noise_priv,
            noise_public=noise_pub,
            signing_private=sign_priv,
            signing_public=sign_pub,
            peer_id_hex=peer_id_hex,
            routing_id=peer_id_to_routing_bytes(peer_id_hex),
        )

    def save(self, path: Union[str, "os.PathLike[str]"]) -> None:
        """Persists both private keys as hex to a local JSON file. A stable
        identity across runs matters once anything (favorite status, a
        Nostr npub association, a real phone's peer list) is keyed by our
        Noise pubkey fingerprint, a fresh random identity every launch
        would silently orphan all of that."""
        path = Path(path)
        data = {
            "noise_private": self.noise_private.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex(),
            "signing_private": self.signing_private.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex(),
        }
        path.write_text(json.dumps(data))
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # best-effort on platforms/filesystems that don't support POSIX modes

    @classmethod
    def load_or_generate(cls, path: Union[str, "os.PathLike[str]"]) -> "Identity":
        path = Path(path)
        if path.is_file():
            data = json.loads(path.read_text())
            noise_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(data["noise_private"]))
            sign_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["signing_private"]))
            return cls._from_private_keys(noise_priv, sign_priv)
        identity = cls.generate()
        identity.save(path)
        return identity
