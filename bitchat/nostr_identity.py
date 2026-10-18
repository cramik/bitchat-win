"""A Nostr identity: a secp256k1 keypair wholly separate from the mesh's
X25519/Ed25519 identity, plus NIP-19 bech32 npub/nsec encoding.

Confirmed from bitchat-android's NostrIdentity.kt/NostrIdentityBridge: the
Nostr keypair is freshly generated on first use and persisted for the life
of the install, it is *not* derived from the mesh Noise static key.
Bridging the two identities happens only via explicit association (storing
noisePublicKey -> nostrPubkey once a favorite notification is exchanged,
see favorites.py), not key derivation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Union

import bech32
from coincurve import PrivateKey, PublicKeyXOnly

GEOHASH_DERIVATION_MAX_ITERATIONS = 10


def _bech32_encode(hrp: str, data: bytes) -> str:
    five_bit = bech32.convertbits(data, 8, 5, True)
    return bech32.bech32_encode(hrp, five_bit)


def _bech32_decode(hrp_expected: str, encoded: str) -> bytes:
    hrp, five_bit = bech32.bech32_decode(encoded)
    if hrp != hrp_expected or five_bit is None:
        raise ValueError(f"not a valid {hrp_expected} string: {encoded!r}")
    return bytes(bech32.convertbits(five_bit, 5, 8, False))


def hex_to_npub(pubkey_hex: str) -> str:
    return _bech32_encode("npub", bytes.fromhex(pubkey_hex))


def npub_to_hex(npub: str) -> str:
    return _bech32_decode("npub", npub).hex()


def hex_to_nsec(privkey_hex: str) -> str:
    return _bech32_encode("nsec", bytes.fromhex(privkey_hex))


def nsec_to_hex(nsec: str) -> str:
    return _bech32_decode("nsec", nsec).hex()


def verify_schnorr(pubkey_hex: str, event_id: bytes, signature: bytes) -> bool:
    """Verifies a BIP-340 Schnorr signature over a 32-byte NIP-01 event ID,
    given the signer's 32-byte x-only pubkey (hex)."""
    xonly = PublicKeyXOnly(bytes.fromhex(pubkey_hex))
    return xonly.verify(signature, event_id)


@dataclass
class NostrIdentity:
    private_key: PrivateKey
    pubkey_hex: str  # 32-byte x-only pubkey, hex, the Nostr "pubkey"

    @property
    def npub(self) -> str:
        return hex_to_npub(self.pubkey_hex)

    @property
    def nsec(self) -> str:
        return hex_to_nsec(self.private_key.secret.hex())

    def sign_event_id(self, event_id: bytes) -> bytes:
        """BIP-340 Schnorr signature over a 32-byte NIP-01 event ID."""
        return self.private_key.sign_schnorr(event_id)

    @classmethod
    def _from_secret(cls, secret: bytes) -> "NostrIdentity":
        priv = PrivateKey(secret)
        xonly = PublicKeyXOnly.from_secret(priv.secret)
        return cls(private_key=priv, pubkey_hex=xonly.format().hex())

    @classmethod
    def generate(cls) -> "NostrIdentity":
        priv = PrivateKey()
        return cls._from_secret(priv.secret)

    def save(self, path: Union[str, "os.PathLike[str]"]) -> None:
        path = Path(path)
        path.write_text(json.dumps({"private_key": self.private_key.secret.hex()}))
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # best-effort on platforms/filesystems that don't support POSIX modes

    @classmethod
    def load_or_generate(cls, path: Union[str, "os.PathLike[str]"]) -> "NostrIdentity":
        path = Path(path)
        if path.is_file():
            data = json.loads(path.read_text())
            return cls._from_secret(bytes.fromhex(data["private_key"]))
        identity = cls.generate()
        identity.save(path)
        return identity

    @classmethod
    def derive_for_geohash(cls, device_seed: bytes, geohash: str) -> "NostrIdentity":
        """A separate, ephemeral-per-geohash identity for public geohash
        channels (see geohash.py), deliberately *not* the same identity
        used for favorite-peer DMs, so posting in a public location channel
        never links back to your persistent npub.

        Ported from NostrIdentityBridge.deriveIdentity (confirmed identical
        in spirit on both iOS and Android, though the two reference clients
        actually use opposite iteration-counter endianness from each other
       , irrelevant here since this only needs to be self-consistent on
        one device, not bit-compatible with either reference: two different
        clients derive unrelated, unlinkable identities per geohash even
        when "the same person" runs both, by design). Candidate private key
        = HMAC-SHA256(key=device_seed, msg=geohash_utf8 || iteration_u32be),
        trying iterations 0..9 for the first one that's a valid secp256k1
        scalar; SHA256(device_seed || geohash) as a last-resort fallback in
        the astronomically unlikely case none of the 10 are valid."""
        for iteration in range(GEOHASH_DERIVATION_MAX_ITERATIONS):
            message = geohash.encode("utf-8") + iteration.to_bytes(4, "big")
            candidate = hmac.new(device_seed, message, hashlib.sha256).digest()
            try:
                return cls._from_secret(candidate)
            except ValueError:
                continue
        fallback = hashlib.sha256(device_seed + geohash.encode("utf-8")).digest()
        return cls._from_secret(fallback)


def generate_device_seed() -> bytes:
    return os.urandom(32)


def save_device_seed(seed: bytes, path: Union[str, "os.PathLike[str]"]) -> None:
    path = Path(path)
    path.write_text(json.dumps({"device_seed": seed.hex()}))
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def load_or_generate_device_seed(path: Union[str, "os.PathLike[str]"]) -> bytes:
    path = Path(path)
    if path.is_file():
        data = json.loads(path.read_text())
        return bytes.fromhex(data["device_seed"])
    seed = generate_device_seed()
    save_device_seed(seed, path)
    return seed
