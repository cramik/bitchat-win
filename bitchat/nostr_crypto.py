r"""NIP-44 "v2" encryption and NIP-01 event ID/Schnorr signing, matching
bitchat-android's actual implementation byte-for-byte, NOT the official
NIP-44 spec.

This is the single most important thing to get right in this module: real
bitchat's `NostrCrypto.kt` deviates from the public NIP-44 spec (which
specifies ChaCha20 + HMAC-SHA256, with length-padding) in favor of a
simpler, non-standard scheme borrowed from their iOS client (comment in the
Kotlin source: "Match iOS: derive HKDF input from the compressed shared
point (33 bytes)"), XChaCha20-Poly1305 AEAD, no padding at all, still
labeled "v2:" on the wire. This means bitchat's Nostr DMs are NOT readable
by generic Nostr clients implementing the real NIP-44, only by other
bitchat clients. Since interop with real bitchat-android is the entire
point here, we match *this* scheme exactly, not the spec.

Key agreement (`derive_conversation_key`):
    1. Lift the other party's 32-byte x-only pubkey to a full point with an
       explicit, chosen Y parity (encrypt always assumes even-Y for the
       *recipient's* key; decrypt doesn't know which parity the sender
       assumed, so it tries both, whichever produces a valid AEAD tag is
       correct. The two parity choices give shared points that are exact
       negatives of each other, same X, opposite sign, which is why
       trying both is both necessary and sufficient, not a guess).
    2. shared_point = our_privkey * their_pubkey_point (real EC scalar
       multiplication, not `coincurve.PrivateKey.ecdh()`, that helper
       returns sha256(compressed point), but bitchat's HKDF wants the raw
       33-byte SEC1-compressed shared point itself as input).
    3. HKDF-SHA256(salt=b"", ikm=compressed_shared_point, info=b"nip44-v2",
       length=32), standard HKDF, one extract + one expand round (the
       output is exactly 32 bytes so a single expand round suffices).

Encryption: XChaCha20-Poly1305 (pynacl) with a random 24-byte nonce, no
associated data, no plaintext padding. Wire format: "v2:" +
base64url-no-padding(nonce || ciphertext || 16-byte tag).

NIP-01 event ID: sha256 of the compact JSON array
`[0, pubkey, created_at, kind, tags, content]`. Compactness matters for
interop, a receiver (or a relay validating before storing/forwarding)
independently recomputes this same hash from the fields and must get the
identical bytes to verify our signature; getting separators or escaping
wrong here would make every event we send silently rejected. Matches
Android's `GsonBuilder().disableHtmlEscaping()`: only the JSON-mandated
escapes (`"`, `\`, and control characters) apply, no HTML-safe escaping
of `<`/`>`/`&`, and non-ASCII text is emitted as raw UTF-8, not escaped.
Python's `json.dumps(..., ensure_ascii=False, separators=(",", ":"))`
matches this for everything except pathological non-standard control
characters, which real chat content won't contain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import List, Tuple

import nacl.bindings as _nacl
from coincurve import PrivateKey, PublicKey

from .nostr_identity import verify_schnorr

NIP44_INFO = b"nip44-v2"
XCHACHA_NONCE_SIZE = 24


class Nip44Error(Exception):
    """Encryption/decryption failed, bad ciphertext, wrong key, etc."""


def _lift_x(xonly_pubkey_hex: str, even_y: bool) -> PublicKey:
    prefix = b"\x02" if even_y else b"\x03"
    return PublicKey(prefix + bytes.fromhex(xonly_pubkey_hex))


def _shared_point_compressed(private_key: PrivateKey, their_xonly_hex: str, even_y: bool) -> bytes:
    their_point = _lift_x(their_xonly_hex, even_y)
    shared_point = their_point.multiply(private_key.secret)
    return shared_point.format(compressed=True)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_one_round(prk: bytes, info: bytes, length: int) -> bytes:
    # A single round (T1 = HMAC(prk, info || 0x01)) is exactly what
    # deriveNIP44Key does, sufficient since 32 requested bytes fits in one
    # SHA-256 HMAC output.
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def derive_conversation_key(private_key: PrivateKey, their_xonly_pubkey_hex: str, even_y: bool) -> bytes:
    shared_secret = _shared_point_compressed(private_key, their_xonly_pubkey_hex, even_y)
    prk = _hkdf_extract(b"", shared_secret)
    return _hkdf_expand_one_round(prk, NIP44_INFO, 32)


def encrypt(plaintext: str, recipient_xonly_pubkey_hex: str, sender_private_key: PrivateKey) -> str:
    """Returns "v2:<base64url>", always assumes even-Y for the
    recipient's x-only pubkey (matches encryptNIP44's `preferOddY = false`)."""
    key = derive_conversation_key(sender_private_key, recipient_xonly_pubkey_hex, even_y=True)
    nonce = os.urandom(XCHACHA_NONCE_SIZE)
    ciphertext = _nacl.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext.encode("utf-8"), b"", nonce, key
    )
    combined = nonce + ciphertext
    b64 = _base64url_encode(combined)
    return f"v2:{b64}"


def decrypt(ciphertext_str: str, sender_xonly_pubkey_hex: str, recipient_private_key: PrivateKey) -> str:
    if not ciphertext_str.startswith("v2:"):
        raise Nip44Error("invalid NIP-44 version prefix")
    encoded = ciphertext_str[len("v2:") :]
    try:
        combined = _base64url_decode(encoded)
    except Exception as exc:  # noqa: BLE001 - base64 raises assorted error types
        raise Nip44Error(f"invalid base64url payload: {exc}") from exc
    if len(combined) < XCHACHA_NONCE_SIZE:
        raise Nip44Error("payload too short to contain a nonce")
    nonce, body = combined[:XCHACHA_NONCE_SIZE], combined[XCHACHA_NONCE_SIZE:]

    last_error: "Exception | None" = None
    for even_y in (True, False):  # sender's parity assumption is unknown to us, try both
        key = derive_conversation_key(recipient_private_key, sender_xonly_pubkey_hex, even_y)
        try:
            plaintext = _nacl.crypto_aead_xchacha20poly1305_ietf_decrypt(body, b"", nonce, key)
            return plaintext.decode("utf-8")
        except Exception as exc:  # noqa: BLE001 - pynacl raises CryptoError on tag mismatch
            last_error = exc
    raise Nip44Error(f"decryption failed with both Y parities: {last_error}")


def _base64url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    import base64

    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def canonical_json(value) -> str:
    """Compact JSON matching Gson's disableHtmlEscaping() output: no extra
    whitespace, no HTML-safe escaping of <>&='|, non-ASCII left as raw
    UTF-8 rather than \\uXXXX-escaped."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def compute_event_id(pubkey_hex: str, created_at: int, kind: int, tags: List[List[str]], content: str) -> bytes:
    """NIP-01 event ID: sha256 of the compact [0, pubkey, created_at, kind,
    tags, content] array."""
    serialized = canonical_json([0, pubkey_hex, created_at, kind, tags, content])
    return hashlib.sha256(serialized.encode("utf-8")).digest()


def sign_event_id(event_id: bytes, private_key: PrivateKey) -> bytes:
    return private_key.sign_schnorr(event_id)


def verify_event_signature(
    pubkey_hex: str, created_at: int, kind: int, tags: List[List[str]], content: str, event_id_hex: str, sig_hex: str
) -> bool:
    """Recomputes the event ID from the fields and checks both that it
    matches the claimed `id` and that `sig` is a valid Schnorr signature
    over it, mirrors NostrEvent.isValidSignature() exactly."""
    computed_id = compute_event_id(pubkey_hex, created_at, kind, tags, content)
    if computed_id.hex() != event_id_hex:
        return False
    return verify_schnorr(pubkey_hex, computed_id, bytes.fromhex(sig_hex))
