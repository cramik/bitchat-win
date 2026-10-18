"""NIP-01 events, NIP-17 gift-wrapped private messages.

Ported from bitchat-android's `NostrEvent.kt`/`NostrProtocol.kt`
(createPrivateMessage / decryptPrivateMessage / createSeal / createGiftWrap
/ unwrapGiftWrap / openSeal).

Flow for sending, exactly matching the reference: rumor (unsigned kind 14,
tagged to the recipient) -> seal (kind 13, signed by the *real* sender
identity, content = NIP-44 of the rumor's JSON) -> gift wrap (kind 1059,
signed by a fresh *ephemeral* throwaway keypair generated just for this one
message, content = NIP-44 of the seal's JSON, encrypted to the recipient
using the ephemeral key). Only the seal's signature is ever checked on
receipt (`seal.isValidSignature()`), the rumor is intentionally unsigned
(that's what makes it a "rumor" under NIP-59) and the gift wrap's own
signature isn't re-verified by application logic either, though it still
needs to be genuinely valid for a well-behaved relay to accept/store/relay
it in the first place.

JSON note: the rumor/seal are serialized as an ordinary JSON *object*
(`{"id":..., "pubkey":..., ...}`) for use as encrypted `content`, not the
canonical `[0, pubkey, ...]` array form nostr_crypto.compute_event_id() uses
for hashing. The receiver only ever JSON-parses this by field name, so exact
escaping/whitespace doesn't matter here the way it does for the event ID.
One real gotcha: a field with value `null` (e.g. `sig` on the unsigned
rumor) must be *omitted* entirely, not emitted as `"sig":null`, Gson's
default serializer drops null fields, and its `JsonElement.asString()` on a
literal JSON null throws rather than returning Kotlin null, so including it
explicitly would make the reference's own receive code crash.
"""
from __future__ import annotations

import dataclasses
import json
import random
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from coincurve import PrivateKey

from . import nostr_crypto
from .nostr_identity import NostrIdentity

MAX_PAST_SECONDS_DEFAULT = 172800  # 2 days, matches randomizeTimestampUpToPast's default


class NostrKind:
    METADATA = 0
    TEXT_NOTE = 1
    SEAL = 13
    DIRECT_MESSAGE = 14
    GIFT_WRAP = 1059
    EPHEMERAL_EVENT = 20000  # geohash channel chat message
    GEOHASH_PRESENCE = 20001  # geohash channel presence heartbeat


def _randomize_timestamp_up_to_past(max_past_seconds: int = MAX_PAST_SECONDS_DEFAULT) -> int:
    now = int(time.time())
    offset = random.randint(0, max_past_seconds)
    return now - offset


@dataclass
class NostrEvent:
    pubkey: str
    created_at: int
    kind: int
    tags: List[List[str]]
    content: str
    id: str = ""
    sig: Optional[str] = None

    def compute_id(self) -> str:
        return nostr_crypto.compute_event_id(self.pubkey, self.created_at, self.kind, self.tags, self.content).hex()

    def sign(self, private_key: PrivateKey) -> "NostrEvent":
        event_id_hex = self.compute_id()
        sig = nostr_crypto.sign_event_id(bytes.fromhex(event_id_hex), private_key)
        return dataclasses.replace(self, id=event_id_hex, sig=sig.hex())

    def is_valid_signature(self) -> bool:
        if not self.sig or not self.id:
            return False
        return nostr_crypto.verify_event_signature(
            self.pubkey, self.created_at, self.kind, self.tags, self.content, self.id, self.sig
        )

    def to_json_object(self) -> dict:
        obj = {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
        }
        if self.sig is not None:  # omit, not null, see module docstring
            obj["sig"] = self.sig
        return obj

    @classmethod
    def from_json_object(cls, obj: dict) -> "NostrEvent":
        return cls(
            id=obj.get("id", ""),
            pubkey=obj["pubkey"],
            created_at=obj["created_at"],
            kind=obj["kind"],
            tags=[list(tag) for tag in obj.get("tags", [])],
            content=obj["content"],
            sig=obj.get("sig"),
        )


def create_private_message_gift_wrap(
    content: str, recipient_pubkey_hex: str, sender_identity: NostrIdentity
) -> NostrEvent:
    """Builds the single gift-wrapped event ready to publish to relays."""
    rumor = NostrEvent(
        pubkey=sender_identity.pubkey_hex,
        created_at=int(time.time()),
        kind=NostrKind.DIRECT_MESSAGE,
        tags=[["p", recipient_pubkey_hex]],
        content=content,
    )
    rumor.id = rumor.compute_id()  # unsigned by design (NIP-59 "rumor"), id set but never signed

    rumor_json = json.dumps(rumor.to_json_object())
    seal_content = nostr_crypto.encrypt(rumor_json, recipient_pubkey_hex, sender_identity.private_key)
    seal = NostrEvent(
        pubkey=sender_identity.pubkey_hex,
        created_at=_randomize_timestamp_up_to_past(),
        kind=NostrKind.SEAL,
        tags=[],
        content=seal_content,
    ).sign(sender_identity.private_key)

    return _create_gift_wrap(seal, recipient_pubkey_hex)


def _create_gift_wrap(seal: NostrEvent, recipient_pubkey_hex: str) -> NostrEvent:
    seal_json = json.dumps(seal.to_json_object())
    ephemeral = NostrIdentity.generate()  # fresh throwaway key, discarded after this one message
    encrypted = nostr_crypto.encrypt(seal_json, recipient_pubkey_hex, ephemeral.private_key)
    gift_wrap = NostrEvent(
        pubkey=ephemeral.pubkey_hex,
        created_at=_randomize_timestamp_up_to_past(),
        kind=NostrKind.GIFT_WRAP,
        tags=[["p", recipient_pubkey_hex]],
        content=encrypted,
    )
    return gift_wrap.sign(ephemeral.private_key)


def decrypt_private_message_gift_wrap(
    gift_wrap: NostrEvent, recipient_identity: NostrIdentity
) -> Optional[Tuple[str, str, int]]:
    """Returns (content, sender_pubkey_hex, created_at) or None if unwrapping
    fails at any stage, mirrors NostrProtocol.decryptPrivateMessage."""
    try:
        decrypted_seal_json = nostr_crypto.decrypt(gift_wrap.content, gift_wrap.pubkey, recipient_identity.private_key)
        seal = NostrEvent.from_json_object(json.loads(decrypted_seal_json))
    except (nostr_crypto.Nip44Error, ValueError, KeyError, json.JSONDecodeError):
        return None

    if seal.kind != NostrKind.SEAL or not seal.is_valid_signature():
        return None

    try:
        decrypted_rumor_json = nostr_crypto.decrypt(seal.content, seal.pubkey, recipient_identity.private_key)
        rumor = NostrEvent.from_json_object(json.loads(decrypted_rumor_json))
    except (nostr_crypto.Nip44Error, ValueError, KeyError, json.JSONDecodeError):
        return None

    if seal.pubkey != rumor.pubkey:
        return None

    return rumor.content, rumor.pubkey, rumor.created_at
