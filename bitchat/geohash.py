"""Geohash channels: public, location-scoped chat over Nostr relays.

Ported from bitchat's NostrProtocol.createEphemeralGeohashEvent /
createGeohashPresenceEvent (Android: NostrProtocol.kt:107-214; iOS:
NostrProtocol.swift:244-335). Unlike favorite-peer DMs (nostr_event.py),
these are plain signed Nostr events published directly to relays, no
NIP-59 gift-wrap, no encryption at all. Anyone subscribed to the same
geohash sees everything; there's no membership or invite concept, unlike
groups (see plan, a completely different, iOS-only feature).

Deliberately out of scope (see README): GPS/location services (the user
types a geohash string directly, a real, supported usage pattern in the
reference apps too, called "teleporting": browsing a channel that doesn't
match your live GPS fix), the geo-relay directory CSV + haversine nearest-
relay ranking (both reference clients already degrade to "no geo-specific
relays, use defaults" when that's unavailable, reusing our fixed 4-relay
list is a legitimate subset of that same fallback behavior, not a
divergence), kind-1 "location notes" (a separate board/bulletin feature),
and proof-of-work mining (opt-in in the reference, skipped here).

Since we have no GPS at all, every message from this client is honestly
always "teleported", there's no way for us to claim live physical
presence, so the teleport tag is always set on outgoing messages.
"""
from __future__ import annotations

import random
import time
from typing import List, Optional

from .nostr_event import NostrEvent, NostrKind
from .nostr_identity import NostrIdentity

GEOHASH_ALPHABET = "0123456789bcdefghjkmnpqrstuvwxyz"
MIN_GEOHASH_LENGTH = 1
MAX_GEOHASH_LENGTH = 12

# GeohashPresenceSpec.md: presence heartbeats are only sent for channels at
# region/province/city precision or coarser (never neighborhood/block/
# building), to avoid broadcasting a device's fine-grained location. A
# shorter geohash string covers a larger area, so "coarse enough" is a
# maximum string length.
PRESENCE_MAX_GEOHASH_LENGTH = 5

# GeohashPresenceSpec.md: heartbeat every 40-80s (avg 60s), randomized.
PRESENCE_INTERVAL_MIN_SECONDS = 40
PRESENCE_INTERVAL_MAX_SECONDS = 80

# "Online" means a last-seen within this window.
PRESENCE_ONLINE_WINDOW_SECONDS = 5 * 60


def is_valid_geohash(geohash: str) -> bool:
    if not (MIN_GEOHASH_LENGTH <= len(geohash) <= MAX_GEOHASH_LENGTH):
        return False
    return all(c in GEOHASH_ALPHABET for c in geohash.lower())


def normalize_geohash(geohash: str) -> str:
    return geohash.strip().lower()


def should_send_presence(geohash: str) -> bool:
    return len(geohash) <= PRESENCE_MAX_GEOHASH_LENGTH


def next_presence_interval_seconds() -> float:
    return random.uniform(PRESENCE_INTERVAL_MIN_SECONDS, PRESENCE_INTERVAL_MAX_SECONDS)


def create_ephemeral_geohash_event(
    content: str,
    geohash: str,
    identity: NostrIdentity,
    nickname: Optional[str] = None,
) -> NostrEvent:
    """A public chat message in a geohash channel, plain signed event, no
    encryption, no gift-wrap. `teleported` is always True here (see module
    docstring: this client has no GPS to ever honestly claim otherwise)."""
    tags: List[List[str]] = [["g", geohash]]
    if nickname:
        tags.append(["n", nickname])
    tags.append(["t", "teleport"])
    event = NostrEvent(
        pubkey=identity.pubkey_hex,
        created_at=int(time.time()),
        kind=NostrKind.EPHEMERAL_EVENT,
        tags=tags,
        content=content,
    )
    return event.sign(identity.private_key)


def create_geohash_presence_event(geohash: str, identity: NostrIdentity) -> NostrEvent:
    event = NostrEvent(
        pubkey=identity.pubkey_hex,
        created_at=int(time.time()),
        kind=NostrKind.GEOHASH_PRESENCE,
        tags=[["g", geohash]],
        content="",
    )
    return event.sign(identity.private_key)


def geohash_tag_value(event: NostrEvent) -> Optional[str]:
    for tag in event.tags:
        if len(tag) >= 2 and tag[0] == "g":
            return tag[1]
    return None


def nickname_tag_value(event: NostrEvent) -> Optional[str]:
    for tag in event.tags:
        if len(tag) >= 2 and tag[0] == "n":
            return tag[1]
    return None


def is_teleported(event: NostrEvent) -> bool:
    return any(len(tag) >= 2 and tag[0] == "t" and tag[1] == "teleport" for tag in event.tags)
