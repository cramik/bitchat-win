"""Stateful manager for geohash public channels: join/leave, presence
tracking, message dedup, and the periodic presence-heartbeat loop.

One instance per running client (like MeshEngine, FavoritesStore, etc.),
owns the currently-joined geohash, its derived Nostr identity (see
nostr_identity.py's derive_for_geohash, a fresh identity per geohash,
unrelated to the persistent favorite-DM identity), and a participant
last-seen map used to answer "who's here" (GeohashPresenceSpec.md: online
= seen within the last 5 minutes).

Deliberately supports only one joined channel at a time, the reference
apps let you keep several channel tabs open simultaneously, but that's a
UI-multiplexing concern more than a protocol one, and a single "current
channel" matches how a text console naturally works (type a line, it goes
to wherever you currently are).
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from . import geohash
from .nostr_event import NostrEvent, NostrKind
from .nostr_identity import NostrIdentity
from .nostr_relay import NostrRelayPool

logger = logging.getLogger("bitchat.geohash_channel")

_SUB_ID_PREFIX = "geo-"
_SEEN_CACHE_MAX = 2000

# (geohash, sender_pubkey_hex, nickname_or_None, content, is_teleported)
GeohashMessageFn = Callable[[str, str, Optional[str], str, bool], None]


@dataclass
class Participant:
    pubkey_hex: str
    nickname: Optional[str]
    last_seen: float


class GeohashChannelManager:
    def __init__(
        self,
        device_seed: bytes,
        relay_pool: NostrRelayPool,
        on_message: Optional[GeohashMessageFn] = None,
    ) -> None:
        self.device_seed = device_seed
        self.relay_pool = relay_pool
        self.on_message = on_message
        self.current_geohash: Optional[str] = None
        self.identity: Optional[NostrIdentity] = None
        self._participants: Dict[str, Participant] = {}
        self._seen_event_ids: "OrderedDict[str, None]" = OrderedDict()
        self._presence_task: Optional["asyncio.Task"] = None

    async def join(self, raw_geohash: str) -> str:
        """Switches the active channel to `raw_geohash` (leaving whatever
        was previously joined first) and returns the normalized geohash
        actually joined. Raises ValueError for an invalid geohash string."""
        normalized = geohash.normalize_geohash(raw_geohash)
        if not geohash.is_valid_geohash(normalized):
            raise ValueError(f"not a valid geohash: {raw_geohash!r}")

        await self.leave()
        self.current_geohash = normalized
        self.identity = NostrIdentity.derive_for_geohash(self.device_seed, normalized)
        self._participants.clear()

        await self.relay_pool.subscribe(
            _SUB_ID_PREFIX + normalized,
            {"kinds": [NostrKind.EPHEMERAL_EVENT, NostrKind.GEOHASH_PRESENCE], "#g": [normalized]},
        )

        if geohash.should_send_presence(normalized):
            # One heartbeat right away so participant counts update
            # promptly, then keep going on the randomized interval.
            await self.relay_pool.publish(geohash.create_geohash_presence_event(normalized, self.identity))
            self._presence_task = asyncio.create_task(self._presence_loop(normalized))

        return normalized

    async def leave(self) -> None:
        if self.current_geohash is None:
            return
        if self._presence_task is not None:
            self._presence_task.cancel()
            try:
                await self._presence_task
            except asyncio.CancelledError:
                pass
            self._presence_task = None
        await self.relay_pool.unsubscribe(_SUB_ID_PREFIX + self.current_geohash)
        self.current_geohash = None
        self.identity = None
        self._participants.clear()

    async def send(self, content: str, nickname: Optional[str] = None) -> None:
        if self.current_geohash is None or self.identity is None:
            raise RuntimeError("not currently in a geohash channel")
        event = geohash.create_ephemeral_geohash_event(content, self.current_geohash, self.identity, nickname)
        await self.relay_pool.publish(event)

    def participant_count(self) -> int:
        cutoff = time.time() - geohash.PRESENCE_ONLINE_WINDOW_SECONDS
        return sum(1 for p in self._participants.values() if p.last_seen >= cutoff)

    def _seen_before(self, event_id: str) -> bool:
        if event_id in self._seen_event_ids:
            return True
        self._seen_event_ids[event_id] = None
        if len(self._seen_event_ids) > _SEEN_CACHE_MAX:
            self._seen_event_ids.popitem(last=False)
        return False

    async def handle_incoming_event(self, event: NostrEvent) -> None:
        """Feed events here as they arrive from NostrRelayPool, ignores
        anything not for the currently-joined channel (including events for
        a channel we've since left, or ones missing/mismatching the `g`
        tag), duplicates, and events with a signature that doesn't actually
        verify against their claimed pubkey."""
        if event.kind not in (NostrKind.EPHEMERAL_EVENT, NostrKind.GEOHASH_PRESENCE):
            return
        if self.current_geohash is None:
            return
        if geohash.geohash_tag_value(event) != self.current_geohash:
            return
        if self._seen_before(event.id):
            return
        if not event.is_valid_signature():
            logger.debug("dropping geohash event with invalid signature")
            return

        nickname = geohash.nickname_tag_value(event)
        self._participants[event.pubkey] = Participant(
            pubkey_hex=event.pubkey, nickname=nickname, last_seen=time.time()
        )

        if event.kind == NostrKind.EPHEMERAL_EVENT and self.on_message is not None:
            self.on_message(
                self.current_geohash,
                event.pubkey,
                nickname,
                event.content,
                geohash.is_teleported(event),
            )

    async def _presence_loop(self, joined_geohash: str) -> None:
        try:
            while True:
                await asyncio.sleep(geohash.next_presence_interval_seconds())
                if self.identity is None:
                    return
                await self.relay_pool.publish(geohash.create_geohash_presence_event(joined_geohash, self.identity))
        except asyncio.CancelledError:
            raise
