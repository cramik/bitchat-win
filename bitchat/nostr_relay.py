"""NIP-01 relay client: publish events, subscribe to one or more filters,
across bitchat's fixed relay set.

Ported from bitchat-android's `NostrRelayManager.kt`. Real client behavior
this mirrors: a small hardcoded relay list (not user-configurable in the
reference), exponential reconnect backoff per relay, and a dedup cache
since the same event commonly arrives from more than one relay at once.
Always subscribed to `kind=1059` (gift wrap) events tagged `#p` with our
own pubkey (favorite-peer DMs); `subscribe()`/`unsubscribe()` add or remove
further subscriptions on top (e.g. one per joined geohash channel, see
geohash.py), every active subscription is re-sent as a fresh REQ on every
(re)connect, so a subscription survives a relay dropping and reconnecting
without the caller having to redo anything.

Optional Tor routing: pass `tor_proxy_url` (e.g. "socks5://127.0.0.1:9050")
to route every relay connection through an external SOCKS5 proxy instead of
connecting directly. This assumes a real Tor process is *already running*
on the machine (Tor Browser, the standalone Tor Expert Bundle, etc.),
real bitchat embeds and manages its own Tor process (Arti, a Rust
implementation, via a JNI bridge on Android); there's no realistic Windows
equivalent to embedding that ourselves, so this is a deliberate, documented
simplification rather than a full port of that piece. Live-tested against
Tor Browser's bundled Tor on this machine: 3 of the 4 default relays
(relay.primal.net, offchain.pub, nostr21.com) connect over Tor without
issue; relay.damus.io specifically rejects the connection with HTTP 503,
that's relay.damus.io's own anti-abuse policy blocking Tor exit-node
traffic, not a bug in this code (confirmed by the same relay accepting a
non-Tor connection immediately).

Testing note: the connection-loop/reconnect logic here isn't covered by
automated tests, it needs a real (or realistically faked) WebSocket
server to exercise meaningfully, and hitting real public relays from a test
suite would be both flaky and rude. `_handle_message`/`_seen_before` (the
actual message-parsing and dedup logic) are pure enough to unit test
directly and are covered; the network loop itself is reviewed by hand,
plus the manual live test described above for the Tor-specific path.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.parse
import uuid
from collections import OrderedDict
from typing import Awaitable, Callable, Dict, List, Optional

import websockets

from .nostr_event import NostrEvent

logger = logging.getLogger("bitchat.nostr_relay")

# NostrRelayManager.kt's fixed relay list for favorite-peer DMs (not the
# separate, much larger geohash-channel relay list, unrelated feature).
DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://offchain.pub",
    "wss://nostr21.com",
]

GIFT_WRAP_KIND = 1059

RECONNECT_INITIAL_SECONDS = 1.0
RECONNECT_MAX_SECONDS = 300.0  # 5 min cap, matches MAX_BACKOFF_INTERVAL
_DEDUP_CACHE_MAX = 500

EventHandler = Callable[[NostrEvent], Awaitable[None]]


class NostrRelayPool:
    def __init__(
        self,
        our_pubkey_hex: str,
        on_event: EventHandler,
        relays: Optional[List[str]] = None,
        tor_proxy_url: Optional[str] = None,
    ) -> None:
        self.our_pubkey_hex = our_pubkey_hex
        self.on_event = on_event
        self.relays = list(relays) if relays is not None else list(DEFAULT_RELAYS)
        self.tor_proxy_url = tor_proxy_url
        self._sub_id = "bitchat-" + uuid.uuid4().hex[:8]
        self._tasks: Dict[str, "asyncio.Task"] = {}
        self._connections: Dict[str, object] = {}
        self._seen_event_ids: "OrderedDict[str, None]" = OrderedDict()
        self._stopped = False
        # sub_id -> filter dict. Re-sent as a REQ to every relay on (re)connect,
        # so a subscription survives reconnects without the caller having to
        # redo anything. Seeded with the one always-on subscription (gift
        # wraps addressed to us); geohash-channel joins add more via subscribe().
        self._subscriptions: Dict[str, dict] = {
            self._sub_id: {"kinds": [GIFT_WRAP_KIND], "#p": [self.our_pubkey_hex]}
        }

    async def start(self) -> None:
        self._stopped = False
        for url in self.relays:
            self._tasks[url] = asyncio.create_task(self._connection_loop(url))

    async def subscribe(self, sub_id: str, filter_dict: dict) -> None:
        """Adds (or replaces) a subscription and sends REQ to every
        currently-connected relay immediately; also resent automatically on
        every future (re)connect for the life of this subscription."""
        self._subscriptions[sub_id] = filter_dict
        message = json.dumps(["REQ", sub_id, filter_dict])
        for url, ws in list(self._connections.items()):
            try:
                await ws.send(message)
            except Exception as exc:  # noqa: BLE001 - websocket libs raise assorted errors
                logger.debug("REQ %s on %s failed: %s", sub_id, url, exc)

    async def unsubscribe(self, sub_id: str) -> None:
        self._subscriptions.pop(sub_id, None)
        message = json.dumps(["CLOSE", sub_id])
        for url, ws in list(self._connections.items()):
            try:
                await ws.send(message)
            except Exception as exc:  # noqa: BLE001 - websocket libs raise assorted errors
                logger.debug("CLOSE %s on %s failed: %s", sub_id, url, exc)

    async def stop(self) -> None:
        self._stopped = True
        for task in self._tasks.values():
            task.cancel()
        for task in self._tasks.values():
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        self._connections.clear()

    async def publish(self, event: NostrEvent) -> int:
        """Best-effort broadcast to every currently-connected relay. Returns
        how many relays it was actually sent to, 0 doesn't mean failure in
        a way we can retry synchronously, it means no relay is connected
        right now (the reconnect loop will keep trying)."""
        message = json.dumps(["EVENT", event.to_json_object()])
        sent = 0
        for url, ws in list(self._connections.items()):
            try:
                await ws.send(message)
                sent += 1
            except Exception as exc:  # noqa: BLE001 - websocket libs raise assorted errors
                logger.debug("publish to %s failed: %s", url, exc)
        return sent

    async def _open_connection(self, url: str):
        """Plain direct connection, or, when tor_proxy_url is set, a
        connection tunneled through an external SOCKS5 proxy: open a raw
        TCP socket to the relay *through* the proxy first (python-socks),
        then hand that already-connected socket to websockets.connect(),
        which still does its own TLS handshake and NIP-01 upgrade over it
        (confirmed: for a wss:// URI, websockets auto-enables TLS with the
        right SNI hostname even when `sock` is supplied, so this isn't a
        special TLS path, just a different transport underneath)."""
        if not self.tor_proxy_url:
            return await websockets.connect(url, open_timeout=10)

        from python_socks.async_.asyncio import Proxy

        parsed = urllib.parse.urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        proxy = Proxy.from_url(self.tor_proxy_url)
        sock = await proxy.connect(parsed.hostname, port, timeout=30)
        return await websockets.connect(url, sock=sock, open_timeout=30)

    async def _connection_loop(self, url: str) -> None:
        backoff = RECONNECT_INITIAL_SECONDS
        while not self._stopped:
            try:
                async with await self._open_connection(url) as ws:
                    self._connections[url] = ws
                    logger.info("connected to relay %s", url)
                    backoff = RECONNECT_INITIAL_SECONDS
                    for sub_id, filter_dict in list(self._subscriptions.items()):
                        await ws.send(json.dumps(["REQ", sub_id, filter_dict]))
                    async for raw in ws:
                        await self._handle_message(raw)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - websocket libs raise assorted errors
                logger.warning("relay %s connection failed/closed: %s", url, exc)
                logger.debug("relay connection detail", exc_info=True)
            finally:
                self._connections.pop(url, None)
            if self._stopped:
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, RECONNECT_MAX_SECONDS)

    async def _handle_message(self, raw) -> None:
        try:
            msg = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(msg, list) or len(msg) < 3 or msg[0] != "EVENT":
            return  # ignore OK/EOSE/NOTICE/CLOSED, nothing we act on yet
        event_obj = msg[2]
        if not isinstance(event_obj, dict):
            return
        event_id = event_obj.get("id")
        if not isinstance(event_id, str) or self._seen_before(event_id):
            return
        try:
            event = NostrEvent.from_json_object(event_obj)
        except (KeyError, TypeError):
            return
        await self.on_event(event)

    def _seen_before(self, event_id: str) -> bool:
        if event_id in self._seen_event_ids:
            return True
        self._seen_event_ids[event_id] = None
        if len(self._seen_event_ids) > _DEDUP_CACHE_MAX:
            self._seen_event_ids.popitem(last=False)
        return False
