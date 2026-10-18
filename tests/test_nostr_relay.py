import asyncio
import json

from bitchat.nostr_event import NostrEvent, NostrKind, create_private_message_gift_wrap
from bitchat.nostr_identity import NostrIdentity
from bitchat.nostr_relay import NostrRelayPool


def make_pool(our_pubkey_hex="aa" * 32):
    received = []

    async def on_event(event):
        received.append(event)

    pool = NostrRelayPool(our_pubkey_hex, on_event, relays=["wss://fake.example"])
    return pool, received


def test_handle_message_delivers_well_formed_event():
    pool, received = make_pool()
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()
    gift_wrap = create_private_message_gift_wrap("hi", bob.pubkey_hex, alice)

    raw = json.dumps(["EVENT", "sub-id", gift_wrap.to_json_object()])
    asyncio.run(pool._handle_message(raw))

    assert len(received) == 1
    assert received[0].id == gift_wrap.id
    assert received[0].kind == NostrKind.GIFT_WRAP


def test_handle_message_dedupes_the_same_event_id():
    pool, received = make_pool()
    alice = NostrIdentity.generate()
    bob = NostrIdentity.generate()
    gift_wrap = create_private_message_gift_wrap("hi", bob.pubkey_hex, alice)
    raw = json.dumps(["EVENT", "sub-id", gift_wrap.to_json_object()])

    asyncio.run(pool._handle_message(raw))
    asyncio.run(pool._handle_message(raw))  # arrives again from a second relay

    assert len(received) == 1


def test_handle_message_ignores_non_event_message_types():
    pool, received = make_pool()
    for control in [
        json.dumps(["EOSE", "sub-id"]),
        json.dumps(["NOTICE", "some notice"]),
        json.dumps(["OK", "event-id", True, ""]),
    ]:
        asyncio.run(pool._handle_message(control))
    assert received == []


def test_handle_message_ignores_malformed_json():
    pool, received = make_pool()
    asyncio.run(pool._handle_message("not json at all"))
    asyncio.run(pool._handle_message(json.dumps(["EVENT"])))  # too short
    asyncio.run(pool._handle_message(json.dumps(["EVENT", "sub-id", "not-an-object"])))
    assert received == []


def test_publish_sends_to_all_connected_relays_and_counts_them():
    pool, _ = make_pool()

    class FakeWebSocket:
        def __init__(self):
            self.sent = []

        async def send(self, message):
            self.sent.append(message)

    ws_a, ws_b = FakeWebSocket(), FakeWebSocket()
    pool._connections["relay-a"] = ws_a
    pool._connections["relay-b"] = ws_b

    identity = NostrIdentity.generate()
    event = NostrEvent(pubkey=identity.pubkey_hex, created_at=1, kind=1, tags=[], content="hi").sign(
        identity.private_key
    )
    sent_count = asyncio.run(pool.publish(event))

    assert sent_count == 2
    assert len(ws_a.sent) == 1
    assert len(ws_b.sent) == 1
    assert json.loads(ws_a.sent[0]) == ["EVENT", event.to_json_object()]


def test_publish_counts_only_relays_that_did_not_raise():
    pool, _ = make_pool()

    class BrokenWebSocket:
        async def send(self, message):
            raise ConnectionError("relay went away")

    pool._connections["broken"] = BrokenWebSocket()
    identity = NostrIdentity.generate()
    event = NostrEvent(pubkey=identity.pubkey_hex, created_at=1, kind=1, tags=[], content="hi").sign(
        identity.private_key
    )
    sent_count = asyncio.run(pool.publish(event))
    assert sent_count == 0


def test_open_connection_without_tor_proxy_connects_directly(monkeypatch):
    pool = NostrRelayPool("aa" * 32, lambda e: None, relays=["wss://fake.example"])
    assert pool.tor_proxy_url is None

    calls = []

    async def fake_connect(url, **kwargs):
        calls.append((url, kwargs))
        return "a-connection"

    import bitchat.nostr_relay as nostr_relay_module

    monkeypatch.setattr(nostr_relay_module.websockets, "connect", fake_connect)

    result = asyncio.run(pool._open_connection("wss://fake.example"))
    assert result == "a-connection"
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == "wss://fake.example"
    assert "sock" not in kwargs  # no proxy -- connects directly, no pre-made socket


def test_open_connection_with_tor_proxy_tunnels_through_a_socket(monkeypatch):
    pool = NostrRelayPool(
        "aa" * 32, lambda e: None, relays=["wss://fake.example"], tor_proxy_url="socks5://127.0.0.1:9050"
    )

    proxy_calls = []
    connect_calls = []
    fake_socket = object()

    class FakeProxy:
        def __init__(self, url):
            self.url = url

        @classmethod
        def from_url(cls, url):
            return cls(url)

        async def connect(self, host, port, timeout=None):
            proxy_calls.append((self.url, host, port))
            return fake_socket

    async def fake_connect(url, **kwargs):
        connect_calls.append((url, kwargs))
        return "a-tor-connection"

    import bitchat.nostr_relay as nostr_relay_module
    import python_socks.async_.asyncio as socks_asyncio_module

    monkeypatch.setattr(socks_asyncio_module, "Proxy", FakeProxy)
    monkeypatch.setattr(nostr_relay_module.websockets, "connect", fake_connect)

    result = asyncio.run(pool._open_connection("wss://fake.example"))

    assert result == "a-tor-connection"
    assert proxy_calls == [("socks5://127.0.0.1:9050", "fake.example", 443)]
    assert len(connect_calls) == 1
    url, kwargs = connect_calls[0]
    assert url == "wss://fake.example"
    assert kwargs["sock"] is fake_socket  # the proxy-tunneled socket was actually used


class FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def send(self, message):
        self.sent.append(message)


def test_pool_starts_with_only_the_gift_wrap_subscription():
    pool, _ = make_pool(our_pubkey_hex="bb" * 32)
    assert len(pool._subscriptions) == 1
    (sub_id, filter_dict), = pool._subscriptions.items()
    assert filter_dict == {"kinds": [1059], "#p": ["bb" * 32]}


def test_subscribe_adds_to_active_subscriptions_and_sends_req_to_connected_relays():
    pool, _ = make_pool()
    ws = FakeWebSocket()
    pool._connections["relay-a"] = ws

    geohash_filter = {"kinds": [20000, 20001], "#g": ["9q8yyk"]}
    asyncio.run(pool.subscribe("geo-sub", geohash_filter))

    assert pool._subscriptions["geo-sub"] == geohash_filter
    assert len(ws.sent) == 1
    assert json.loads(ws.sent[0]) == ["REQ", "geo-sub", geohash_filter]


def test_unsubscribe_removes_it_and_sends_close():
    pool, _ = make_pool()
    ws = FakeWebSocket()
    pool._connections["relay-a"] = ws
    asyncio.run(pool.subscribe("geo-sub", {"kinds": [20000]}))
    ws.sent.clear()

    asyncio.run(pool.unsubscribe("geo-sub"))

    assert "geo-sub" not in pool._subscriptions
    assert len(ws.sent) == 1
    assert json.loads(ws.sent[0]) == ["CLOSE", "geo-sub"]


def test_subscriptions_are_all_resent_on_reconnect():
    # Exercises the actual _connection_loop path (not just subscribe()'s
    # direct send) using a fake connection object as an async context
    # manager and async iterator, to confirm every active subscription --
    # not just the always-on gift-wrap one -- gets REQ'd on (re)connect.
    pool, _ = make_pool(our_pubkey_hex="cc" * 32)
    pool._subscriptions["geo-sub"] = {"kinds": [20000], "#g": ["9q8"]}

    sent_reqs = []

    class FakeConnection:
        def __init__(self):
            self.sent = []

        async def send(self, message):
            self.sent.append(message)
            sent_reqs.append(message)

        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

    async def fake_open_connection(url):
        return FakeConnection()

    pool._open_connection = fake_open_connection
    pool._stopped = False

    async def run_one_iteration():
        # _connection_loop loops forever on failure/backoff -- run just the
        # connect-and-drain-empty-stream part once, then stop it.
        task = asyncio.create_task(pool._connection_loop("wss://fake.example"))
        await asyncio.sleep(0.05)
        pool._stopped = True
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_one_iteration())

    sub_ids_reqd = {json.loads(m)[1] for m in sent_reqs}
    assert sub_ids_reqd == {pool._sub_id, "geo-sub"}
