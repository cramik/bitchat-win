"""BLE central role: scan for bitchat peripherals, connect, subscribe, write.

Uses bleak (which itself drives the WinRT central APIs on Windows) so we
don't have to touch WinRT directly for this half. Phase 2 (ble_peripheral.py)
is where we become discoverable/connectable ourselves via a hand-written
WinRT GattServiceProvider, since bleak has no peripheral/server support.

Real bitchat UUIDs, from bitchat-reference/bitchat/Services/BLE/BLEService.swift.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice

from . import fragment
from .mesh import MeshEngine

logger = logging.getLogger("bitchat.ble_central")

SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
CHARACTERISTIC_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

# A fragment.FRAGMENT_CHUNK_SIZE (469) chunk wrapped in a FRAGMENT packet's
# header+senderID+payload-preamble comes out to ~504 bytes, this ceiling
# has to clear that plus some margin, not just fit an unfragmented packet.
# Real phones negotiated mtu=517 (max_write_without_response=514) in
# testing, so 520 stays safely below what fragmentation actually produces.
MAX_WRITE_BYTES = 520

ANNOUNCE_INTERVAL_SECONDS = 30

# Cooldown after a failed connection attempt before retrying the same
# address. Without this, a device that reliably fails (e.g. Windows/WinRT's
# "Unreachable" service-discovery races, or a device that's mid-rotation of
# its random BLE address) gets re-attempted on every single advertisement
# packet, observed hammering one address 60 times in 3 minutes, saturating
# the radio and starving other BLE activity (including our own peripheral
# advertising) in testing.
RECONNECT_BACKOFF_SECONDS = 30.0

# Ceiling on a single write_gatt_char call. Live testing observed a write to
# a degrading link hang for ~20s before failing; without a hard timeout that
# stalls this client's writes indefinitely and (before _relay was made
# concurrent) delayed delivery to every other connected client too.
WRITE_TIMEOUT_SECONDS = 5.0


class BLECentral:
    def __init__(self, mesh: MeshEngine) -> None:
        self.mesh = mesh
        self.mesh.relay_sinks.append(self._relay)
        self._clients: Dict[str, BleakClient] = {}
        self._connecting: set[str] = set()
        self._failed_until: Dict[str, float] = {}
        # `_connect()` runs as an independent top-level task (spawned from the
        # scan detection_callback, not awaited by `run()`), so cancelling the
        # `run()` task alone never touches one still mid-`client.connect()`.
        # Left to just get abandoned when the event loop closes, WinRT's
        # native connection request doesn't get a clean cancel/disconnect,
        # observed live to degrade the adapter until a driver reset, after
        # repeated quick process restarts each leaving one behind. Tracked
        # here so shutdown() can cancel and await them properly instead.
        self._connect_tasks: Dict[str, asyncio.Task] = {}

    def _in_backoff(self, address: str) -> bool:
        until = self._failed_until.get(address)
        return until is not None and time.monotonic() < until

    async def _safe_write(self, client: BleakClient, raw: bytes) -> None:
        if len(raw) > MAX_WRITE_BYTES:
            logger.warning(
                "dropping %d-byte outbound packet to %s (no fragmentation support yet)",
                len(raw),
                client.address,
            )
            return
        logger.debug("writing %d bytes to %s: %s", len(raw), client.address, raw.hex())
        try:
            # response=True (not the write-without-response used before): a
            # dropped write-without-response gets no error on either end,
            # this trades a little latency for an actual ATT-level ack/error,
            # which is the only way to tell "sent" from "silently vanished."
            # NOTE: even an ATT-level ack only proves the write reached the
            # peripheral's write-handler dispatch, not that the app's own
            # parsing/validation accepted it, see diagnostic notes.
            #
            # WRITE_TIMEOUT_SECONDS matters more than it looks: without it, a
            # write to one degrading/out-of-range link can hang for ~20s
            # (observed live), and since _relay below used to await each
            # client sequentially, that single stuck write delayed delivery
            # to every *other* client by the same ~20s, which is exactly
            # how a second fragment of a message ended up racing the
            # connection teardown on /quit instead of arriving in time.
            await asyncio.wait_for(
                client.write_gatt_char(CHARACTERISTIC_UUID, raw, response=True),
                timeout=WRITE_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 - BLE stacks raise all sorts of things
            # One-line summary always visible; full traceback only under
            # BITCHAT_DEBUG=1, a link going stale mid-session is routine
            # BLE flakiness, not something worth a wall of text by default.
            logger.warning("write of %d bytes to %s failed: %s", len(raw), client.address, exc)
            logger.debug("write failure detail", exc_info=True)

    async def _write_packets(self, client: BleakClient, packets: List[bytes]) -> None:
        for index, raw in enumerate(packets):
            if index > 0:
                await asyncio.sleep(fragment.FRAGMENT_SPACING_SECONDS)
            await self._safe_write(client, raw)

    async def _relay(self, raw: bytes, exclude_link_id: Optional[str]) -> None:
        # Concurrent, not sequential: a slow/stuck write to one client must
        # not delay delivery to every other client (see WRITE_TIMEOUT_SECONDS
        # note above for what that used to cause).
        targets = [client for address, client in self._clients.items() if address != exclude_link_id]
        if targets:
            await asyncio.gather(*(self._safe_write(client, raw) for client in targets))

    async def broadcast(self, raw: bytes) -> None:
        await self._relay(raw, exclude_link_id=None)

    def _on_disconnect(self, address: str):
        def handler(_client: BleakClient) -> None:
            self._clients.pop(address, None)
            logger.info("disconnected from %s", address)

        return handler

    def _on_notify(self, address: str):
        def handler(_sender, data: bytearray) -> None:
            asyncio.create_task(self.mesh.handle_incoming(bytes(data), link_id=address))

        return handler

    async def _connect(self, device: BLEDevice) -> None:
        address = device.address
        if address in self._clients or address in self._connecting or self._in_backoff(address):
            return
        self._connecting.add(address)
        try:
            client = BleakClient(device, disconnected_callback=self._on_disconnect(address))
            await client.connect(timeout=10.0)
            await client.start_notify(CHARACTERISTIC_UUID, self._on_notify(address))
            self._clients[address] = client
            char = client.services.get_characteristic(CHARACTERISTIC_UUID)
            max_write = getattr(char, "max_write_without_response_size", None) if char else None
            logger.info(
                "connected to bitchat peer at %s (mtu=%s, max_write_without_response=%s)",
                address,
                getattr(client, "mtu_size", "unknown"),
                max_write,
            )
            await self._write_packets(client, self.mesh.build_announce_packet())
        except Exception as exc:  # noqa: BLE001
            # One-line summary always visible; full traceback only under
            # BITCHAT_DEBUG=1, a device rotating its BLE address or
            # briefly going out of range is routine, not exceptional.
            logger.warning("failed to connect to %s: %s", address, exc)
            logger.debug("connect failure detail", exc_info=True)
            self._failed_until[address] = time.monotonic() + RECONNECT_BACKOFF_SECONDS
        finally:
            self._connecting.discard(address)
            self._connect_tasks.pop(address, None)

    async def _cancel_pending_connects(self) -> None:
        """Cancel and await every still-in-flight `_connect()` task. Must run
        before the process exits, an abandoned (never cancelled, never
        awaited) task doing `await client.connect(...)` leaves WinRT's
        native connection request dangling instead of properly aborted."""
        tasks = list(self._connect_tasks.values())
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._connect_tasks.clear()
        self._connecting.clear()

    async def run(self) -> None:
        def detection_callback(device: BLEDevice, _adv_data) -> None:
            address = device.address
            if address in self._clients or address in self._connecting or self._in_backoff(address):
                return
            self._connect_tasks[address] = asyncio.create_task(self._connect(device))

        scanner = BleakScanner(detection_callback=detection_callback, service_uuids=[SERVICE_UUID])
        await scanner.start()
        logger.info("scanning for bitchat peers (service %s)...", SERVICE_UUID)
        try:
            while True:
                await asyncio.sleep(ANNOUNCE_INTERVAL_SECONDS)
                # send_packets/broadcast_to_all (not self.broadcast) so this
                # reaches peripheral-side subscribers too, not just our own
                # outbound central connections.
                await self.mesh.send_packets(self.mesh.build_announce_packet())
        finally:
            await scanner.stop()
            await self._cancel_pending_connects()
            for client in list(self._clients.values()):
                try:
                    await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass

    async def shutdown(self) -> None:
        await self._cancel_pending_connects()
        if self._clients:
            for leave in self.mesh.build_leave_packet():
                await self.broadcast(leave)
        for client in list(self._clients.values()):
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                pass
