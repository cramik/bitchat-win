"""BLE peripheral role: a real WinRT GATT server advertising the bitchat
service, so phones scanning *us* can connect in rather than the reverse.

This is what turns Phase 1's central-only client into an actual dual-role
mesh node. bleak has no peripheral/server support on any platform, so this
is hand-written against the WinRT `GenericAttributeProfile` + `Advertisement`
namespaces (the same projection bleak uses internally for its Windows
central backend, exposed to Python by the `winrt-Windows.*` packages).

Verified interactively against this machine's real Bluetooth radio while
building this:
  - `BluetoothAdapter.get_default_async()` reports
    `is_peripheral_role_supported = True` here.
  - `GattServiceProvider.create_async(...)` and
    `service.create_characteristic_async(...)` both succeed (status SUCCESS)
    for the exact bitchat service/characteristic UUIDs.
  - `DataWriter`/`DataReader` <-> `bytes` round-trips correctly.
  - BUT: `start_advertising_with_parameters(...)` transitions straight to
    `ABORTED`, and, to isolate whether this was a GATT-specific issue,
    a bare `BluetoothLEAdvertisementPublisher.start()` (no GATT service
    involved at all) *also* aborts immediately on this machine. That means
    the failure is a general "this radio/driver refuses to broadcast any
    LE advertisement," not a bug in the GATT server wiring below. See
    README "Known Issues" for what to check (Windows discoverability
    setting, Bluetooth driver, a different adapter).

Because of that, `BLEPeripheral.start()` is written to raise a clear
`RuntimeError` on failure rather than fail silently, and callers (cli.py)
treat it as optional: central-role (Phase 1) keeps working even if this
never gets past `create_async`.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Optional

from winrt.windows.devices.bluetooth.genericattributeprofile import (
    GattCharacteristicProperties,
    GattCommunicationStatus,
    GattLocalCharacteristic,
    GattLocalCharacteristicParameters,
    GattProtectionLevel,
    GattServiceProvider,
    GattServiceProviderAdvertisingParameters,
    GattWriteOption,
)
from winrt.windows.storage.streams import DataReader, DataWriter

from . import fragment
from .mesh import MeshEngine

logger = logging.getLogger("bitchat.ble_peripheral")

SERVICE_UUID = uuid.UUID("f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c")
CHARACTERISTIC_UUID = uuid.UUID("a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d")

# Every subscribed central shares this single logical link for dedup/relay
# purposes, WinRT gives us per-write GattSession objects, but attributing
# "which of N subscribed centrals sent this write" to a stable link id would
# need session bookkeeping this MVP skips. Practical effect: a packet we
# relay back out over the peripheral characteristic can loop back to the
# same central that sent it; that central's own dedup cache drops it as a
# repeat, so this is a minor inefficiency, not a correctness bug.
PERIPHERAL_LINK_ID = "peripheral"


def _bytes_to_buffer(data: bytes):
    writer = DataWriter()
    writer.write_bytes(data)
    return writer.detach_buffer()


def _buffer_to_bytes(buffer) -> bytes:
    reader = DataReader.from_buffer(buffer)
    out = bytearray(reader.unconsumed_buffer_length)
    reader.read_bytes(out)
    return bytes(out)


class BLEPeripheral:
    def __init__(self, mesh: MeshEngine) -> None:
        self.mesh = mesh
        self._provider: Optional[GattServiceProvider] = None
        self._characteristic: Optional[GattLocalCharacteristic] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subscribed_count = 0

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()

        result = await GattServiceProvider.create_async(SERVICE_UUID)
        if result.error != GattCommunicationStatus.SUCCESS:
            raise RuntimeError(f"GattServiceProvider.create_async failed: {result.error}")
        self._provider = result.service_provider

        params = GattLocalCharacteristicParameters()
        params.characteristic_properties = (
            GattCharacteristicProperties.WRITE
            | GattCharacteristicProperties.WRITE_WITHOUT_RESPONSE
            | GattCharacteristicProperties.NOTIFY
        )
        params.write_protection_level = GattProtectionLevel.PLAIN

        char_result = await self._provider.service.create_characteristic_async(
            CHARACTERISTIC_UUID, params
        )
        if char_result.error != GattCommunicationStatus.SUCCESS:
            raise RuntimeError(f"create_characteristic_async failed: {char_result.error}")
        self._characteristic = char_result.characteristic
        self._characteristic.add_write_requested(self._on_write_requested)
        self._characteristic.add_subscribed_clients_changed(self._on_subscribed_clients_changed)

        adv_params = GattServiceProviderAdvertisingParameters()
        adv_params.is_connectable = True
        adv_params.is_discoverable = True
        self._provider.add_advertisement_status_changed(self._on_advertisement_status_changed)
        self._provider.start_advertising_with_parameters(adv_params)

        self.mesh.relay_sinks.append(self._relay)
        logger.info("peripheral GATT server advertising (service %s)", SERVICE_UUID)

    def _on_advertisement_status_changed(self, sender, _args) -> None:
        logger.info("peripheral advertisement status: %s", sender.advertisement_status)

    def _on_write_requested(self, _sender, args) -> None:
        # Fires on a WinRT/COM callback thread, not our asyncio loop thread.
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._handle_write(args), self._loop)

    async def _handle_write(self, args) -> None:
        try:
            request = await args.get_request_async()
        except Exception as exc:  # noqa: BLE001
            logger.debug("get_request_async failed: %s", exc)
            return
        raw = _buffer_to_bytes(request.value)
        if request.option == GattWriteOption.WRITE_WITH_RESPONSE:
            try:
                request.respond()
            except Exception:  # noqa: BLE001
                pass
        await self.mesh.handle_incoming(raw, link_id=PERIPHERAL_LINK_ID)

    def _on_subscribed_clients_changed(self, sender, _args) -> None:
        # Fires on a WinRT/COM callback thread, not our asyncio loop thread.
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(self._handle_subscription_change(sender), self._loop)

    async def _handle_subscription_change(self, characteristic) -> None:
        try:
            count = len(characteristic.subscribed_clients)
        except Exception:  # noqa: BLE001
            return
        if count > self._subscribed_count:
            # A new central just subscribed to notifications, proactively
            # announce ourselves rather than waiting for them to write
            # first. Real bitchat peripherals do this; without it, a fresh
            # subscriber (including a plain BLE scanner like nRF Connect)
            # sees total silence on the characteristic until we happen to
            # send something else, which looks exactly like a broken
            # peripheral even though discovery/connect/subscribe all worked.
            for index, announce in enumerate(self.mesh.build_announce_packet()):
                if index > 0:
                    await asyncio.sleep(fragment.FRAGMENT_SPACING_SECONDS)
                try:
                    await self._characteristic.notify_value_async(_bytes_to_buffer(announce))
                except Exception as exc:  # noqa: BLE001
                    logger.debug("failed to notify announce on new subscription: %s", exc)
        self._subscribed_count = count

    async def _relay(self, raw: bytes, exclude_link_id: Optional[str]) -> None:
        # We always notify all subscribed centrals, even when exclude_link_id
        # is PERIPHERAL_LINK_ID (i.e. this packet arrived from one of them),
        # see the PERIPHERAL_LINK_ID note above for why that's a deliberate,
        # documented tradeoff rather than a bug.
        if self._characteristic is None:
            return
        try:
            await self._characteristic.notify_value_async(_bytes_to_buffer(raw))
        except Exception as exc:  # noqa: BLE001
            logger.debug("notify_value_async failed: %s", exc)

    def stop(self) -> None:
        if self._provider is not None:
            try:
                self._provider.stop_advertising()
            except Exception:  # noqa: BLE001
                pass
