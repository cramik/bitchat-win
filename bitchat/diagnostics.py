"""Pre-flight checks for BLE peripheral (GATT server) support on Windows.

Building bitchat-win surfaced a real, non-obvious failure mode: Windows can
silently abort *any* BLE advertisement, a full GATT server or even a bare
`BluetoothLEAdvertisementPublisher` with no GATT service at all, with
`BluetoothError.DISABLED_BY_POLICY`.

**What actually controls this (corrected from an earlier, wrong theory):**
the resolved value at
`HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Bluetooth\\AllowAdvertising`.
We initially assumed this mirrored the classic "Allow Bluetooth devices to
find this PC" Control Panel checkbox (`bthprops.cpl`), it does not: no
policy provider even claims this value, there's no Group Policy (ADMX)
definition for it on a stock Windows install, and toggling that checkbox
repeatedly never changed the registry value in testing. The only way found
to actually change it (short of real MDM enrollment) is an elevated
`Set-ItemProperty` write to that exact path, which `offer_elevated_fix()`
below does for you, behind a real UAC prompt you approve yourself. Even
after that write takes (confirmed via registry read), the *running*
Bluetooth stack did not immediately respect it in testing, a `bthserv`
restart (also done by `offer_elevated_fix()`) was needed before a live
advertising attempt actually succeeded, and a full reboot is a reasonable
fallback if even that doesn't take.

Static capability flags are not reliable for detecting any of this:
`BluetoothAdapter.is_peripheral_role_supported` reported `True` on hardware
that still refused to advertise for this exact policy reason. The only
trustworthy check is to actually try advertising for real and read the
`BluetoothError` off the abort.
"""
from __future__ import annotations

import asyncio
import ctypes
import logging
import subprocess
from dataclasses import dataclass
from typing import Optional

from winrt.windows.devices.bluetooth import BluetoothAdapter, BluetoothError
from winrt.windows.devices.bluetooth.advertisement import (
    BluetoothLEAdvertisement,
    BluetoothLEAdvertisementPublisher,
    BluetoothLEAdvertisementPublisherStatus,
    BluetoothLEManufacturerData,
)
from winrt.windows.storage.streams import DataWriter

logger = logging.getLogger("bitchat.diagnostics")

# 0xFFFF is the Bluetooth SIG's reserved "for testing" company id, never a
# real vendor, appropriate for a throwaway probe payload we tear down
# within a couple seconds either way.
_PROBE_COMPANY_ID = 0xFFFF

ALLOW_ADVERTISING_REGISTRY_PATH = r"HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth"
ALLOW_ADVERTISING_VALUE_NAME = "AllowAdvertising"

_ALLOW_ADVERTISING_FIX = (
    "Windows is blocking Bluetooth LE advertising via a policy value at\n"
    f"  {ALLOW_ADVERTISING_REGISTRY_PATH}\\{ALLOW_ADVERTISING_VALUE_NAME}\n"
    "(not the classic Bluetooth Control Panel checkbox, despite how similar "
    "issues are usually described online, that checkbox does not touch "
    "this value; nothing on an unmanaged machine does by default).\n"
    "We can fix this for you: it takes one elevated (Administrator) action "
    "you approve via a normal Windows UAC prompt, we never bypass that "
    "prompt or do this silently.\n"
    "If you'd rather do it yourself in an elevated PowerShell:\n"
    f'  Set-ItemProperty -Path "{ALLOW_ADVERTISING_REGISTRY_PATH}" '
    f'-Name "{ALLOW_ADVERTISING_VALUE_NAME}" -Value 1 -Type DWord\n'
    "  Restart-Service bthserv -Force\n"
    "A full reboot is the fallback if the service restart alone doesn't "
    "make a live advertising attempt succeed."
)

_INSTRUCTIONS_BY_ERROR = {
    BluetoothError.DISABLED_BY_POLICY: _ALLOW_ADVERTISING_FIX,
    BluetoothError.RADIO_NOT_AVAILABLE: (
        "Windows reports no Bluetooth radio is available right now. Check "
        "that Bluetooth is turned on (Settings > Bluetooth & devices) and "
        "that the adapter shows healthy in Device Manager."
    ),
    BluetoothError.NOT_SUPPORTED: (
        "This adapter/driver reports it does not support advertising at "
        "all. Some Bluetooth adapters genuinely lack LE peripheral "
        "support regardless of settings, a different USB BLE adapter "
        "may be required."
    ),
    BluetoothError.RESOURCE_IN_USE: (
        "Another app, or a previous bitchat-win instance that didn't "
        "shut down cleanly, is already using the radio for advertising. "
        "Close other Bluetooth peripheral/beacon apps and try again."
    ),
    BluetoothError.DISABLED_BY_USER: (
        "Bluetooth advertising has been explicitly disabled for this "
        "user account. Check Settings > Bluetooth & devices."
    ),
    BluetoothError.CONSENT_REQUIRED: (
        "Windows is asking for user consent it never surfaced a prompt "
        "for. Try running bitchat-win from an interactive desktop session "
        "rather than a background/service/remote context."
    ),
}


@dataclass
class PeripheralCapabilityResult:
    ok: bool
    reason: str
    instructions: Optional[str] = None
    # True specifically for the DISABLED_BY_POLICY / AllowAdvertising case,
    # the one case with an actual automated fix (offer_elevated_fix()).
    fixable_by_elevation: bool = False


def _bytes_to_buffer(data: bytes):
    writer = DataWriter()
    writer.write_bytes(data)
    return writer.detach_buffer()


async def check_peripheral_capability(timeout: float = 3.0) -> PeripheralCapabilityResult:
    """Actually attempts a ~1-2 second throwaway advertisement to find out
    *why* peripheral mode would fail, rather than trusting static capability
    flags (see module docstring for why those lie)."""
    adapter = await BluetoothAdapter.get_default_async()
    if adapter is None:
        return PeripheralCapabilityResult(
            ok=False,
            reason="No Bluetooth adapter found on this machine.",
            instructions="Check Device Manager for a Bluetooth radio and that drivers are installed.",
        )
    if not adapter.is_low_energy_supported:
        return PeripheralCapabilityResult(ok=False, reason="This adapter does not support Bluetooth LE at all.")
    if not adapter.is_peripheral_role_supported:
        return PeripheralCapabilityResult(
            ok=False,
            reason="This adapter reports it does not support the LE peripheral role.",
            instructions="A different Bluetooth adapter (e.g. a dedicated USB BLE dongle) may be required.",
        )

    advertisement = BluetoothLEAdvertisement()
    mfg = BluetoothLEManufacturerData()
    mfg.company_id = _PROBE_COMPANY_ID
    mfg.data = _bytes_to_buffer(b"bitchat-win-probe")
    advertisement.manufacturer_data.append(mfg)
    publisher = BluetoothLEAdvertisementPublisher(advertisement)

    loop = asyncio.get_running_loop()
    outcome_future: "asyncio.Future[PeripheralCapabilityResult]" = loop.create_future()

    def _resolve(value: PeripheralCapabilityResult) -> None:
        # Runs on the event loop thread (via call_soon_threadsafe), the
        # done() check must happen here, not on the calling COM thread,
        # otherwise back-to-back status events (e.g. STARTED immediately
        # followed by our own stop()-triggered ABORTED) can both pass an
        # earlier done()==False check before either has actually resolved
        # the future, and the second set_result raises InvalidStateError.
        if not outcome_future.done():
            outcome_future.set_result(value)

    def on_status_changed(sender, args) -> None:
        status = sender.status
        if status == BluetoothLEAdvertisementPublisherStatus.STARTED:
            loop.call_soon_threadsafe(
                _resolve, PeripheralCapabilityResult(ok=True, reason="Advertising started successfully.")
            )
        elif status == BluetoothLEAdvertisementPublisherStatus.ABORTED:
            error = args.error
            error_name = getattr(error, "name", str(error))
            loop.call_soon_threadsafe(
                _resolve,
                PeripheralCapabilityResult(
                    ok=False,
                    reason=f"Advertising aborted ({error_name}).",
                    instructions=_INSTRUCTIONS_BY_ERROR.get(error),
                    fixable_by_elevation=(error == BluetoothError.DISABLED_BY_POLICY),
                ),
            )

    token = publisher.add_status_changed(on_status_changed)
    try:
        publisher.start()
        try:
            outcome = await asyncio.wait_for(outcome_future, timeout=timeout)
        except asyncio.TimeoutError:
            outcome = PeripheralCapabilityResult(
                ok=False,
                reason="Advertising neither started nor aborted within the timeout, unknown state.",
            )
    finally:
        try:
            publisher.remove_status_changed(token)
        except Exception:  # noqa: BLE001
            pass
        try:
            publisher.stop()
        except Exception:  # noqa: BLE001
            pass
    return outcome


def offer_elevated_fix() -> bool:
    """Launches an elevated PowerShell (via the `runas` verb, which shows a
    real Windows UAC consent prompt, the user approves or denies it
    themselves; this never bypasses that prompt) that sets
    AllowAdvertising=1 and restarts the `bthserv` service, since testing
    showed the registry write alone isn't enough, the running Bluetooth
    stack only picked up the change after a service restart.

    Returns whether the elevation request was successfully *launched*,
    not whether the user approved the UAC prompt or whether the fix
    ultimately worked. Restarting `bthserv` briefly disconnects every
    paired Bluetooth device (mice, keyboards, headsets, phones); the
    PowerShell window says so and pauses before running it."""
    script = (
        "Write-Host 'Setting Bluetooth AllowAdvertising policy...'; "
        f"Set-ItemProperty -Path '{ALLOW_ADVERTISING_REGISTRY_PATH}' "
        f"-Name '{ALLOW_ADVERTISING_VALUE_NAME}' -Value 1 -Type DWord; "
        "Write-Host 'Restarting the Bluetooth service "
        "(this will briefly disconnect paired Bluetooth devices)...'; "
        "Restart-Service bthserv -Force; "
        "Write-Host 'Done. You can close this window.'; "
        "Start-Sleep -Seconds 5"
    )
    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "powershell.exe", f'-NoProfile -Command "{script}"', None, 1
        )
        # ShellExecuteW returns a value > 32 on success; anything else
        # (including the user clicking "No" on the UAC prompt, which
        # yields 5/ERROR_ACCESS_DENIED) means the elevated process never ran.
        return result > 32
    except Exception as exc:  # noqa: BLE001
        logger.debug("could not launch elevated fix: %s", exc)
        return False


def open_bluetooth_settings() -> bool:
    """Best-effort: launch the classic Bluetooth control panel applet.
    Kept for general Bluetooth troubleshooting, NOT a fix for
    AllowAdvertising specifically (see module docstring: that checkbox was
    confirmed not to touch this policy value). Prefer `offer_elevated_fix()`
    for the actual DISABLED_BY_POLICY case."""
    try:
        subprocess.Popen(["control.exe", "bthprops.cpl"])
        return True
    except Exception as exc:  # noqa: BLE001
        logger.debug("could not launch bthprops.cpl: %s", exc)
        return False
