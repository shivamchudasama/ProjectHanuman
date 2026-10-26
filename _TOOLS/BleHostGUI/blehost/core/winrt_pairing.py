"""LE Secure Connections passkey entry from Windows (host authentication).

bleak's own pair() offers Windows only "confirm" (Just Works), which gives no
protection against someone in between. Host authentication derives a passkey
from its handshake (protocols/host_auth.py); here Windows pairs with
DevicePairingKinds.ProvidePin and answers its PairingRequested event with that
passkey. The device acts as DisplayOnly (it "shows" the derived passkey), the
PC enters it: LE SC passkey entry, authenticated, level 4, bonded.

Works on the BleakClient's WinRT device (bleak internals: client._backend.
_requester, a BluetoothLEDevice), as BleLink._request_fast_link does.
Windows only; elsewhere every call raises PairingUnavailable.
"""

import sys


class PairingUnavailable(Exception):
    """This PC cannot pair this way (not Windows, no WinRT, bleak changed)."""


class PairingFailed(Exception):
    """Windows reported a pairing result other than Paired. str() names it."""


def _device(client):
    device = getattr(getattr(client, "_backend", None), "_requester", None)
    if device is None:
        raise PairingUnavailable("the WinRT device behind the BLE link was not found (bleak changed?)")
    return device


def _enumeration():
    if sys.platform != "win32":
        raise PairingUnavailable("pairing with a passkey needs Windows (WinRT)")
    try:
        from winrt.windows.devices import enumeration
    except ImportError as e:
        raise PairingUnavailable(f"WinRT enumeration API not available ({e})") from None
    if enumeration is None:                     # a blocked module
        raise PairingUnavailable("WinRT enumeration API not available")
    return enumeration


async def _pairing(client):
    en = _enumeration()
    info = await en.DeviceInformation.create_from_id_async(_device(client).device_information.id)
    return en, info.pairing


async def _pairing_at(address: str):
    """The DevicePairing of a BLE address, without a link (the link may be the
    thing that fails: a board that lost its keys while Windows kept its own)."""
    en = _enumeration()
    try:
        from winrt.windows.devices.bluetooth import BluetoothLEDevice
    except ImportError as e:
        raise PairingUnavailable(f"WinRT Bluetooth API not available ({e})") from None
    try:
        raw = int(address.replace(":", "").replace("-", ""), 16)
    except ValueError:
        raise ValueError(f"not a Bluetooth address: {address!r}") from None
    device = await BluetoothLEDevice.from_bluetooth_address_async(raw)
    if device is None:
        return en, None
    return en, device.device_information.pairing


async def is_paired_address(address: str) -> bool:
    """Whether Windows holds pairing keys for this address."""
    _en, pairing = await _pairing_at(address)
    return bool(pairing is not None and pairing.is_paired)


async def unpair_address(address: str) -> str:
    """Forget this address's keys on this PC, without a link. Returns
    Windows' result name."""
    _en, pairing = await _pairing_at(address)
    if pairing is None or not pairing.is_paired:
        return "not_paired"
    result = await pairing.unpair_async()
    return result.status.name.lower()


async def is_paired(client) -> bool:
    _en, pairing = await _pairing(client)
    return bool(pairing.is_paired)


async def unpair(client) -> str:
    """Forget the device's keys on this PC. Returns Windows' result name."""
    _en, pairing = await _pairing(client)
    if not pairing.is_paired:
        return "not_paired"
    result = await pairing.unpair_async()
    return result.status.name.lower()


async def pair_with_pin(client, pin: int, log=print) -> str:
    """Pair with LE SC passkey entry, entering pin. Returns the protection
    level used (its name). Raises PairingFailed or PairingUnavailable."""
    if not 0 <= int(pin) <= 999999:
        raise ValueError("a passkey has six digits")
    en, pairing = await _pairing(client)
    kinds = en.DevicePairingKinds
    if pairing.is_paired:
        # Keys the device no longer has: a fresh pairing replaces them
        log("pairing: the PC holds old keys for this device; removing them first")
        await pairing.unpair_async()
    custom = pairing.custom
    asked = []
    errors = []

    def on_requested(_sender, args):            # WinRT thread
        asked.append(args.pairing_kind)
        try:
            if args.pairing_kind == kinds.PROVIDE_PIN:
                # pywinrt names the overloads: Accept(String pin) is
                # accept_with_pin(); accept() takes no argument
                args.accept_with_pin(f"{int(pin):06d}")
        except Exception as e:                  # lost on the WinRT thread otherwise
            errors.append(e)
        # anything else (confirm only, numeric comparison) is left unanswered:
        # Windows then fails the pairing, which is what must happen

    token = custom.add_pairing_requested(on_requested)
    try:
        result = await custom.pair_with_protection_level_async(
            kinds.PROVIDE_PIN, en.DevicePairingProtectionLevel.ENCRYPTION_AND_AUTHENTICATION)
    finally:
        custom.remove_pairing_requested(token)
    status = result.status
    if status not in (en.DevicePairingResultStatus.PAIRED, en.DevicePairingResultStatus.ALREADY_PAIRED):
        extra = f" (Windows asked for {', '.join(k.name for k in asked)})" if asked else ""
        if errors:
            extra += f"; answering it failed: {errors[0]!r}"
        raise PairingFailed(f"{status.name.lower()}{extra}")
    level = result.protection_level_used
    if level != en.DevicePairingProtectionLevel.ENCRYPTION_AND_AUTHENTICATION:
        raise PairingFailed(f"paired without authentication ({level.name.lower()})")
    return level.name.lower()
