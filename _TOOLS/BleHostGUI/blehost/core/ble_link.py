"""The BLE central link: the only module that talks to bleak.

Features and protocol modules never hold a BleakClient. They use:
  - BleLink.gatt: a GattFacade with write_gatt_char / read_gatt_char / mtu_size,
    which reports every access to the traffic monitor;
  - BleLink.start_notify(), which reports every notification;
  - connect/disconnect hooks, run on the asyncio loop.

All coroutines here run on the AsyncRunner loop. State changes of the main
link (ctx.link) are posted to the EventBus (LINK_STATE) for the Tk side. A
feature that needs links of its own (the Pairing page talks to two devices at
once) makes more BleLinks with primary=False and a label: they post no
LINK_STATE, and their traffic is tagged with the label.
"""

import enum
import sys
from dataclasses import dataclass, field

from .event_bus import LINK_STATE, LOG

CCCD_NOTIFY = b"\x01\x00"


class LinkState(enum.Enum):
    IDLE = "Idle"
    SCANNING = "Scanning"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    DISCONNECTING = "Disconnecting"


@dataclass
class ScanResult:
    address: str
    name: str
    rssi: int
    service_uuids: list = field(default_factory=list)


class GattFacade:
    """The subset of BleakClient that protocol code uses, with traffic capture."""

    def __init__(self, client, tap, label: str = ""):
        self._client = client
        self._tap = tap
        self._label = label

    @property
    def mtu_size(self) -> int:
        return self._client.mtu_size

    async def write_gatt_char(self, uuid, data, response: bool = False):
        self._tap.tx("WRITE" if response else "WNR", uuid, data, self._label)
        await self._client.write_gatt_char(uuid, data, response=response)

    async def read_gatt_char(self, uuid) -> bytes:
        data = bytes(await self._client.read_gatt_char(uuid))
        self._tap.rx("READ", uuid, data, self._label)
        return data

    def has_characteristic(self, uuid) -> bool:
        return self._client.services.get_characteristic(uuid) is not None


class BleLink:
    def __init__(self, bus, tap, label: str = "", primary: bool = True):
        self._bus = bus
        self._tap = tap
        self.label = label              # tags this link's traffic ("" for the main link)
        self.primary = primary          # only the main link drives the window (LINK_STATE)
        self._devices = {}              # address -> BLEDevice from the last scan
        self._client = None
        self.gatt: GattFacade | None = None
        self.state = LinkState.IDLE
        self.info = {}
        self._connect_hooks = []
        self._disconnect_hooks = []
        self._fast_link = None          # (WinRT device, changed-event token, request)

    # ---- hooks -------------------------------------------------------------
    def add_connect_hook(self, coro_fn):
        """await coro_fn(link) after connecting, before the state becomes CONNECTED.
        An exception is logged and does not drop the link."""
        self._connect_hooks.append(coro_fn)

    def add_disconnect_hook(self, fn):
        """fn(link, reason) on the asyncio loop once the link is gone."""
        self._disconnect_hooks.append(fn)

    # ---- state -------------------------------------------------------------
    @property
    def connected(self) -> bool:
        return self.state == LinkState.CONNECTED

    def _set_state(self, state: LinkState, **info):
        self.state = state
        self.info = info
        if self.primary:
            self._bus.post(LINK_STATE, (state, dict(info)))

    def _info(self, op: str, note: str):
        self._tap.info(op, f"[{self.label}] {note}" if self.label else note)

    def _log(self, level, text):
        self._bus.post(LOG, (level, text))

    # ---- scan --------------------------------------------------------------
    async def scan(self, timeout: float = 5.0) -> list:
        from bleak import BleakScanner

        self._set_state(LinkState.SCANNING)
        self._info("SCAN", f"scanning {timeout:.0f} s")
        try:
            found = await BleakScanner.discover(timeout=timeout, return_adv=True)
        finally:
            self._set_state(LinkState.IDLE)
        self._devices = {}
        results = []
        for addr, (dev, adv) in found.items():
            self._devices[addr] = dev
            results.append(ScanResult(addr, adv.local_name or dev.name or "", adv.rssi,
                                      [u.lower() for u in adv.service_uuids]))
        self._info("SCAN", f"{len(results)} device(s) found")
        return results

    # ---- connect / disconnect ----------------------------------------------
    async def connect(self, address: str, name: str = "", timeout: float = 15.0):
        from bleak import BleakClient

        if self._client is not None:
            raise RuntimeError("already connected")
        target = self._devices.get(address, address)
        self._set_state(LinkState.CONNECTING, address=address, name=name)
        self._info("CONNECT", f"connecting to {name or '?'} [{address}]")
        client = BleakClient(target, disconnected_callback=self._on_bleak_disconnect, timeout=timeout)
        try:
            await client.connect()
        except BaseException:
            self._set_state(LinkState.IDLE)
            raise
        self._client = client
        self.gatt = GattFacade(client, self._tap, self.label)
        self._info("CONNECT", f"connected, ATT MTU {client.mtu_size}")
        self._request_fast_link(client)
        for hook in self._connect_hooks:
            try:
                await hook(self)
            except Exception as e:
                self._log("warn", f"connect hook {getattr(hook, '__qualname__', hook)}: {e}")
        if self._client is client:          # the link can drop while the hooks run
            self._set_state(LinkState.CONNECTED, address=address, name=name, mtu=client.mtu_size)

    async def disconnect(self):
        client = self._client
        if client is None:
            return
        self._set_state(LinkState.DISCONNECTING, **self.info)
        try:
            await client.disconnect()
        finally:
            self._teardown(client, "disconnected")

    def _on_bleak_disconnect(self, client):
        # bleak calls this on the loop for both local and remote disconnects
        self._teardown(client, "link lost")

    def _teardown(self, client, reason: str):
        if self._client is not client:
            return                          # already torn down
        self._client = None
        self.gatt = None
        self._release_fast_link()
        self._info("DISCONNECT", reason)
        for hook in self._disconnect_hooks:
            try:
                hook(self, reason)
            except Exception as e:
                self._log("warn", f"disconnect hook: {e}")
        self._set_state(LinkState.IDLE, reason=reason)

    # ---- connection parameters (Windows 11) --------------------------------
    def _request_fast_link(self, client):
        """Ask Windows for its ThroughputOptimized connection parameters (15 ms).

        After service discovery Windows settles on its Balanced interval (30-60 ms,
        45 ms in practice), which caps an upload at about 10 KB/s. The request holds
        only while its object is open, so it is kept until the link goes down.
        Failure is logged and never drops the link.
        """
        if sys.platform != "win32":
            return
        try:
            from winrt.windows.devices.bluetooth import (
                BluetoothLEPreferredConnectionParameters as Params)

            # bleak internals: the WinRT BluetoothLEDevice behind the BleakClient
            device = getattr(getattr(client, "_backend", None), "_requester", None)
            if device is None:
                self._log("warn", "connection parameters: WinRT device not found in bleak")
                return

            def on_changed(sender, _args):          # WinRT thread; the tap only posts
                self._info("CONN", self._describe_params(sender.get_connection_parameters()))

            token = device.add_connection_parameters_changed(on_changed)
            request = device.request_preferred_connection_parameters(Params.throughput_optimized)
            self._fast_link = (device, token, request)
            self._log("info", f"connection parameters: requested throughput-optimized, "
                              f"{request.status.name.lower()}; now "
                              f"{self._describe_params(device.get_connection_parameters())}")
        except Exception as e:                      # e.g. Windows 10: API not present
            self._log("warn", f"connection parameters: request not possible ({e})")

    def _release_fast_link(self):
        if self._fast_link is None:
            return
        device, token, request = self._fast_link
        self._fast_link = None
        for release in (request.close, lambda: device.remove_connection_parameters_changed(token)):
            try:
                release()
            except Exception:
                pass                                # bleak may have closed the device already

    @staticmethod
    def _describe_params(p) -> str:
        return (f"interval {p.connection_interval * 1.25:g} ms, latency {p.connection_latency}, "
                f"timeout {p.link_timeout * 10} ms")

    # ---- GATT --------------------------------------------------------------
    @property
    def mtu_size(self) -> int:
        return self._client.mtu_size if self._client else 0

    async def start_notify(self, uuid: str, callback):
        """Subscribe; callback(handle, data) runs on the loop after the notification
        is reported to the traffic monitor."""
        tap = self._tap
        label = self.label

        def wrapped(sender, data):
            tap.rx("NOTIFY", uuid, data, label)
            callback(sender, data)

        tap.tx("CCCD", uuid, CCCD_NOTIFY, f"[{label}] subscribe" if label else "subscribe")
        await self._client.start_notify(uuid, wrapped)

    async def stop_notify(self, uuid: str):
        self._tap.tx("CCCD", uuid, b"\x00\x00", f"[{self.label}] unsubscribe" if self.label else "unsubscribe")
        await self._client.stop_notify(uuid)

    # ---- security ----------------------------------------------------------
    # The PC pairs only after host authentication (protocols/host_auth.py), with
    # LE SC passkey entry and the passkey the handshake derived; it is then the
    # device's trusted host, and Windows re-encrypts the link with the stored
    # keys on every later connection. Device-to-device pairing is orchestrated
    # over the Pairing service (protocols/pairing.py, features/pairing.py).
    def _require_client(self):
        if self._client is None:
            raise RuntimeError("not connected")
        return self._client

    async def pair_with_pin(self, pin: int) -> str:
        """Pair with the device, entering pin (core/winrt_pairing.py)."""
        from . import winrt_pairing

        client = self._require_client()
        self._info("PAIR", "pairing, passkey entry")
        level = await winrt_pairing.pair_with_pin(client, pin, log=lambda t: self._log("info", t))
        self._info("PAIR", f"paired ({level})")
        return level

    async def unpair(self) -> str:
        """Forget the device's keys on this PC (the device keeps its own)."""
        from . import winrt_pairing

        result = await winrt_pairing.unpair(self._require_client())
        self._info("PAIR", f"keys forgotten on this PC ({result})")
        return result

    async def is_paired(self) -> bool:
        from . import winrt_pairing

        return await winrt_pairing.is_paired(self._require_client())
