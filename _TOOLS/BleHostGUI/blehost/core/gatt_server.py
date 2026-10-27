"""The PC's own SETU GATT service, so the device can send to the PC.

A SETU transfer goes from the GATT client to the side that hosts DATA and
CTRL (_DOC/SETU/PROTOCOL.md). bleak is a GATT client only, so for the
device -> PC direction (the CSR during provisioning) the PC hosts the service
itself, and the device attaches its SETU Client role to it over the same
connection. The service uses the same UUIDs as the device's (base from the
settings): DATA (Write Without Response), CTRL (Notify) and CAPS (Read).

PcGattServer is the SETUReceiver (setu_receiver.py) plus a backend
that hosts the attributes. WinRtBackend, the only code in the tool that uses
the WinRT GATT *server* API, needs Windows 10/11 and an adapter that supports
the peripheral role; it uses the winrt packages bleak already installs.
(bless, the usual Python GATT server library, cannot be installed next to
bleak >= 1 on Python 3.12: its winrt pins conflict.)

Several boards: Windows publishes the service to every board the PC is
connected to. The backend reports which board wrote (the write's GATT
session) and which boards subscribe, and PcGattServer takes writes from the
active device only (set_peer(), core/devices.py) and notifies only it.

Threading: WinRT raises its events on its own threads. The backend hands each
written value to the asyncio loop in arrival order; the receiver runs on the
loop only, as BleLink's code does.
"""

import asyncio
import re
import sys
import uuid

import setu_client
from setu_receiver import SETUReceiver

CAPS = bytes([2, setu_client.MAX_FRAME, setu_client.WINDOW, 0])    # as the device's gv_SETUS_GetCaps()


class GattServerUnavailable(RuntimeError):
    """This PC cannot host the service (OS, adapter or driver)."""


_ADDRESS = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})$")


def session_address(session) -> str:
    """The board's address from a WinRT GattSession ('BluetoothLE#BluetoothLE
    <adapter>-<board>' device ID), upper case; '' if it cannot be told."""
    try:
        m = _ADDRESS.search(str(session.device_id.id))
    except Exception:                               # noqa: BLE001 - unknown is ''
        return ""
    return m.group(1).upper() if m else ""


class WinRtBackend:
    """Hosts the SETU service with WinRT's GattServiceProvider.

    on_write(data: bytes, sender: str) and on_subscribed(addresses: list) are
    called on `loop`; an address is '' where WinRT does not tell it.
    """

    def __init__(self, base: str, loop, on_write, on_subscribed, log):
        self.base = base
        self.loop = loop
        self.on_write = on_write
        self.on_subscribed = on_subscribed
        self.log = log
        self._provider = None
        self._ctrl = None
        self._tokens = []
        self._writes: asyncio.Queue = asyncio.Queue()
        self._pump = None

    def _uuid(self, char_id: int):
        return uuid.UUID(setu_client.char_uuid(char_id, self.base))

    async def start(self):
        if sys.platform != "win32":
            raise GattServerUnavailable("hosting a GATT service needs Windows (WinRT)")
        try:
            from winrt.windows.devices.bluetooth import BluetoothAdapter, BluetoothError
            from winrt.windows.devices.bluetooth.genericattributeprofile import (
                GattCharacteristicProperties as P, GattLocalCharacteristicParameters,
                GattProtectionLevel, GattServiceProvider, GattServiceProviderAdvertisingParameters)
            from winrt.windows.storage.streams import DataWriter
        except ImportError as e:
            raise GattServerUnavailable(f"WinRT Bluetooth packages missing ({e})") from None

        adapter = await BluetoothAdapter.get_default_async()
        if adapter is None or not adapter.is_peripheral_role_supported:
            raise GattServerUnavailable("the Bluetooth adapter does not support the peripheral role")

        res = await GattServiceProvider.create_async(self._uuid(0))
        if res.error != BluetoothError.SUCCESS:
            raise GattServerUnavailable(f"GattServiceProvider: {BluetoothError(res.error).name}")
        self._provider = res.service_provider
        service = self._provider.service

        async def add(char_id, props, value=None):
            p = GattLocalCharacteristicParameters()
            p.characteristic_properties = props
            p.read_protection_level = GattProtectionLevel.PLAIN
            p.write_protection_level = GattProtectionLevel.PLAIN
            if value is not None:
                w = DataWriter()
                w.write_bytes(value)
                p.static_value = w.detach_buffer()
            r = await service.create_characteristic_async(self._uuid(char_id), p)
            if r.error != BluetoothError.SUCCESS:
                raise GattServerUnavailable(f"characteristic {char_id}: {BluetoothError(r.error).name}")
            return r.characteristic

        data = await add(1, P.WRITE_WITHOUT_RESPONSE | P.WRITE)
        self._ctrl = await add(2, P.NOTIFY)
        await add(3, P.READ, CAPS)
        self._tokens.append((data, data.add_write_requested(self._write_requested)))
        self._tokens.append((self._ctrl, self._ctrl.add_subscribed_clients_changed(self._subscribed_changed)))
        self._pump = asyncio.ensure_future(self._pump_writes())

        # Starting the advertisement is what publishes the service in Windows'
        # GATT database, where the connected device discovers it. The device
        # never scans for it; discoverable + connectable is the configuration
        # verified on Windows 11.
        ap = GattServiceProviderAdvertisingParameters()
        ap.is_connectable = True
        ap.is_discoverable = True
        self._provider.start_advertising_with_parameters(ap)

    async def stop(self):
        if self._pump is not None:
            self._pump.cancel()
            self._pump = None
        for obj, token in self._tokens:
            try:
                if obj is self._ctrl:
                    obj.remove_subscribed_clients_changed(token)
                else:
                    obj.remove_write_requested(token)
            except Exception:
                pass
        self._tokens = []
        if self._provider is not None:
            try:
                self._provider.stop_advertising()
            except Exception:
                pass
            self._provider = None

    # ---- WinRT threads -> loop ------------------------------------------------
    def _write_requested(self, _sender, args):
        deferral = args.get_deferral()
        self.loop.call_soon_threadsafe(self._writes.put_nowait, (args, deferral))

    def _subscribed_changed(self, sender, _args):
        clients = [session_address(getattr(c, "session", None)) for c in sender.subscribed_clients]
        self.loop.call_soon_threadsafe(self.on_subscribed, clients)

    async def _pump_writes(self):
        """One write at a time, in arrival order (DATA frames must not overtake)."""
        from winrt.windows.devices.bluetooth.genericattributeprofile import GattWriteOption
        from winrt.windows.storage.streams import DataReader

        while True:
            args, deferral = await self._writes.get()
            try:
                request = await args.get_request_async()
                reader = DataReader.from_buffer(request.value)
                data = bytes(reader.read_byte() for _ in range(reader.unconsumed_buffer_length))
                if request.option == GattWriteOption.WRITE_WITH_RESPONSE:
                    request.respond()
                self.on_write(data, session_address(getattr(args, "session", None)))
            except Exception as e:
                self.log(f"PC GATT server: write failed: {e}")
            finally:
                deferral.complete()

    # ---- loop -> WinRT ----------------------------------------------------------
    def notify(self, frame: bytes, peer=None):
        """Notify CTRL: to the subscribed board at address peer only, when it is
        found among the subscribers; to every subscriber otherwise."""
        from winrt.windows.storage.streams import DataWriter

        if self._ctrl is None:
            return
        w = DataWriter()
        w.write_bytes(frame)
        buf = w.detach_buffer()
        client = self._client_for(peer)
        if client is not None:                                  # starts now: order kept
            op = self._ctrl.notify_value_for_subscribed_client_async(buf, client)
        else:
            op = self._ctrl.notify_value_async(buf)
        asyncio.ensure_future(self._await_notify(op))

    def _client_for(self, peer):
        if not peer:
            return None
        try:
            clients = list(self._ctrl.subscribed_clients)
        except Exception:                               # noqa: BLE001 - notify them all
            return None
        return next((c for c in clients if session_address(getattr(c, "session", None)) == peer),
                    None)

    async def _await_notify(self, op):
        try:
            await op
        except Exception as e:
            self.log(f"PC GATT server: notification failed: {e}")


class PcGattServer:
    """The PC's SETU service and its receiver.

    tap: TrafficTap (or None) to show the device's writes and the PC's
    notifications in the traffic monitor. backend_factory(server) -> backend
    is for tests; the default is WinRtBackend.
    """

    NAME = "pc_server"

    def __init__(self, base: str, log=print, tap=None, backend_factory=None):
        self.base = base
        self.log = log
        self.tap = tap
        self.backend = None
        self.available = False
        self.error = None
        self.subscribers = 0                # subscribed boards whose writes are taken
        self.peer = None                    # the active device's address (set_peer)
        self._clients = []                  # subscribed boards' addresses ('' if unknown)
        self._ignored = set()               # boards whose writes were refused (logged once)
        self.receiver = SETUReceiver(self._notify, log=lambda t: self.log(t))
        self.receiver.subscribed = False
        self._backend_factory = backend_factory

    async def start(self):
        """Publish the service (on the loop that will run the receiver)."""
        loop = asyncio.get_running_loop()
        factory = self._backend_factory or (lambda s: WinRtBackend(
            s.base, loop, s._on_write, s._on_subscribed, s.log))
        backend = factory(self)
        try:
            await backend.start()
        except Exception as e:
            self.available, self.error = False, str(e)
            raise
        self.backend = backend
        self.available, self.error = True, None

    async def stop(self):
        if self.backend is not None:
            await self.backend.stop()
            self.backend = None
        self.available = False

    def set_peer(self, address):
        """Take writes from the board at address only (the active device), and
        notify only it; None takes them from any board. A transfer from the
        board before ends as DISCONNECTED."""
        peer = (address or "").upper() or None
        if peer == self.peer:
            return
        self.peer = peer
        self._ignored = set()
        self.receiver.disconnected()
        self._refresh_subscribed()

    def link_lost(self, address=None):
        """A BLE connection is gone (address: that board's; None: every one): a
        running transfer from that board fails as DISCONNECTED."""
        address = (address or "").upper()
        if not address or not self.peer or address == self.peer:
            self.receiver.disconnected()
        self._clients = [c for c in self._clients if address and c != address]
        self._refresh_subscribed()

    # ---- backend callbacks (on the loop) -----------------------------------------
    def _takes(self, sender: str) -> bool:
        """A write or subscription from sender counts ('' when unknown)."""
        return not self.peer or not sender or sender == self.peer

    def _on_write(self, data: bytes, sender: str = ""):
        sender = (sender or "").upper()
        if not self._takes(sender):
            if sender not in self._ignored:
                self._ignored.add(sender)
                self.log(f"PC SETU service: writes from {sender} ignored, it is not the active device")
            return
        if self.tap is not None:
            self.tap.rx("WNR", setu_client.char_uuid(1, self.base), data, "PC service")
        self.receiver.on_write(data)

    def _on_subscribed(self, clients):
        """clients: the subscribed boards' addresses (a count from older callers)."""
        if isinstance(clients, int):
            clients = [""] * clients
        self._clients = [(c or "").upper() for c in clients]
        self._refresh_subscribed()

    def _refresh_subscribed(self):
        self.subscribers = sum(1 for c in self._clients if self._takes(c))
        self.receiver.subscribed = self.subscribers > 0     # PROTOCOL.md §7.1 step 1

    def _notify(self, frame: bytes):
        if self.tap is not None:
            self.tap.tx("NOTIFY", setu_client.char_uuid(2, self.base), frame, "PC service")
        if self.backend is not None:
            self.backend.notify(frame, self.peer)
