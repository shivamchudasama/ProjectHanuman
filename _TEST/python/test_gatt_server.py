# SPDX-License-Identifier: MIT
"""PcGattServer (_TOOLS/BleHostGUI/blehost/core/gatt_server.py): the PC's
SETU service, with a fake backend in place of WinRT; and WinRtBackend
against fake winrt modules (the WinRT GATT server API surface it uses), so
its service layout, write pump, subscriptions and notifications are tested
on any OS. Whether Windows and a real adapter accept it is hil-tests."""

import asyncio
import enum
import sys
import types

import pytest

import setu_client
from blehost.core import gatt_server as gs

BASE = "16a1-4812-af35-f3f29a92f6ca"
DEV_A, DEV_B = "C6:C0:BE:27:A3:CF", "D0:11:22:33:44:55"


class FakeBackend:
    def __init__(self, server, fail=None):
        self.server = server
        self.fail = fail
        self.started = False
        self.notified = []
        self.peers = []                     # the peer each notification was for
        self.client = None                  # a SETUClient on the device side

    async def start(self):
        if self.fail:
            raise gs.GattServerUnavailable(self.fail)
        self.started = True

    async def stop(self):
        self.started = False

    def notify(self, frame, peer=None):
        self.notified.append(bytes(frame))
        self.peers.append(peer)
        if self.client is not None:
            self.client.on_notify(0, bytearray(frame))


class Tap:
    def __init__(self):
        self.events = []

    def rx(self, op, uuid, data, note=""):
        self.events.append(("RX", op, uuid, bytes(data), note))

    def tx(self, op, uuid, data, note=""):
        self.events.append(("TX", op, uuid, bytes(data), note))


class DeviceLink:
    """The device's SETU Client writes into the PC's DATA."""

    def __init__(self, server, sender=""):
        self.server = server
        self.sender = sender                # the board's address, as WinRT reports it
        self.mtu_size = 247

    async def write_gatt_char(self, uuid, data, response=False):
        assert uuid == setu_client.char_uuid(1, BASE)
        self.server._on_write(bytes(data), self.sender)
        await asyncio.sleep(0)


def make(tap=None, fail=None):
    backends = []

    def factory(server):
        backends.append(FakeBackend(server, fail))
        return backends[-1]
    return gs.PcGattServer(BASE, log=lambda *_: None, tap=tap, backend_factory=factory), backends


def test_start_and_stop():
    async def go():
        srv, b = make()
        await srv.start()
        up = srv.available and b[0].started
        await srv.stop()
        return up, srv.available, b[0].started
    assert run(go()) == (True, False, False)


def test_start_failure_is_reported():
    async def go():
        srv, _ = make(fail="no peripheral role")
        with pytest.raises(gs.GattServerUnavailable):
            await srv.start()
        return srv
    srv = run(go())
    assert not srv.available and srv.error == "no peripheral role"


def test_device_sends_an_object_to_the_pc():
    tap = Tap()

    async def go():
        srv, b = make(tap)
        await srv.start()
        dev = setu_client.SETUClient(DeviceLink(srv), BASE, log=lambda *_: None)
        b[0].client = dev
        srv._on_subscribed(1)                       # the device subscribed to CTRL
        status = await dev.send(0x23, bytes(range(256)) * 2)
        return status, await srv.receiver.receive(0x23, timeout=1.0), b[0]
    status, r, backend = run(go())
    assert status == "OK" and r.status == "OK" and r.data == bytes(range(256)) * 2
    assert backend.notified[-1][1] == setu_client.T_END
    assert ("RX", "WNR", setu_client.char_uuid(1, BASE)) == tap.events[0][:3]
    assert any(e[0] == "TX" and e[2] == setu_client.char_uuid(2, BASE) and e[4] == "PC service"
               for e in tap.events)


def test_start_is_ignored_until_the_device_subscribes():
    async def go():
        srv, b = make()
        await srv.start()
        start = setu_client.frame(setu_client.T_START, bytes([1, 0x23, 10, 0, 0, 0, 240, 16, 0, 0, 0, 0]))
        srv._on_write(start)
        before = list(b[0].notified)
        srv._on_subscribed(1)
        srv._on_write(start)
        return before, b[0].notified
    before, after = run(go())
    assert before == [] and after[0][1] == setu_client.T_ACK


def test_link_lost_fails_the_transfer():
    async def go():
        srv, _ = make()
        await srv.start()
        srv._on_subscribed(1)
        srv._on_write(setu_client.frame(setu_client.T_START, bytes([1, 0x23, 0, 1, 0, 0, 240, 16, 0, 0, 0, 0])))
        srv.link_lost()
        return srv, await srv.receiver.receive(timeout=1.0)
    srv, r = run(go())
    assert r.status == "DISCONNECTED" and not srv.receiver.subscribed and srv.subscribers == 0


# ---- several boards: only the active device's writes ---------------------------
START_23 = setu_client.frame(setu_client.T_START, bytes([1, 0x23, 0, 1, 0, 0, 240, 16, 0, 0, 0, 0]))


def test_only_the_active_device_is_heard():
    logs = []

    async def go():
        srv, b = make()
        srv.log = logs.append
        await srv.start()
        srv.set_peer(DEV_A.lower())
        srv._on_subscribed([DEV_B])
        no_peer_sub = srv.receiver.subscribed
        srv._on_subscribed([DEV_A, DEV_B])
        counted = srv.subscribers
        for _ in range(2):
            srv._on_write(START_23, DEV_B)          # another board's writes: dropped, logged once
        dropped = list(b[0].notified)
        dev = setu_client.SETUClient(DeviceLink(srv, DEV_A), BASE, log=lambda *_: None)
        b[0].client = dev
        status = await dev.send(0x23, b"csr")
        return no_peer_sub, counted, dropped, status, await srv.receiver.receive(0x23, timeout=1.0), b[0]
    no_peer_sub, counted, dropped, status, r, backend = run(go())
    assert not no_peer_sub and counted == 1
    assert dropped == [] and len([t for t in logs if DEV_B in t and "ignored" in t]) == 1
    assert status == "OK" and r.data == b"csr"
    assert set(backend.peers) == {DEV_A}, "notified to the active device only"


def test_switching_or_losing_the_active_device_ends_its_transfer():
    async def go():
        srv, _ = make()
        await srv.start()
        srv.set_peer(DEV_A)
        srv._on_subscribed([DEV_A, DEV_B])
        srv._on_write(START_23, DEV_A)
        srv.link_lost(DEV_B)                         # another board left: A's transfer goes on
        running = srv.receiver.active
        subs_after_b = srv.subscribers
        srv.set_peer(DEV_B)                          # switch: A's transfer ends
        r = await srv.receiver.receive(timeout=1.0)
        b_subscribed = srv.receiver.subscribed
        srv._on_subscribed([DEV_A, DEV_B])           # B subscribes again, then sends
        srv._on_write(START_23, DEV_B)
        srv.link_lost(DEV_B)
        r2 = await srv.receiver.receive(timeout=1.0)
        return running, subs_after_b, r, b_subscribed, r2, srv
    running, subs_after_b, r, b_subscribed, r2, srv = run(go())
    assert running and subs_after_b == 1
    assert r.status == "DISCONNECTED"
    assert not b_subscribed, "B's subscription went with its link"
    assert r2.status == "DISCONNECTED" and srv.subscribers == 0


def test_without_a_peer_every_board_is_heard():
    async def go():
        srv, b = make()
        await srv.start()
        srv._on_subscribed([DEV_B])
        sub = srv.receiver.subscribed
        srv._on_write(START_23, DEV_B)
        return sub, b[0].notified, b[0].peers
    sub, notified, peers = run(go())
    assert sub and notified[0][1] == setu_client.T_ACK and peers == [None]


def test_caps_value_matches_the_device():
    assert gs.CAPS == bytes([2, 244, 16, 0])


def test_winrt_backend_needs_windows(monkeypatch):
    monkeypatch.setattr(gs.sys, "platform", "linux")
    backend = gs.WinRtBackend(BASE, None, None, None, print)
    with pytest.raises(gs.GattServerUnavailable, match="Windows"):
        run(backend.start())


# ---- WinRtBackend against fake winrt modules ---------------------------------
class _Buffer:
    def __init__(self, data):
        self.data = bytes(data)


class _DataWriter:
    def __init__(self):
        self._data = b""

    def write_bytes(self, data):
        self._data += bytes(data)

    def detach_buffer(self):
        return _Buffer(self._data)


class _DataReader:
    def __init__(self, buf):
        self._data, self._pos = buf.data, 0

    @staticmethod
    def from_buffer(buf):
        return _DataReader(buf)

    @property
    def unconsumed_buffer_length(self):
        return len(self._data) - self._pos

    def read_byte(self):
        self._pos += 1
        return self._data[self._pos - 1]


class _BluetoothError(enum.IntEnum):
    SUCCESS = 0
    RADIO_NOT_AVAILABLE = 1
    OTHER_ERROR = 5


class _Props(enum.IntFlag):
    READ = 0x02
    WRITE_WITHOUT_RESPONSE = 0x04
    WRITE = 0x08
    NOTIFY = 0x10


class _WriteOption(enum.IntEnum):
    WRITE_WITH_RESPONSE = 0
    WRITE_WITHOUT_RESPONSE = 1


class _Params:
    """GattLocalCharacteristicParameters / GattServiceProviderAdvertisingParameters."""


class _Result:
    def __init__(self, error, **kw):
        self.error = error
        self.__dict__.update(kw)


class _Characteristic:
    def __init__(self, uuid, params, world):
        self.uuid, self.params, self.world = uuid, params, world
        self.write_handlers, self.sub_handlers = {}, {}
        self.subscribed_clients = []
        self.notified = []
        self.notified_to = []
        self.removed = []

    def add_write_requested(self, handler):
        token = len(self.write_handlers) + 100
        self.write_handlers[token] = handler
        return token

    def remove_write_requested(self, token):
        if self.world.fail_remove:
            raise OSError("already gone")
        self.removed.append(("write", token))

    def add_subscribed_clients_changed(self, handler):
        token = len(self.sub_handlers) + 200
        self.sub_handlers[token] = handler
        return token

    def remove_subscribed_clients_changed(self, token):
        self.removed.append(("sub", token))

    def notify_value_async(self, buf):
        self.notified.append(buf.data)
        fail = self.world.fail_notify

        async def op():
            if fail:
                raise OSError("no client")
        return op()

    def notify_value_for_subscribed_client_async(self, buf, client):
        self.notified_to.append((buf.data, client))

        async def op():
            pass
        return op()


class _Service:
    def __init__(self, world):
        self.world = world
        self.characteristics = []

    async def create_characteristic_async(self, uuid, params):
        n = len(self.characteristics) + 1
        if self.world.fail_char == n:
            return _Result(_BluetoothError.OTHER_ERROR)
        c = _Characteristic(uuid, params, self.world)
        self.characteristics.append(c)
        return _Result(_BluetoothError.SUCCESS, characteristic=c)


class _Provider:
    def __init__(self, uuid, world):
        self.uuid = uuid
        self.service = _Service(world)
        self.advertising = None

    def start_advertising_with_parameters(self, ap):
        self.advertising = ap

    def stop_advertising(self):
        self.advertising = None


class _World:
    """State of the fake WinRT: what the test configures and what the backend did."""

    def __init__(self):
        self.peripheral = True
        self.adapter = True
        self.provider_error = _BluetoothError.SUCCESS
        self.fail_char = 0
        self.fail_remove = False
        self.fail_notify = False
        self.provider = None


class _Request:
    def __init__(self, data, option, fail=False):
        self.value = _Buffer(data)
        self.option = option
        self.responded = False
        self.fail = fail

    def respond(self):
        self.responded = True


def _session(address):
    """A GattSession whose device ID names the board at address."""
    return types.SimpleNamespace(device_id=types.SimpleNamespace(
        id=f"BluetoothLE#BluetoothLE00:1a:7d:da:71:13-{address.lower()}"))


class _WriteArgs:
    def __init__(self, request, sender=None):
        self.request = request
        self.done = False
        if sender:
            self.session = _session(sender)

    def get_deferral(self):
        return types.SimpleNamespace(complete=lambda: setattr(self, "done", True))

    async def get_request_async(self):
        if self.request.fail:
            raise OSError("request lost")
        return self.request


@pytest.fixture
def winrt(monkeypatch):
    """Install fake winrt modules and pretend to be Windows."""
    world = _World()

    async def get_default_async():
        if not world.adapter:
            return None
        return types.SimpleNamespace(is_peripheral_role_supported=world.peripheral)

    async def create_async(uuid):
        if world.provider_error != _BluetoothError.SUCCESS:
            return _Result(world.provider_error)
        world.provider = _Provider(uuid, world)
        return _Result(_BluetoothError.SUCCESS, service_provider=world.provider)

    bt = types.ModuleType("winrt.windows.devices.bluetooth")
    bt.BluetoothAdapter = types.SimpleNamespace(get_default_async=get_default_async)
    bt.BluetoothError = _BluetoothError
    gap = types.ModuleType("winrt.windows.devices.bluetooth.genericattributeprofile")
    gap.GattCharacteristicProperties = _Props
    gap.GattLocalCharacteristicParameters = _Params
    gap.GattProtectionLevel = types.SimpleNamespace(PLAIN=0)
    gap.GattServiceProvider = types.SimpleNamespace(create_async=create_async)
    gap.GattServiceProviderAdvertisingParameters = _Params
    gap.GattWriteOption = _WriteOption
    streams = types.ModuleType("winrt.windows.storage.streams")
    streams.DataWriter = _DataWriter
    streams.DataReader = _DataReader
    for name in ("winrt", "winrt.windows", "winrt.windows.devices", "winrt.windows.storage"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    for mod in (bt, gap, streams):
        monkeypatch.setitem(sys.modules, mod.__name__, mod)
    monkeypatch.setattr(gs.sys, "platform", "win32")
    return world


def _backend(loop, writes=None, subs=None, logs=None, senders=None):
    writes = writes if writes is not None else []
    senders = senders if senders is not None else []

    def on_write(data, sender):
        writes.append(data)
        senders.append(sender)
    return gs.WinRtBackend(BASE, loop, on_write,
                           (subs if subs is not None else []).append,
                           (logs if logs is not None else []).append)


async def _settle(n=20):
    for _ in range(n):
        await asyncio.sleep(0)


def test_winrt_backend_publishes_the_service(winrt):
    async def go():
        b = _backend(asyncio.get_running_loop())
        await b.start()
        p = winrt.provider
        result = (p.uuid, list(p.service.characteristics), p.advertising)
        await b.stop()
        return result
    svc_uuid, chars, adv = run(go())
    assert str(svc_uuid) == setu_client.char_uuid(0, BASE)
    assert [str(c.uuid) for c in chars] == [setu_client.char_uuid(i, BASE) for i in (1, 2, 3)]
    data, ctrl, caps = (c.params for c in chars)
    assert data.characteristic_properties == _Props.WRITE_WITHOUT_RESPONSE | _Props.WRITE
    assert ctrl.characteristic_properties == _Props.NOTIFY
    assert caps.characteristic_properties == _Props.READ
    assert caps.static_value.data == gs.CAPS
    assert not hasattr(data, "static_value")
    assert all(c.params.read_protection_level == 0 and c.params.write_protection_level == 0
               for c in chars)
    # Publishing is advertising, connectable and discoverable
    assert adv.is_connectable and adv.is_discoverable
    assert len(chars[0].write_handlers) == 1 and len(chars[1].sub_handlers) == 1


@pytest.mark.parametrize("setup, match", [
    (lambda w: setattr(w, "adapter", False), "peripheral role"),
    (lambda w: setattr(w, "peripheral", False), "peripheral role"),
    (lambda w: setattr(w, "provider_error", _BluetoothError.RADIO_NOT_AVAILABLE),
     "GattServiceProvider: RADIO_NOT_AVAILABLE"),
    (lambda w: setattr(w, "fail_char", 2), "characteristic 2: OTHER_ERROR"),
], ids=["no-adapter", "no-peripheral-role", "provider-error", "characteristic-error"])
def test_winrt_backend_start_failures(winrt, setup, match):
    setup(winrt)

    async def go():
        await _backend(asyncio.get_running_loop()).start()
    with pytest.raises(gs.GattServerUnavailable, match=match):
        run(go())


def test_winrt_backend_without_winrt_packages(winrt, monkeypatch):
    monkeypatch.setitem(sys.modules, "winrt.windows.devices.bluetooth", None)
    with pytest.raises(gs.GattServerUnavailable, match="WinRT Bluetooth packages missing"):
        run(_backend(None).start())


def test_winrt_backend_pumps_writes_in_order(winrt):
    writes, logs = [], []

    async def go():
        b = _backend(asyncio.get_running_loop(), writes=writes, logs=logs)
        await b.start()
        data = winrt.provider.service.characteristics[0]
        handler = next(iter(data.write_handlers.values()))
        reqs = [_Request(b"\x01\x02", _WriteOption.WRITE_WITHOUT_RESPONSE),
                _Request(b"\x03", _WriteOption.WRITE_WITH_RESPONSE),
                _Request(b"lost", _WriteOption.WRITE_WITHOUT_RESPONSE, fail=True),
                _Request(b"\x04\x05\x06", _WriteOption.WRITE_WITHOUT_RESPONSE)]
        args = [_WriteArgs(r) for r in reqs]
        for a in args:
            handler(data, a)                   # as WinRT would, from its thread
        await _settle()
        await b.stop()
        return reqs, args
    reqs, args = run(go())
    assert writes == [b"\x01\x02", b"\x03", b"\x04\x05\x06"]
    assert [r.responded for r in reqs] == [False, True, False, False]
    assert all(a.done for a in args), "every deferral completes, also on failure"
    assert any("write failed: request lost" in t for t in logs)


def test_winrt_backend_reports_subscriptions(winrt):
    subs = []

    async def go():
        b = _backend(asyncio.get_running_loop(), subs=subs)
        await b.start()
        ctrl = winrt.provider.service.characteristics[1]
        handler = next(iter(ctrl.sub_handlers.values()))
        ctrl.subscribed_clients = ["device"]                 # WinRT does not say which
        handler(ctrl, None)
        ctrl.subscribed_clients = [types.SimpleNamespace(session=_session(DEV_A)),
                                   types.SimpleNamespace(session=_session(DEV_B))]
        handler(ctrl, None)
        ctrl.subscribed_clients = []
        handler(ctrl, None)
        await _settle()
        await b.stop()
    run(go())
    assert subs == [[""], [DEV_A, DEV_B], []]


def test_winrt_backend_reports_who_wrote(winrt):
    writes, senders = [], []

    async def go():
        b = _backend(asyncio.get_running_loop(), writes=writes, senders=senders)
        await b.start()
        data = winrt.provider.service.characteristics[0]
        handler = next(iter(data.write_handlers.values()))
        handler(data, _WriteArgs(_Request(b"\x01", _WriteOption.WRITE_WITHOUT_RESPONSE), DEV_A))
        handler(data, _WriteArgs(_Request(b"\x02", _WriteOption.WRITE_WITHOUT_RESPONSE)))
        await _settle()
        await b.stop()
    run(go())
    assert writes == [b"\x01", b"\x02"] and senders == [DEV_A, ""]


def test_winrt_backend_notifies_the_peer_only(winrt):
    async def go():
        b = _backend(asyncio.get_running_loop())
        await b.start()
        ctrl = winrt.provider.service.characteristics[1]
        a = types.SimpleNamespace(session=_session(DEV_A))
        ctrl.subscribed_clients = [types.SimpleNamespace(session=_session(DEV_B)), a]
        b.notify(b"\x02\x10", DEV_A)
        b.notify(b"\x02\x11", "11:22:33:44:55:66")        # not subscribed: to everyone
        b.notify(b"\x02\x12")
        await _settle()
        await b.stop()
        return ctrl.notified_to, ctrl.notified, a
    to, everyone, a = run(go())
    assert to == [(b"\x02\x10", a)] and everyone == [b"\x02\x11", b"\x02\x12"]


def test_session_address():
    assert gs.session_address(_session(DEV_A)) == DEV_A
    assert gs.session_address(None) == ""
    assert gs.session_address(types.SimpleNamespace(device_id=types.SimpleNamespace(id="x"))) == ""


def test_winrt_backend_notifies_on_ctrl(winrt):
    logs = []

    async def go():
        b = _backend(asyncio.get_running_loop(), logs=logs)
        b.notify(b"before start")              # nothing to notify on yet: ignored
        await b.start()
        ctrl = winrt.provider.service.characteristics[1]
        b.notify(b"\x02\x10")
        winrt.fail_notify = True
        b.notify(b"\x02\x11")
        await _settle()
        await b.stop()
        return ctrl.notified
    assert run(go()) == [b"\x02\x10", b"\x02\x11"]
    assert any("notification failed: no client" in t for t in logs)


def test_winrt_backend_stop_releases_everything(winrt):
    async def go():
        b = _backend(asyncio.get_running_loop())
        await b.start()
        provider = winrt.provider
        data, ctrl, _ = provider.service.characteristics
        pump = b._pump
        await b.stop()
        await _settle()
        state = (data.removed, ctrl.removed, provider.advertising, pump.cancelled(), b._tokens)
        await b.stop()                         # twice is harmless
        return state
    data_removed, ctrl_removed, adv, cancelled, tokens = run(go())
    assert data_removed == [("write", 100)] and ctrl_removed == [("sub", 200)]
    assert adv is None and cancelled and tokens == []


def test_winrt_backend_stop_tolerates_winrt_errors(winrt):
    def refuse():
        raise OSError("radio off")

    async def go():
        b = _backend(asyncio.get_running_loop())
        await b.start()
        winrt.fail_remove = True
        winrt.provider.stop_advertising = refuse
        await b.stop()
        return b._provider, b._tokens
    assert run(go()) == (None, [])


def test_pc_server_uses_the_winrt_backend_by_default(winrt):
    async def go():
        srv = gs.PcGattServer(BASE, log=lambda *_: None)
        await srv.start()
        kind = type(srv.backend)
        ctrl = winrt.provider.service.characteristics[1]
        srv._notify(b"\x02\x05")                # receiver -> backend -> CTRL
        await _settle()
        await srv.stop()
        return kind, ctrl.notified, srv.available
    kind, notified, available = run(go())
    assert kind is gs.WinRtBackend and notified == [b"\x02\x05"] and not available


def run(coro):
    return asyncio.run(coro)
