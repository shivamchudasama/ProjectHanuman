# SPDX-License-Identifier: MIT
"""DeviceManager (_TOOLS/BleHostGUI/blehost/core/devices.py): several boards
connected at once, one of them the active device.

Fake links stand in for BleLink: they change state as BleLink does and
report it through on_state. Checked: the sessions and their order, which
board is active (the first one up, a later one unless a page is busy,
set_active refused while busy), the DEVICES and LINK_STATE events (LINK_STATE
for the active device only, a switch as IDLE + CONNECTED with "switched"),
a failed connect, the active device's link loss, disconnect_all, the idle
link and the ActiveService proxy."""

import asyncio

import pytest

from blehost.core import devices as dm
from blehost.core.ble_link import LinkState
from blehost.core.event_bus import DEVICES, LINK_STATE

A, B, C = "C6:C0:BE:27:A3:CF", "D0:11:22:33:44:55", "E1:22:33:44:55:66"


class Bus:
    def __init__(self):
        self.posts = []

    def post(self, topic, payload=None):
        self.posts.append((topic, payload))

    def topic(self, name):
        return [p for t, p in self.posts if t == name]


class Gatt:
    def __init__(self, chars):
        self.chars = chars

    def has_characteristic(self, uuid):
        return uuid in self.chars


class FakeLink:
    """BleLink's state behaviour, without bleak."""

    def __init__(self, label, world):
        self.label = label
        self.world = world
        self.state = LinkState.IDLE
        self.info = {}
        self.on_state = None
        self.gatt = None
        self.connected_with = None
        self.disconnect_hooks = []

    @property
    def connected(self):
        return self.state == LinkState.CONNECTED

    @property
    def mtu_size(self):
        return 247 if self.gatt else 0

    def _set(self, state, **info):
        self.state, self.info = state, info
        if self.on_state:
            self.on_state(self, state, dict(info))

    async def connect(self, address, name="", timeout=15.0, device=None):
        self.connected_with = device
        self._set(LinkState.CONNECTING, address=address, name=name)
        if address in self.world.unreachable:
            self._set(LinkState.IDLE)
            raise TimeoutError("not found")
        self.gatt = Gatt(self.world.chars.get(address, set()))
        self._set(LinkState.CONNECTED, address=address, name=name, mtu=247)

    async def disconnect(self):
        if self.state != LinkState.CONNECTED:
            return
        self._set(LinkState.DISCONNECTING, **self.info)
        self.drop("disconnected")

    def drop(self, reason="link lost"):
        self.gatt = None
        self._set(LinkState.IDLE, reason=reason)

    # the scan link
    async def scan(self, timeout):
        self.world.scanned_while = self.world.manager.scanning
        return ["result"]

    def device(self, address):
        return self.world.ble_devices.get(address)

    async def is_paired_address(self, address):
        return address == A

    async def unpair_address(self, address):
        return f"unpaired {address}"


class World:
    def __init__(self):
        self.bus = Bus()
        self.links = []
        self.unreachable = set()
        self.chars = {}
        self.ble_devices = {}
        self.busy = False
        self.scanned_while = None
        self.manager = dm.DeviceManager(self.bus, None, make_link=self.make_link,
                                        is_busy=lambda: self.busy)

    def make_link(self, label):
        link = FakeLink(label, self)
        self.links.append(link)
        return link

    def connect(self, address, name="ProjectHanuman", mdata=None):
        return asyncio.run(self.manager.connect(address, name, mdata))


@pytest.fixture
def world():
    return World()


def link_states(world):
    return [(st, info.get("switched", False), info.get("address") or info.get("reason"))
            for st, info in world.bus.topic(LINK_STATE)]


# ---- connect -----------------------------------------------------------------------------
def test_first_board_becomes_active(world):
    m = world.manager
    assert m.active is None and m.link is m.idle_link and not m.idle_link.connected
    s = world.connect(A, mdata={0xFFFF: b"\x01\x03"})
    assert m.active is s and m.link is s.link and list(m.sessions) == [A]
    assert s.link.label == "ProjectHanuman A3:CF" and s.manufacturer_data == {0xFFFF: b"\x01\x03"}
    assert s.connected_at is not None
    assert link_states(world) == [(LinkState.CONNECTED, False, A)], "active only, not switched"
    devs = world.bus.topic(DEVICES)
    assert devs[0] == (s, LinkState.IDLE, {}), "listed at once"
    assert (s, LinkState.CONNECTING, {"address": A, "name": "ProjectHanuman"}) in devs


def test_scanned_device_is_handed_to_the_boards_link(world):
    world.ble_devices[A] = object()
    s = world.connect(A)
    assert s.link.connected_with is world.ble_devices[A]


def test_a_later_board_becomes_active_unless_busy(world):
    m = world.manager
    a = world.connect(A)
    b = world.connect(B)
    assert m.active is b
    assert link_states(world)[1:] == [(LinkState.IDLE, True, "switched"),
                                      (LinkState.CONNECTED, False, B)]
    world.busy = True
    c = world.connect(C)
    assert m.active is b, "a page is busy on B"
    assert [s.address for s in m.connected()] == [A, B, C]
    assert m.get(c.address.lower()) is c and m.get("") is None and m.get(None) is None
    assert a.connected


def test_connected_twice_is_refused(world):
    world.connect(A)
    with pytest.raises(RuntimeError, match="connected already"):
        world.connect(A.lower())


def test_failed_connect_leaves_nothing(world):
    world.unreachable.add(B)
    a = world.connect(A)
    with pytest.raises(TimeoutError):
        world.connect(B)
    assert list(world.manager.sessions) == [A] and world.manager.active is a


def test_connect_that_never_starts_is_removed(world):
    def boom(*a, **kw):
        raise ImportError("no bleak")             # before the link leaves IDLE

    async def go():
        m = world.manager
        session_hook = []
        m.add_session_hook(lambda s: setattr(s.link, "connect", boom) or session_hook.append(s))
        with pytest.raises(ImportError):
            await m.connect(A)
        return session_hook
    hooked = asyncio.run(go())
    assert len(hooked) == 1 and world.manager.sessions == {}


def test_session_hooks_run_before_connecting(world):
    seen = []
    world.manager.add_session_hook(lambda s: seen.append((s.address, s.state)))
    world.connect(A)
    assert seen == [(A, LinkState.IDLE)]


# ---- the active device -------------------------------------------------------------------
def test_set_active(world):
    m = world.manager
    hooked = []
    m.add_active_hook(lambda s: hooked.append(s.address if s else None))
    a, _ = world.connect(A), world.connect(B)
    world.bus.posts.clear()
    assert m.set_active(A) and m.active is a
    assert link_states(world) == [(LinkState.IDLE, True, "switched"), (LinkState.CONNECTED, True, A)]
    assert world.bus.topic(DEVICES)[-1] == (None, None, {})
    assert m.set_active(A), "already active"
    assert not m.set_active(C), "not connected"
    world.busy = True
    assert not m.set_active(B) and m.active is a, "refused while a page is busy"
    assert hooked == [A, B, A]


def test_losing_the_active_device(world):
    m = world.manager
    hooked = []
    m.add_active_hook(lambda s: hooked.append(s and s.address))
    a, b = world.connect(A), world.connect(B)
    world.bus.posts.clear()
    b.link.drop()
    assert m.active is None and m.link is m.idle_link, "none until the user chooses"
    assert list(m.sessions) == [A]
    assert link_states(world) == [(LinkState.IDLE, False, "link lost")]
    assert (b, LinkState.IDLE, {"reason": "link lost"}) in world.bus.topic(DEVICES)
    assert hooked[-1] is None
    assert m.set_active(A) and m.active is a


def test_losing_another_board_leaves_the_active_one(world):
    m = world.manager
    a, b = world.connect(A), world.connect(B)
    world.bus.posts.clear()
    a.link.drop()
    assert m.active is b and list(m.sessions) == [B]
    assert link_states(world) == [], "not the active device"


def test_disconnect_and_disconnect_all(world):
    m = world.manager
    world.connect(A), world.connect(B), world.connect(C)
    asyncio.run(m.disconnect(B))
    asyncio.run(m.disconnect("11:22:33:44:55:66"))         # unknown: nothing
    assert list(m.sessions) == [A, C]
    asyncio.run(m.disconnect_all())
    assert m.sessions == {} and m.active is None


# ---- scan, keys, sessions ------------------------------------------------------------------
def test_scan_is_flagged_and_allowed_while_connected(world):
    m = world.manager
    world.connect(A)
    assert asyncio.run(m.scan(0.1)) == ["result"]
    assert world.scanned_while is True and m.scanning is False
    assert world.bus.topic(DEVICES)[-2:] == [(None, None, {}), (None, None, {})]


def test_keys_without_a_link(world):
    m = world.manager
    assert asyncio.run(m.is_paired_address(A)) and not asyncio.run(m.is_paired_address(B))
    assert asyncio.run(m.unpair_address(B)) == f"unpaired {B}"


def test_session_characteristics(world):
    world.chars[A] = {"b1c10002-x"}
    s = world.connect(A)
    assert s.has_characteristic("b1c10002-x") and not s.has_characteristic("other")
    s.link.drop()
    assert not s.has_characteristic("b1c10002-x"), "not connected"


def test_link_label():
    assert dm.link_label("ProjectHanuman", "c6:c0:be:27:a3:cf") == "ProjectHanuman A3:CF"
    assert dm.link_label("", A) == "device A3:CF"


# ---- ActiveService ---------------------------------------------------------------------------
class Svc:
    def __init__(self, name):
        self.name = name
        self.available = True

    def new_client(self):
        return f"client of {self.name}"


def test_active_service_follows_the_active_device(world):
    m = world.manager
    m.add_session_hook(lambda s: s.services.__setitem__("setu", Svc(s.address)))
    proxy = dm.ActiveService(m, "setu")
    assert not proxy.available and proxy.target() is None
    with pytest.raises(RuntimeError, match="not connected"):
        proxy.new_client()
    world.connect(A)
    b = world.connect(B)
    assert proxy.available and proxy.new_client() == f"client of {B}" and proxy.target() is b.services["setu"]
    m.set_active(A)
    assert proxy.new_client() == f"client of {A}"
    m.active.services["setu"].available = False
    assert not proxy.available
    with pytest.raises(AttributeError):
        proxy._private
