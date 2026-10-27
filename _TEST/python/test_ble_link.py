# SPDX-License-Identifier: MIT
"""BleLink (_TOOLS/BleHostGUI/blehost/core/ble_link.py) with a fake `bleak`:
a primary link posts LINK_STATE, a board's link (primary=False, as
core/devices.py makes) does not and reports through on_state instead, and its
traffic is tagged with its label."""

import asyncio
import sys
import types

import pytest

from blehost.core.ble_link import BleLink, LinkState
from blehost.core.event_bus import LINK_STATE, TRAFFIC
from blehost.core.traffic import TrafficTap


class FakeClient:
    def __init__(self, target, disconnected_callback=None, timeout=15.0):
        self.target = target
        self.mtu_size = 247
        self.writes = []

    async def connect(self):
        pass

    async def disconnect(self):
        pass

    async def write_gatt_char(self, uuid, data, response=False):
        self.writes.append((uuid, bytes(data), response))

    async def read_gatt_char(self, uuid):
        return b"\x07"

    async def start_notify(self, uuid, cb):
        self.cb = cb


class Bus:
    def __init__(self):
        self.posts = []

    def post(self, topic, payload=None):
        self.posts.append((topic, payload))


@pytest.fixture
def bleak(monkeypatch):
    mod = types.ModuleType("bleak")
    mod.BleakClient = FakeClient
    monkeypatch.setitem(sys.modules, "bleak", mod)
    monkeypatch.setattr(sys, "platform", "linux")    # no WinRT connection parameters
    return mod


def _session(link):
    async def go():
        await link.connect("AA:BB", "dev")
        await link.gatt.write_gatt_char("u-1", b"\x01", response=True)
        await link.gatt.read_gatt_char("u-2")
        await link.start_notify("u-2", lambda s, d: None)
        link._client.cb(None, b"\x08")
        await link.disconnect()
    asyncio.run(go())


def test_main_link_drives_the_window(bleak):
    bus = Bus()
    tap = TrafficTap(bus)
    tap.enabled = True
    link = BleLink(bus, tap)
    _session(link)
    states = [p[0] for t, p in bus.posts if t == LINK_STATE]
    assert states == [LinkState.CONNECTING, LinkState.CONNECTED, LinkState.DISCONNECTING, LinkState.IDLE]
    notes = [p.note for t, p in bus.posts if t == TRAFFIC]
    assert not any(n.startswith("[") for n in notes)


def test_a_features_link_is_its_own(bleak):
    bus = Bus()
    tap = TrafficTap(bus)
    tap.enabled = True
    link = BleLink(bus, tap, label="central", primary=False)
    _session(link)
    assert not [p for t, p in bus.posts if t == LINK_STATE], "no LINK_STATE from a feature's link"
    assert link.state == LinkState.IDLE, "its own state still follows"
    events = [p for t, p in bus.posts if t == TRAFFIC]
    infos = [e.note for e in events if e.dir == "--"]
    assert "[central] connecting to dev [AA:BB]" in infos
    assert "[central] connected, ATT MTU 247" in infos and "[central] disconnected" in infos
    tagged = {(e.op, e.note) for e in events if e.dir != "--"}
    assert {("WRITE", "central"), ("READ", "central"), ("NOTIFY", "central"),
            ("CCCD", "[central] subscribe")} <= tagged


def test_scan_keeps_the_manufacturer_data(bleak):
    # The device's advert says whether it has a host bond (protocols/host_auth.parse_adv)
    dev = types.SimpleNamespace(name="ProjectHanuman")
    adv = types.SimpleNamespace(local_name="ProjectHanuman", rssi=-50, service_uuids=["ABC"],
                                manufacturer_data={0xFFFF: b"\x01\x01"})

    async def discover(timeout, return_adv):
        return {"AA:BB": (dev, adv)}
    bleak.BleakScanner = types.SimpleNamespace(discover=discover)
    link = BleLink(Bus(), TrafficTap(Bus()))
    (r,) = asyncio.run(link.scan(0.1))
    assert r.service_uuids == ["abc"] and r.manufacturer_data == {0xFFFF: b"\x01\x01"}


def _keys(link, monkeypatch, fail=None):
    removed = []

    async def unpair_address(address):
        if fail:
            raise fail
        removed.append(address)
        return "unpaired"
    monkeypatch.setattr(link, "unpair_address", unpair_address)
    return removed


def test_keys_are_forgotten_when_the_link_ends(bleak, monkeypatch):
    # After a DEPROVISION from this PC: not at once (Windows would drop the link)
    bus = Bus()
    link = BleLink(bus, TrafficTap(bus))
    removed = _keys(link, monkeypatch)

    async def go():
        await link.connect("AA:BB", "dev")
        link.forget_keys_after_disconnect()
        await asyncio.sleep(0)
        assert removed == [], "kept while the link is up"
        await link.disconnect()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    asyncio.run(go())
    assert removed == ["AA:BB"]
    assert any("keys for AA:BB forgotten on this PC" in p[1] for t, p in bus.posts if t != LINK_STATE
               and isinstance(p, tuple) and len(p) == 2 and isinstance(p[1], str))

    # Once only: the next link keeps its keys
    async def again():
        await link.connect("AA:BB", "dev")
        await link.disconnect()
        await asyncio.sleep(0)
    asyncio.run(again())
    assert removed == ["AA:BB"]


def test_forgetting_failure_is_logged(bleak, monkeypatch):
    bus = Bus()
    link = BleLink(bus, TrafficTap(bus))
    _keys(link, monkeypatch, fail=RuntimeError("no WinRT"))

    async def go():
        await link.connect("AA:BB", "dev")
        link.forget_keys_after_disconnect()
        link._on_bleak_disconnect(link._client)          # the link drops
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    asyncio.run(go())
    assert any(isinstance(p, tuple) and p[0] == "warn" and "could not forget the keys for AA:BB" in p[1]
               for t, p in bus.posts)


def test_on_state_reports_every_change(bleak):
    # core/devices.py follows each board's link through it
    seen = []
    link = BleLink(Bus(), TrafficTap(Bus()), label="dev A3:CF", primary=False,
                   on_state=lambda lk, st, info: seen.append((lk, st, info)))
    _session(link)
    assert [s for _, s, _ in seen] == [LinkState.CONNECTING, LinkState.CONNECTED,
                                       LinkState.DISCONNECTING, LinkState.IDLE]
    assert all(lk is link for lk, _, _ in seen)
    assert seen[1][2] == {"address": "AA:BB", "name": "dev", "mtu": 247}
    assert seen[-1][2] == {"reason": "disconnected"}


def test_connect_with_another_links_scanned_device(bleak):
    # The scan link finds the board, the board's own link connects to that BLEDevice
    dev = types.SimpleNamespace(name="ProjectHanuman")
    adv = types.SimpleNamespace(local_name="ProjectHanuman", rssi=-50, service_uuids=[],
                                manufacturer_data={})

    async def discover(timeout, return_adv):
        return {"AA:BB": (dev, adv)}
    bleak.BleakScanner = types.SimpleNamespace(discover=discover)
    scanner = BleLink(Bus(), TrafficTap(Bus()), primary=False)
    link = BleLink(Bus(), TrafficTap(Bus()), primary=False)

    async def go():
        await scanner.scan(0.1)
        assert scanner.device("AA:BB") is dev and scanner.device("CC:DD") is None
        await link.connect("AA:BB", "dev", device=scanner.device("AA:BB"))
        return link._client.target
    assert asyncio.run(go()) is dev
