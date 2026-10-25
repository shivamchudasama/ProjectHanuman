# SPDX-License-Identifier: MIT
"""LE SC passkey entry from Windows (_TOOLS/BleHostGUI/blehost/core/winrt_pairing.py)
and BleLink's pairing calls, against a fake `winrt.windows.devices.enumeration`:
the pairing kind asked for is ProvidePin, the PairingRequested event is answered
with the six-digit passkey (and nothing else is accepted), the result must be
Paired with encryption and authentication, old keys are removed first; off
Windows every call says so."""

import asyncio
import enum
import sys
import types

import pytest

from blehost.core import winrt_pairing as wp
from blehost.core.ble_link import BleLink


class Kinds(enum.IntFlag):
    CONFIRM_ONLY = 1
    DISPLAY_PIN = 2
    PROVIDE_PIN = 4
    CONFIRM_PIN_MATCH = 8


class Level(enum.Enum):
    DEFAULT = 0
    NONE = 1
    ENCRYPTION = 2
    ENCRYPTION_AND_AUTHENTICATION = 3


class Status(enum.Enum):
    PAIRED = 0
    NOT_READY_TO_PAIR = 1
    ALREADY_PAIRED = 3
    AUTHENTICATION_FAILURE = 11
    UNPAIRED = 20


class _Done:
    """An awaitable WinRT async operation that has finished."""

    def __init__(self, value):
        self.value = value

    def __await__(self):
        if False:
            yield
        return self.value


class World:
    def __init__(self):
        self.paired = False
        self.status = Status.PAIRED
        self.level = Level.ENCRYPTION_AND_AUTHENTICATION
        self.kind = Kinds.PROVIDE_PIN          # what Windows asks the app for
        self.accepted = []
        self.asked_kinds = None
        self.asked_level = None
        self.unpairs = 0
        self.handler_removed = False
        self.ids = []


class Args:
    def __init__(self, world, kind):
        self.world = world
        self.pairing_kind = kind

    def accept(self, pin=None):
        self.world.accepted.append(pin)


class Custom:
    def __init__(self, world):
        self.w = world
        self.handler = None

    def add_pairing_requested(self, h):
        self.handler = h
        return 77

    def remove_pairing_requested(self, token):
        assert token == 77
        self.w.handler_removed = True

    def pair_with_protection_level_async(self, kinds, level):
        self.w.asked_kinds, self.w.asked_level = kinds, level
        self.handler(self, Args(self.w, self.w.kind))
        if self.w.status == Status.PAIRED:
            self.w.paired = True
        return _Done(types.SimpleNamespace(status=self.w.status, protection_level_used=self.w.level))


class Pairing:
    def __init__(self, world):
        self.w = world
        self.custom = Custom(world)

    @property
    def is_paired(self):
        return self.w.paired

    def unpair_async(self):
        self.w.unpairs += 1
        self.w.paired = False
        return _Done(types.SimpleNamespace(status=Status.UNPAIRED))


@pytest.fixture
def world(monkeypatch):
    w = World()

    class DeviceInformation:
        @staticmethod
        def create_from_id_async(dev_id):
            w.ids.append(dev_id)
            return _Done(types.SimpleNamespace(pairing=Pairing(w)))

    en = types.ModuleType("winrt.windows.devices.enumeration")
    en.DeviceInformation = DeviceInformation
    en.DevicePairingKinds = Kinds
    en.DevicePairingProtectionLevel = Level
    en.DevicePairingResultStatus = Status
    for name in ("winrt", "winrt.windows", "winrt.windows.devices"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules["winrt.windows.devices"].enumeration = en
    monkeypatch.setitem(sys.modules, "winrt.windows.devices.enumeration", en)
    monkeypatch.setattr(wp.sys, "platform", "win32")
    return w


def client():
    dev = types.SimpleNamespace(device_information=types.SimpleNamespace(id="BluetoothLE#dev-1"))
    return types.SimpleNamespace(_backend=types.SimpleNamespace(_requester=dev))


def run(coro):
    return asyncio.run(coro)


def test_pairs_with_the_passkey(world):
    assert run(wp.pair_with_pin(client(), 42)) == "encryption_and_authentication"
    assert world.asked_kinds == Kinds.PROVIDE_PIN
    assert world.asked_level == Level.ENCRYPTION_AND_AUTHENTICATION
    assert world.accepted == ["000042"]
    assert world.handler_removed
    assert world.ids == ["BluetoothLE#dev-1"]
    assert run(wp.is_paired(client()))


def test_other_ceremonies_are_not_accepted(world):
    # Windows offering Just Works or numeric comparison: no answer, the pairing fails
    world.kind = Kinds.CONFIRM_ONLY
    world.status = Status.AUTHENTICATION_FAILURE
    with pytest.raises(wp.PairingFailed, match="authentication_failure.*CONFIRM_ONLY"):
        run(wp.pair_with_pin(client(), 123456))
    assert world.accepted == []
    assert world.handler_removed


def test_unauthenticated_result_is_a_failure(world):
    world.level = Level.ENCRYPTION
    with pytest.raises(wp.PairingFailed, match="without authentication"):
        run(wp.pair_with_pin(client(), 1))


def test_old_keys_are_removed_first(world):
    world.paired = True
    logs = []
    run(wp.pair_with_pin(client(), 999999, log=logs.append))
    assert world.unpairs == 1 and world.accepted == ["999999"]
    assert any("old keys" in line for line in logs)
    world.status = Status.ALREADY_PAIRED
    run(wp.pair_with_pin(client(), 5))


def test_passkey_range(world):
    with pytest.raises(ValueError):
        run(wp.pair_with_pin(client(), 1000000))
    with pytest.raises(ValueError):
        run(wp.pair_with_pin(client(), -1))


def test_unpair(world):
    assert run(wp.unpair(client())) == "not_paired"
    world.paired = True
    assert run(wp.unpair(client())) == "unpaired"
    assert world.unpairs == 1


def test_unavailable(world, monkeypatch):
    with pytest.raises(wp.PairingUnavailable, match="bleak changed"):
        run(wp.pair_with_pin(types.SimpleNamespace(), 1))
    monkeypatch.setattr(wp.sys, "platform", "linux")
    with pytest.raises(wp.PairingUnavailable, match="Windows"):
        run(wp.is_paired(client()))
    monkeypatch.setattr(wp.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "winrt.windows.devices.enumeration", None)
    monkeypatch.delattr(sys.modules["winrt.windows.devices"], "enumeration")
    with pytest.raises(wp.PairingUnavailable, match="not available"):
        run(wp.unpair(client()))


class _Bus:
    def post(self, topic, payload=None):
        pass


class _Tap:
    def __init__(self):
        self.infos = []

    def info(self, op, note):
        self.infos.append((op, note))


def test_ble_link_pairs_its_client(world):
    tap = _Tap()
    link = BleLink(_Bus(), tap)
    with pytest.raises(RuntimeError, match="not connected"):
        run(link.pair_with_pin(1))
    link._client = client()
    assert run(link.pair_with_pin(7)) == "encryption_and_authentication"
    assert run(link.is_paired())
    assert run(link.unpair()) == "unpaired"
    assert [op for op, _ in tap.infos] == ["PAIR", "PAIR", "PAIR"]
