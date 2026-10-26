# SPDX-License-Identifier: MIT
"""The Device page's stale-key handling (_TOOLS/BleHostGUI/blehost/ui/connection_panel.py).

A board that forgot this PC (chip erase, wipe, DEPROVISION, Button 3 held)
cannot be reached while Windows keeps its own keys: Windows encrypts with them
and drops the link. When a link dies while connecting or soon after, the page
asks Windows whether it holds keys for the address and offers to forget them;
More -> "Forget pairing on this PC" does it for the selected board. The logic
runs against stand-in widgets and a fake link; one test builds the real page.
"""

import asyncio

import pytest

from blehost.core.ble_link import LinkState, ScanResult
from blehost.core.winrt_pairing import PairingUnavailable
from blehost.ui import connection_panel as cp

ADDR = "C6:C0:BE:27:A3:CF"


class Var:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Widget:
    def __init__(self):
        self.enabled = True

    def state(self, spec):
        self.enabled = spec == ["!disabled"]


class Pill:
    def set(self, text, tone):
        self.text = text


class Tree:
    def __init__(self):
        self.sel = (ADDR,)

    def selection(self):
        return self.sel

    def set(self, iid, column):
        return "ProjectHanuman"


class Link:
    def __init__(self):
        self.state = LinkState.IDLE
        self.paired = {ADDR}
        self.unpaired = []
        self.connect_error = None
        self.lookup_error = None
        self.order = []

    async def connect(self, addr, name):
        self.order.append("connect")
        if self.connect_error:
            raise self.connect_error

    async def is_paired_address(self, addr):
        if self.lookup_error:
            raise self.lookup_error
        return addr in self.paired

    async def unpair_address(self, addr):
        self.order.append("unpair")
        self.unpaired.append(addr)
        self.paired.discard(addr)
        return "unpaired"


class Ctx:
    def __init__(self):
        self.link = Link()
        self.logs = []
        self.settings = type("S", (), {"base_uuid": ""})()

    def log(self, text, level="info"):
        self.logs.append((level, text))

    def run(self, coro, on_done=None, on_error=None, on_cancel=None):
        try:
            result = asyncio.run(coro)
        except Exception as e:                 # noqa: BLE001 - mirrors AppContext.run
            if on_error:
                on_error(e)
        else:
            if on_done:
                on_done(result)


@pytest.fixture
def dialogs(monkeypatch):
    seen = {"asked": [], "answer": True, "errors": []}

    def ask(title, text):
        seen["asked"].append((title, text))
        return seen["answer"]
    monkeypatch.setattr(cp.messagebox, "askyesno", ask)
    monkeypatch.setattr(cp.messagebox, "showerror", lambda t, m: seen["errors"].append(m))
    return seen


@pytest.fixture
def panel(dialogs):
    p = cp.ConnectionPanel.__new__(cp.ConnectionPanel)
    p.ctx = Ctx()
    p._is_busy = lambda: False
    p._results = []
    p._attempt = p._connected_at = None
    p.tree = Tree()
    for name in ("scan_btn", "connect_btn", "disconnect_btn", "caps_btn", "base_entry", "forget_btn"):
        setattr(p, name, Widget())
    p.state_pill = Pill()
    p.name_var, p.addr_var, p.caps_var = Var(), Var(), Var()
    p.base_var = Var("0000-1000-8000-00805f9b34fb")
    p._facts = {k: Var() for k in ("ATT MTU", "Protocol", "Window", "Max frame")}
    return p


def lost(p):
    p.ctx.link.state = LinkState.IDLE
    p.show_link(LinkState.IDLE, {"reason": "link lost"})


def test_drop_while_connecting_offers_to_forget(panel, dialogs):
    # The reported case: the SETU subscription fails, the link is gone before CONNECTED
    panel._connect()
    lost(panel)
    assert len(dialogs["asked"]) == 1
    title, text = dialogs["asked"][0]
    assert title == "Stale pairing keys" and ADDR in text and "chip erase" in text
    assert panel.ctx.link.unpaired == [ADDR]
    assert any("forgotten on this PC" in t for _, t in panel.ctx.logs)
    assert panel._attempt is None


def test_declining_keeps_the_keys(panel, dialogs):
    dialogs["answer"] = False
    panel._connect()
    lost(panel)
    assert dialogs["asked"] and panel.ctx.link.unpaired == []


def test_drop_soon_after_connecting(panel, dialogs, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(cp.time, "monotonic", lambda: now[0])
    panel._connect()
    panel.ctx.link.state = LinkState.CONNECTED
    panel.show_link(LinkState.CONNECTED, {"address": ADDR, "name": "ProjectHanuman"})
    now[0] += cp.STALE_KEYS_WINDOW_S - 1
    lost(panel)
    assert len(dialogs["asked"]) == 1


def test_late_drop_or_plain_disconnect_asks_nothing(panel, dialogs, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(cp.time, "monotonic", lambda: now[0])
    panel._connect()
    panel.show_link(LinkState.CONNECTED, {"address": ADDR})
    now[0] += cp.STALE_KEYS_WINDOW_S + 1
    lost(panel)
    panel._connect()
    panel.show_link(LinkState.IDLE, {"reason": "disconnected"})
    lost(panel)                                   # no Connect since: nothing to check
    assert dialogs["asked"] == []


def test_unpaired_board_asks_nothing(panel, dialogs):
    panel.ctx.link.paired = set()
    panel._connect()
    lost(panel)
    assert dialogs["asked"] == []


def test_lookup_failure_is_logged_quietly(panel, dialogs):
    panel.ctx.link.lookup_error = RuntimeError("no WinRT")
    panel._connect()
    lost(panel)
    assert dialogs["asked"] == [] and ("warn", f"pairing state of {ADDR} unknown: no WinRT") \
        in panel.ctx.logs


def test_connect_error_after_reaching_the_board(panel, dialogs):
    panel.ctx.link.connect_error = OSError("Unreachable")
    panel._connect()
    assert dialogs["errors"] and len(dialogs["asked"]) == 1


@pytest.mark.parametrize("exc", [TimeoutError(), type("BleakDeviceNotFoundError", (Exception,), {})()])
def test_unreached_board_asks_nothing(panel, dialogs, exc):
    # A trusted board out of range must not be offered for forgetting
    panel.ctx.link.connect_error = exc
    panel._connect()
    assert dialogs["errors"] and dialogs["asked"] == []


def test_forget_selected(panel, dialogs):
    panel.update_state()
    assert panel.forget_btn.enabled
    dialogs["answer"] = False
    panel._forget_selected()
    assert panel.ctx.link.unpaired == []
    dialogs["answer"] = True
    panel._forget_selected()
    assert panel.ctx.link.unpaired == [ADDR]
    assert "Button 3" in dialogs["asked"][-1][1]


def test_forget_needs_an_idle_link_and_a_selection(panel, dialogs):
    panel.ctx.link.state = LinkState.CONNECTED
    panel.update_state()
    assert not panel.forget_btn.enabled
    panel._forget_selected()
    panel.ctx.link.state = LinkState.IDLE
    panel.tree.sel = ()
    panel.update_state()
    assert not panel.forget_btn.enabled
    panel._forget_selected()
    assert dialogs["asked"] == []


# ---- the advert: stale keys removed silently before connecting ----------------------
def advert(panel, flags):
    panel._results = [ScanResult(ADDR, "ProjectHanuman", -50, [], {0xFFFF: bytes([1, flags])})]


def test_no_host_bond_advertised_removes_the_keys_first(panel, dialogs):
    # The board was erased or wiped: it says so, so no dialog and no dropped link
    advert(panel, 0x00)
    panel._connect()
    assert panel.ctx.link.order == ["unpair", "connect"]
    assert dialogs["asked"] == [] and dialogs["errors"] == []
    assert ("info", f"ProjectHanuman has no host bond: this PC's old keys for it removed (unpaired)")         in panel.ctx.logs


def test_host_bond_advertised_keeps_the_keys(panel, dialogs):
    advert(panel, 0x03)                            # provisioned, host bonded
    panel._connect()
    assert panel.ctx.link.order == ["connect"] and panel.ctx.link.unpaired == []


def test_no_keys_held_nothing_to_remove(panel, dialogs):
    advert(panel, 0x01)
    panel.ctx.link.paired = set()
    panel._connect()
    assert panel.ctx.link.order == ["connect"]


def test_cleanup_failures_still_connect(panel, dialogs):
    advert(panel, 0x00)
    panel.ctx.link.lookup_error = PairingUnavailable("not Windows")
    panel._connect()
    assert panel.ctx.link.order == ["connect"] and panel.ctx.logs == [], "quiet off Windows"
    panel.ctx.link.lookup_error = RuntimeError("WinRT broke")
    panel._connect()
    assert panel.ctx.link.order == ["connect", "connect"]
    assert any(level == "warn" and "could not check this PC's keys" in t for level, t in panel.ctx.logs)


def test_real_page_has_the_menu(tk_root):
    from blehost.context import AppContext
    page = cp.ConnectionPanel(tk_root, AppContext(), is_busy=lambda: False)
    assert page.forget_btn is not None
    page.destroy()
