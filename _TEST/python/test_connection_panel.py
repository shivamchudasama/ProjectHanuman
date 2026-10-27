# SPDX-License-Identifier: MIT
"""The Device page (_TOOLS/BleHostGUI/blehost/ui/connection_panel.py).

Several boards: Connect adds a board (core/devices.py), the connected list
shows each with its state and the active device, Make active switches (and
says why not while a page is busy), Disconnect acts on the selected board,
and the buttons follow what is selected and connected.

Stale keys: a board that forgot this PC (chip erase, wipe, DEPROVISION,
Button 3 held) cannot be reached while Windows keeps its own keys: Windows
encrypts with them and drops the link. When a board's link dies while
connecting or soon after, the page asks Windows whether it holds keys for the
address and offers to forget them; More -> "Forget pairing on this PC" does it
for the selected nearby board. The logic runs against stand-in widgets and a
fake device manager; one test builds the real page.
"""

import asyncio

import pytest

from blehost.core.ble_link import LinkState, ScanResult
from blehost.core.winrt_pairing import PairingUnavailable
from blehost.protocols import pairing
from blehost.ui import connection_panel as cp

ADDR = "C6:C0:BE:27:A3:CF"
OTHER = "D0:11:22:33:44:55"


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
    text = ""

    def set(self, text, tone):
        self.text = text


class Details:
    is_open = False

    def set_open(self, open_):
        self.is_open = open_


class Tree:
    """A Treeview's rows and selection."""

    def __init__(self, sel=()):
        self.rows = {}                  # iid -> (values, tags)
        self.sel = tuple(sel)
        self.names = {}                 # iid -> name for set(iid, "name") without a row

    def selection(self):
        return self.sel

    def selection_set(self, iid):
        self.sel = (iid,)

    def set(self, iid, column):
        if iid in self.rows:
            return self.rows[iid][0][0]
        return self.names.get(iid, "ProjectHanuman")

    def delete(self, *iids):
        for iid in iids:
            self.rows.pop(iid, None)

    def insert(self, parent, index, iid, values=(), tags=()):
        self.rows[iid] = (values, tags)

    def get_children(self):
        return tuple(self.rows)

    def exists(self, iid):
        return iid in self.rows


class Link:
    def __init__(self):
        self.mtu_size = 247


class Session:
    def __init__(self, address, name="ProjectHanuman", state=LinkState.CONNECTED, pairing_svc=False):
        self.address, self.name = address, name
        self.state = state
        self.link = Link()
        self.connected_at = None
        self.pairing_svc = pairing_svc

    @property
    def key(self):
        return self.address.upper()

    @property
    def connected(self):
        return self.state == LinkState.CONNECTED

    def has_characteristic(self, uuid):
        return self.pairing_svc and uuid == pairing.STATUS_UUID


class Devices:
    """The DeviceManager surface the page uses."""

    def __init__(self):
        self.sessions = {}
        self.active = None
        self.scanning = False
        self.busy = False
        self.paired = {ADDR}
        self.unpaired = []
        self.connect_error = None
        self.lookup_error = None
        self.order = []
        self.disconnected = []

    def get(self, address):
        return self.sessions.get((address or "").upper())

    def connected(self):
        return [s for s in self.sessions.values() if s.connected]

    def add(self, address, **kw):
        s = Session(address, **kw)
        self.sessions[s.key] = s
        return s

    async def connect(self, addr, name, mdata=None):
        self.order.append("connect")
        if self.connect_error:
            raise self.connect_error
        s = self.add(addr, name=name, state=LinkState.CONNECTING)
        if self.active is None:
            self.active = s
        return s

    async def disconnect(self, address):
        self.disconnected.append(address)

    def set_active(self, address):
        if self.busy:
            return False
        self.active = self.get(address)
        return True

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
        self.devices = Devices()
        self.logs = []
        self.settings = type("S", (), {"base_uuid": "", "name_filter": "", "scan_timeout": 0.1})()

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
    seen = {"asked": [], "answer": True, "errors": [], "info": []}

    def ask(title, text):
        seen["asked"].append((title, text))
        return seen["answer"]
    monkeypatch.setattr(cp.messagebox, "askyesno", ask)
    monkeypatch.setattr(cp.messagebox, "showerror", lambda t, m: seen["errors"].append(m))
    monkeypatch.setattr(cp.messagebox, "showinfo", lambda t, m: seen["info"].append(m))
    return seen


@pytest.fixture
def panel(dialogs):
    p = cp.ConnectionPanel.__new__(cp.ConnectionPanel)
    p.ctx = Ctx()
    p.busy = False
    p._is_busy = lambda: p.busy
    p._results = []
    p._shown_active = None
    p.tree = Tree(sel=(ADDR,))
    p.dev_tree = Tree()
    for name in ("scan_btn", "connect_btn", "forget_btn", "active_btn", "disconnect_btn",
                 "caps_btn", "base_entry"):
        setattr(p, name, Widget())
    p.state_pill = Pill()
    p.details = Details()
    p.name_var, p.addr_var, p.caps_var = Var(), Var(), Var()
    p.base_var = Var("0000-1000-8000-00805f9b34fb")
    p.filter_var = Var("")
    p._facts = {k: Var() for k in ("ATT MTU", "Protocol", "Window", "Max frame")}
    return p


def event(p, session, state, **info):
    """The DEVICES event for session, after the manager has acted on it."""
    session.state = state
    if state == LinkState.IDLE:
        p.ctx.devices.sessions.pop(session.key, None)
        if p.ctx.devices.active is session:
            p.ctx.devices.active = None
    p.show_devices((session, state, info))


def lost(p, address=ADDR):
    session = p.ctx.devices.get(address)
    event(p, session, LinkState.IDLE, reason="link lost")


# ---- several boards --------------------------------------------------------------------------
def test_connected_boards_are_listed_with_the_active_one(panel):
    d = panel.ctx.devices
    a = d.add(ADDR, pairing_svc=True)
    d.add(OTHER, name="")
    d.active = a
    panel.show_devices((None, None, {}))
    rows = panel.dev_tree.rows
    assert rows[ADDR] == (("ProjectHanuman", ADDR, "Active", "yes"), ("active",))
    assert rows[OTHER] == (("(no name)", OTHER, "Connected", ""), ())
    assert panel.dev_tree.selection() == (ADDR,), "the active board selected by default"
    assert panel.name_var.get() == "ProjectHanuman" and panel.addr_var.get() == ADDR
    assert panel._facts["ATT MTU"].get() == "247" and panel.state_pill.text == "Connected"
    assert not panel.base_entry.enabled, "the base UUID is fixed while boards are connected"


def test_header_lines_without_an_active_device(panel):
    d = panel.ctx.devices
    panel.show_devices((None, None, {}))
    assert panel.name_var.get() == "Not connected" and panel.state_pill.text == "Idle"
    d.add(OTHER)
    panel.show_devices((None, None, {}))
    assert panel.name_var.get() == "No active device"
    assert panel.addr_var.get() == "Make a connected board active."
    d.scanning = True
    panel.update_state()
    assert panel.state_pill.text == "Scanning…" and not panel.scan_btn.enabled
    assert not panel.connect_btn.enabled


def test_connect_adds_a_board_and_is_refused_for_a_connected_one(panel):
    d = panel.ctx.devices
    panel._connect()
    assert d.order == ["connect"] and d.get(ADDR) is not None
    panel.show_devices((d.get(ADDR), LinkState.CONNECTING, {}))
    assert not panel.connect_btn.enabled and not panel.scan_btn.enabled, "connecting"
    event(panel, d.get(ADDR), LinkState.CONNECTED)
    assert not panel.connect_btn.enabled, "connected already"
    panel._connect()
    assert d.order == ["connect"]
    panel.tree.sel = (OTHER,)
    panel.update_state()
    assert panel.connect_btn.enabled and panel.scan_btn.enabled, "another board may be added"


def test_nearby_list_marks_connected_boards(panel):
    panel._results = [ScanResult(ADDR, "ProjectHanuman", -50, []),
                      ScanResult(OTHER, "ProjectHanuman", -60, [])]
    panel.ctx.devices.add(ADDR)
    panel._show_results()
    assert panel.tree.rows[ADDR][0][0] == "ProjectHanuman (connected)"
    assert panel.tree.rows[OTHER][0][0] == "ProjectHanuman"


def test_make_active(panel, dialogs):
    d = panel.ctx.devices
    a, b = d.add(ADDR), d.add(OTHER)
    d.active = a
    panel.show_devices((None, None, {}))
    panel.dev_tree.sel = (OTHER,)
    panel.update_state()
    assert panel.active_btn.enabled
    panel._make_active()
    assert d.active is b and dialogs["info"] == []
    panel.update_state()
    assert not panel.active_btn.enabled, "already the active device"
    # A page is busy: refused, and the page says why
    panel.dev_tree.sel = (ADDR,)
    panel.busy = d.busy = True
    panel.update_state()
    assert not panel.active_btn.enabled
    panel._make_active()
    assert d.active is b and dialogs["info"] == [cp.BUSY_TEXT]


def test_disconnect_the_selected_board(panel, dialogs):
    d = panel.ctx.devices
    a = d.add(ADDR)
    d.add(OTHER)
    d.active = a
    panel.dev_tree.sel = (OTHER,)
    panel.update_state()
    assert panel.disconnect_btn.enabled
    panel._disconnect()
    assert d.disconnected == [OTHER] and dialogs["asked"] == []
    # Nothing selected: the active device
    panel.dev_tree.sel = ()
    panel.busy = True
    dialogs["answer"] = False
    panel._disconnect()
    assert d.disconnected == [OTHER] and "Abort it and disconnect ProjectHanuman" in dialogs["asked"][0][1]
    dialogs["answer"] = True
    panel._disconnect()
    assert d.disconnected == [OTHER, ADDR]


def test_link_details_follow_the_active_device(panel):
    d = panel.ctx.devices
    a, b = d.add(ADDR), d.add(OTHER)
    d.active = a
    panel.show_devices((None, None, {}))
    panel._caps_done((2, 244, 16, 247))
    assert panel.details.is_open and panel._facts["Protocol"].get() == "v2"
    d.active = b
    panel.show_devices((None, None, {}))
    assert not panel.details.is_open and panel._facts["Protocol"].get() == "–"
    assert panel.caps_var.get() == "" and panel.caps_btn.enabled


# ---- stale keys ----------------------------------------------------------------------------------
def test_drop_while_connecting_offers_to_forget(panel, dialogs):
    # The reported case: the SETU subscription fails, the link is gone before CONNECTED
    panel._connect()
    lost(panel)
    assert len(dialogs["asked"]) == 1
    title, text = dialogs["asked"][0]
    assert title == "Stale pairing keys" and ADDR in text and "chip erase" in text
    assert panel.ctx.devices.unpaired == [ADDR]
    assert any("forgotten on this PC" in t for _, t in panel.ctx.logs)


def test_declining_keeps_the_keys(panel, dialogs):
    dialogs["answer"] = False
    panel._connect()
    lost(panel)
    assert dialogs["asked"] and panel.ctx.devices.unpaired == []


def test_drop_soon_after_connecting(panel, dialogs, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(cp.time, "monotonic", lambda: now[0])
    panel._connect()
    panel.ctx.devices.get(ADDR).connected_at = now[0]
    now[0] += cp.STALE_KEYS_WINDOW_S - 1
    lost(panel)
    assert len(dialogs["asked"]) == 1


def test_late_drop_or_plain_disconnect_asks_nothing(panel, dialogs, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(cp.time, "monotonic", lambda: now[0])
    panel._connect()
    panel.ctx.devices.get(ADDR).connected_at = now[0]
    now[0] += cp.STALE_KEYS_WINDOW_S + 1
    lost(panel)
    panel._connect()
    event(panel, panel.ctx.devices.get(ADDR), LinkState.IDLE, reason="disconnected")
    assert dialogs["asked"] == []


def test_another_boards_drop_is_checked_for_that_board(panel, dialogs):
    # Each board has its own attempt: B dropping is asked about B, not the active A
    d = panel.ctx.devices
    a = d.add(ADDR)
    a.connected_at = 0.0
    d.active = a
    d.paired = {OTHER}
    panel.tree.sel = (OTHER,)
    panel.tree.names[OTHER] = "board B"
    panel._connect()
    lost(panel, OTHER)
    assert len(dialogs["asked"]) == 1 and OTHER in dialogs["asked"][0][1]
    assert d.unpaired == [OTHER] and d.active is a


def test_unpaired_board_asks_nothing(panel, dialogs):
    panel.ctx.devices.paired = set()
    panel._connect()
    lost(panel)
    assert dialogs["asked"] == []


def test_lookup_failure_is_logged_quietly(panel, dialogs):
    panel.ctx.devices.lookup_error = RuntimeError("no WinRT")
    panel._connect()
    lost(panel)
    assert dialogs["asked"] == [] and ("warn", f"pairing state of {ADDR} unknown: no WinRT") \
        in panel.ctx.logs


def test_connect_error_after_reaching_the_board(panel, dialogs):
    panel.ctx.devices.connect_error = OSError("Unreachable")
    panel._connect()
    assert dialogs["errors"] and len(dialogs["asked"]) == 1


@pytest.mark.parametrize("exc", [TimeoutError(), type("BleakDeviceNotFoundError", (Exception,), {})()])
def test_unreached_board_asks_nothing(panel, dialogs, exc):
    # A trusted board out of range must not be offered for forgetting
    panel.ctx.devices.connect_error = exc
    panel._connect()
    assert dialogs["errors"] and dialogs["asked"] == []


def test_forget_selected(panel, dialogs):
    panel.update_state()
    assert panel.forget_btn.enabled
    dialogs["answer"] = False
    panel._forget_selected()
    assert panel.ctx.devices.unpaired == []
    dialogs["answer"] = True
    panel._forget_selected()
    assert panel.ctx.devices.unpaired == [ADDR]
    assert "Button 3" in dialogs["asked"][-1][1]


def test_forget_needs_an_unconnected_board_and_a_selection(panel, dialogs):
    panel.ctx.devices.add(ADDR)
    panel.update_state()
    assert not panel.forget_btn.enabled
    panel._forget_selected()
    panel.ctx.devices.sessions.clear()
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
    assert panel.ctx.devices.order == ["unpair", "connect"]
    assert dialogs["asked"] == [] and dialogs["errors"] == []
    assert ("info", "ProjectHanuman has no host bond: this PC's old keys for it removed (unpaired)") \
        in panel.ctx.logs


def test_host_bond_advertised_keeps_the_keys(panel, dialogs):
    advert(panel, 0x03)                            # provisioned, host bonded
    panel._connect()
    assert panel.ctx.devices.order == ["connect"] and panel.ctx.devices.unpaired == []


def test_no_keys_held_nothing_to_remove(panel, dialogs):
    advert(panel, 0x01)
    panel.ctx.devices.paired = set()
    panel._connect()
    assert panel.ctx.devices.order == ["connect"]


def test_cleanup_failures_still_connect(panel, dialogs):
    advert(panel, 0x00)
    d = panel.ctx.devices
    d.lookup_error = PairingUnavailable("not Windows")
    panel._connect()
    assert d.order == ["connect"] and panel.ctx.logs == [], "quiet off Windows"
    d.sessions.clear()
    d.lookup_error = RuntimeError("WinRT broke")
    panel._connect()
    assert d.order == ["connect", "connect"]
    assert any(level == "warn" and "could not check this PC's keys" in t for level, t in panel.ctx.logs)


def test_real_page(tk_root):
    from blehost.context import AppContext
    page = cp.ConnectionPanel(tk_root, AppContext(), is_busy=lambda: False)
    assert page.forget_btn is not None and page.dev_tree.get_children() == ()
    page.show_devices((None, None, {}))
    assert "disabled" in page.active_btn.state() and "disabled" in page.caps_btn.state()
    page.destroy()
