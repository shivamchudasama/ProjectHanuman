# SPDX-License-Identifier: MIT
"""The Pairing page (_TOOLS/BleHostGUI/blehost/features/pairing.py).

The page's logic (list the boards connected on the Device page and those
with the Pairing service, choose the roles, check the chosen devices, pair
over the boards' own links and leave them up, refuse devices paired with each
other, cancel, unpair, which buttons are enabled, what the pills and step
lists show) runs against stand-in Tk variables and buttons, a fake AppContext
whose run() executes the coroutine at once, and the simulated devices of
test_pairing.py behind fake links held by DeviceSessions, as the Device page
connects them (the orchestrator itself is tested there). One test builds the
real Tk page on conftest's shared Tk root.
"""

import asyncio
import functools

import pytest

from blehost.core.decoders import DecoderRegistry
from blehost.core.devices import DeviceSession
from blehost.features import pairing as fpair
from blehost.protocols import pairing as pp
from test_pairing import A, B, SimDevice, World

C = ("D0:11:22:33:44:55", 1)


# ---- stand-ins for Tk and the context -------------------------------------------------
class Var:
    def __init__(self, value=""):
        self.value = value
        self.sets = 0

    def get(self):
        return self.value

    def set(self, value):
        self.value = value
        self.sets += 1


class Button:
    def __init__(self):
        self.enabled = True

    def state(self, spec):
        self.enabled = spec == ["!disabled"]


class Bus:
    def call(self, fn, *args):
        fn(*args)


class Future:
    def __init__(self, on_cancel=None):
        self._on_cancel = on_cancel

    def cancel(self):
        if self._on_cancel:
            self._on_cancel()


class Boards:
    """The DeviceManager surface the page uses: the connected boards."""

    def __init__(self, world):
        self.world = world
        self.sessions = {}

    def connect(self, address):
        link = self.world.make_link(f"board {address[-5:]}")
        asyncio.run(link.connect(address))
        s = DeviceSession(address, f"dev-{address[:2]}", link)
        self.sessions[s.key] = s
        return s

    def drop(self, address):
        self.sessions.pop(address).link.connected = False

    def get(self, address):
        return self.sessions.get((address or "").upper())

    def connected(self):
        return [s for s in self.sessions.values() if s.connected]


class Ctx:
    def __init__(self, world):
        self.bus = Bus()
        self.devices = Boards(world)
        self.decoders = DecoderRegistry()
        self.settings = type("Settings", (), {"scan_timeout": 0.1})()
        self.logs = []
        self.hold = False
        self.held = None
        self.pending = []

    def log(self, text, level="info"):
        self.logs.append((level, text))

    def run(self, coro, on_done=None, on_error=None, on_cancel=None):
        if self.hold:
            coro.close()
            self.held = Future(on_cancel)
            return self.held
        try:
            result = asyncio.run(coro)
        except Exception as e:                 # noqa: BLE001 - mirrors AppContext.run
            self.pending.append(lambda exc=e: on_error(exc))
        else:
            self.pending.append(lambda: on_done(result))
        return Future()

    def flush(self):
        while self.pending:
            self.pending.pop(0)()


@pytest.fixture
def fast(monkeypatch):
    """The page's orchestrator with test timings."""
    monkeypatch.setattr(fpair.pairing, "PairingOrchestrator", functools.partial(
        pp.PairingOrchestrator, timeout=1.0, fail_grace=0.1, poll=0.02, start_settle=0.0))


@pytest.fixture
def dialogs(monkeypatch):
    seen = {"errors": [], "ask": True}
    monkeypatch.setattr(fpair.messagebox, "showerror", lambda t, m: seen["errors"].append(m))
    monkeypatch.setattr(fpair.messagebox, "askyesno", lambda t, m: seen["ask"])
    return seen


def make_page(world):
    """A PairingFeature with stand-in widgets, as build() would leave it."""
    f = fpair.PairingFeature(Ctx(world))
    for name in ("central_var", "peripheral_var", "result_var", "hint_var"):
        setattr(f, name, Var())
    f.role_vars = {"central": Var(), "peripheral": Var()}
    for name in ("check_btn", "swap_btn", "pair_btn", "cancel_btn",
                 "unpair_c_btn", "unpair_p_btn"):
        setattr(f, name, Button())
    return f


@pytest.fixture
def page(fast, dialogs):
    c, p = SimDevice(A[0]), SimDevice(B[0])
    world = World(c, p)
    f = make_page(world)
    f.world = world
    return f


def listed(f):
    """Connect every simulated board on the 'Device page', as it would."""
    for addr in f.world.devices:
        if f.ctx.devices.get(addr) is None:
            f.ctx.devices.connect(addr)
    f.on_devices_changed()
    return f


def links(f):
    return [s.link for s in f.ctx.devices.sessions.values()]


def logged(f) -> str:
    return "\n".join(text for _, text in f.ctx.logs)


def enabled(f):
    return {n for n in ("check", "swap", "pair", "cancel", "unpair_c", "unpair_p")
            if getattr(f, f"{n}_btn").enabled}


# ---- display helpers ------------------------------------------------------------------
def test_choice_texts():
    text = fpair.choice_text("dev", A[0])
    assert text == f"dev [{A[0]}]"
    assert fpair.choice_address(text) == A[0] and fpair.choice_name(text) == "dev"
    assert fpair.choice_address(fpair.choice_text("", A[0].lower())) == A[0]
    assert fpair.choice_text("", A[0]).startswith("(no name)")
    assert fpair.choice_address("") == "" and fpair.choice_address("dev") == ""


def test_row_status():
    st = lambda **kw: pp.PairStatus(**{**dict(state=0, error=0, detail=0, prov_state=3, role=0,
                                               own=A[0], own_type=1, peer="", peer_type=0), **kw})
    assert fpair.row_status(None) == ""
    assert fpair.row_status(OSError("gone")) == "error: gone"
    assert fpair.row_status(st(prov_state=1)) == "not provisioned"
    assert fpair.row_status(st(state=7, peer=B[0])) == f"paired with {B[0]}"
    assert fpair.row_status(st(state=7)) == "paired"
    assert fpair.row_status(st(state=3)) == "pairing…"
    assert fpair.row_status(st(state=8, error=7)) == "ready (last run failed: PEER_CERT)"
    assert fpair.row_status(st()) == "ready"


@pytest.mark.parametrize("text, pill, step", [
    ("", ("Not started", "idle"), (0, "idle")),
    ("IDLE", ("Idle", "idle"), (0, "idle")),
    ("ARMED as central, peer x", ("Armed", "info"), (0, "running")),
    ("CERT_VERIFIED as central", ("Cert Verified", "info"), (3, "running")),
    ("PAIRING as peripheral", ("Pairing", "info"), (5, "running")),
    ("PAIRED as central, peer x", ("Paired", "ok"), (6, "done")),
    ("FAILED as central: cancelled", ("Failed", "err"), (2, "failed")),
])
def test_role_pill_and_steps(text, pill, step):
    assert fpair.role_pill(text) == pill
    assert fpair.step_position(text, current=2) == step


def test_result_pill():
    assert fpair.result_pill("") == ("Idle", "idle")
    assert fpair.result_pill("Running…") == ("Running", "info")
    assert fpair.result_pill("Paired: both") == ("Paired", "ok")
    assert fpair.result_pill("Cancelled (…)") == ("Cancelled", "warn")
    assert fpair.result_pill("Failed: x") == ("Failed", "err")
    assert fpair.result_pill("Not started: x") == ("Failed", "err")
    assert fpair.result_pill("Checked: central ready") == ("Checked", "info")


# ---- the boards, check, roles ----------------------------------------------------------
def test_decoders_are_registered(page):
    assert page.ctx.decoders.name(pp.STATUS_UUID) == "PAIR STATUS"


def test_lists_connected_boards_with_the_service_and_proposes_roles(page):
    page.world.devices[C[0]] = SimDevice(C[0])
    page.world.devices[C[0]].has_service = False     # not provisioned: no Pairing service
    listed(page)
    assert set(page._found) == {A[0], B[0]}, "only boards with the Pairing service"
    assert fpair.choice_address(page.central_var.get()) == A[0]
    assert fpair.choice_address(page.peripheral_var.get()) == B[0]
    # A refresh keeps the user's choice
    page.central_var.set(fpair.choice_text("dev", B[0]))
    page.on_devices_changed()
    assert fpair.choice_address(page.central_var.get()) == B[0]


def test_a_board_that_goes_clears_its_choice(page):
    listed(page)
    page._check()
    page.ctx.flush()
    assert set(page._checked) == {A[0], B[0]}
    page.ctx.devices.drop(B[0])
    page.on_devices_changed()
    assert page.peripheral_var.get() == "" and set(page._found) == {A[0]}
    assert set(page._checked) == {A[0]}
    assert page.hint_var.get() == fpair.CONNECT_HINT and "pair" not in enabled(page)


def test_check_reads_the_chosen_devices(page):
    page.world.devices[C[0]] = SimDevice(C[0])
    listed(page)
    page.world.devices[B[0]].prov_state = 1
    page._check()
    page.ctx.flush()
    assert set(page._checked) == {A[0], B[0]}, "only the chosen central and peripheral"
    assert page._checked[A[0]].provisioned
    assert fpair.row_status(page._checked[B[0]]) == "not provisioned"
    assert "peripheral dev-E1: not provisioned" in logged(page)
    # Shown in the progress pane
    assert page.role_vars["central"].get() == "IDLE"
    assert page.role_vars["peripheral"].get() == "IDLE"
    assert page.result_var.get() == "Checked: central ready; peripheral not provisioned"
    assert fpair.result_pill(page.result_var.get()) == ("Checked", "info")
    # A board whose link went before the list caught up shows its error, the other its status
    page.ctx.devices.get(C[0]).link.connected = False
    page.peripheral_var.set(fpair.choice_text("dev-D0", C[0]))
    page._check()
    page.ctx.flush()
    assert ("peripheral dev-D0: error: dev-D0 is not connected: connect it on the Device page"
            in logged(page))
    assert page.role_vars["peripheral"].get() == ""
    assert "peripheral error:" in page.result_var.get()
    assert C[0] not in page._checked and page.peripheral_var.get() == "", "gone from the list"
    # One role chosen: only that one
    page.peripheral_var.set("")
    page._checked.clear()
    page._check()
    page.ctx.flush()
    assert set(page._checked) == {A[0]} and page.result_var.get() == "Checked: central ready"


def test_check_shows_devices_paired_with_each_other(page):
    listed(page)
    a, b = page.world.devices[A[0]], page.world.devices[B[0]]
    a.state, a.peer, a.peer_type, a.role = pp.State.PAIRED, B[0], 1, 1
    b.state, b.peer, b.peer_type, b.role = pp.State.PAIRED, A[0], 1, 2
    page._check()
    page.ctx.flush()
    assert page.role_vars["central"].get().startswith("PAIRED as central")
    assert page.role_vars["peripheral"].get().startswith("PAIRED as peripheral")
    assert page.result_var.get().startswith("Paired with each other already")
    assert fpair.result_pill(page.result_var.get()) == ("Paired", "ok")


def test_paired_devices_are_not_paired_again(page, dialogs):
    listed(page)
    page._pair()
    page.ctx.flush()
    assert "pair" not in enabled(page), "paired with each other: unpair one first"
    assert "paired with each other already" in page.hint_var.get()
    controls = list(page.world.devices[A[0]].controls)
    page._pair()
    assert dialogs["errors"] and "paired with each other already" in dialogs["errors"][0]
    assert page.world.devices[A[0]].controls == controls, "no START"
    # Swapped roles are the same two devices
    page._swap()
    page._update()
    assert "pair" not in enabled(page)
    # Unpairing one of them allows a new run
    page._unpair("central")
    page.ctx.flush()
    assert "pair" in enabled(page) and page.hint_var.get() == ""
    page._pair()
    page.ctx.flush()
    assert page.result_var.get().startswith("Paired: both devices paired")


def test_paired_devices_found_by_another_tool_are_refused(page):
    """The page's statuses may be stale: the orchestrator checks again."""
    listed(page)
    a, b = page.world.devices[A[0]], page.world.devices[B[0]]
    a.state, a.peer, a.peer_type = pp.State.PAIRED, B[0], 1
    b.state, b.peer, b.peer_type = pp.State.PAIRED, A[0], 1
    page._update()
    assert "pair" in enabled(page), "not checked since"
    page._pair()
    page.ctx.flush()
    assert page.result_var.get().startswith("Not started: the devices are paired with each other")
    assert a.controls == [] and b.controls == []


def test_swap(page):
    listed(page)
    page._swap()
    assert fpair.choice_address(page.central_var.get()) == B[0]
    assert fpair.choice_address(page.peripheral_var.get()) == A[0]


def test_buttons(page):
    page._update()
    assert enabled(page) == {"swap"}, "nothing to check or pair yet"
    assert page.hint_var.get() == fpair.CONNECT_HINT
    listed(page)
    assert enabled(page) == {"check", "swap", "pair", "unpair_c", "unpair_p"}
    assert page.hint_var.get() == ""

    # The same device twice
    page.peripheral_var.set(page.central_var.get())
    page._update()
    assert "pair" not in enabled(page) and page.hint_var.get() == "Choose two different devices."

    # Busy: only Cancel
    page._swap()
    page.peripheral_var.set(fpair.choice_text("dev", B[0]))
    page.ctx.hold = True
    page._pair()
    assert enabled(page) == {"cancel"}


# ---- pair, cancel, unpair ----------------------------------------------------------------
def test_pair(page):
    listed(page)
    page._pair()
    assert page.result_var.get() == "Running…"
    page.ctx.flush()
    assert page.result_var.get().startswith("Paired: both devices paired")
    assert page.role_vars["central"].get().startswith("PAIRED as central")
    assert page.role_vars["peripheral"].get().startswith("PAIRED as peripheral")
    assert page._checked[A[0]].paired and page._checked[B[0]].paired
    assert "pairing dev-C4 (central) with dev-E1 (peripheral)" in logged(page)
    assert "paired; the devices keep their encrypted link" in logged(page)
    assert not page.busy
    # Over the Device page's links, which stay up for the other pages
    assert len(page.world.links) == 2, "no link of its own"
    assert all(link.connected and link.disconnects == 0 and link.unsubscribed == 1
               for link in links(page))


def test_pair_shows_both_devices_live(page):
    """Each STATUS notification reaches its role's step list while pairing."""
    listed(page)
    seen = []
    page.role_vars["central"].set = lambda v: seen.append(v)
    page._pair()
    page.ctx.flush()
    states = [v.split(" ")[0] for v in seen]
    assert states[0] == "" and "ARMED" in states and "CERT_EXCHANGE" in states and states[-1] == "PAIRED"


def test_pair_failure(page):
    listed(page)
    c, p = page.world.devices[A[0]], page.world.devices[B[0]]
    c.outcome, p.outcome = ("fail", pp.Error.PEER_CERT, 5), "lost"
    c.peer_dev, p.peer_dev = p, c
    page._pair()
    page.ctx.flush()
    assert page.result_var.get().startswith("Failed: central: the peer's certificate was rejected")
    assert page.role_vars["central"].get().startswith("FAILED")
    assert ("error", "pairing: failed: central: the peer's certificate was rejected (BAD_SIG); "
                     "peripheral: the link between the devices dropped (detail 0x08)") in page.ctx.logs


def test_pair_not_started(page):
    listed(page)
    page.world.devices[B[0]].prov_state = 2
    page._pair()
    page.ctx.flush()
    assert page.result_var.get() == "Not started: the peripheral device is not provisioned"
    assert "pair failed: the peripheral device is not provisioned" in logged(page)
    assert not page.busy


def test_pair_needs_two_devices(page, dialogs):
    page._pair()
    assert dialogs["errors"] and "two different devices" in dialogs["errors"][0]
    assert page.world.links == [], "nothing connected by the page"
    listed(page)
    page.peripheral_var.set(page.central_var.get())
    page._pair()
    assert len(dialogs["errors"]) == 2


def test_cancel(page):
    listed(page)
    page.ctx.hold = True
    page._pair()
    assert page.busy
    page.cancel()
    assert page.result_var.get().startswith("Cancelled")
    assert not page.busy
    page.cancel()                                   # nothing running: no effect


def test_unpair(page, dialogs):
    listed(page)
    dev = page.world.devices[B[0]]
    dev.state, dev.peer, dev.peer_type = pp.State.PAIRED, A[0], 1
    dialogs["ask"] = False
    page._unpair("peripheral")
    page.ctx.flush()
    assert dev.controls == [], "not confirmed"
    dialogs["ask"] = True
    page._unpair("peripheral")
    page.ctx.flush()
    assert dev.controls == [pp.encode_unpair()]
    assert page.role_vars["peripheral"].get() == "IDLE"
    assert "dev-E1 unpaired: IDLE" in logged(page)
    page.central_var.set("")
    page._unpair("central")                         # no role chosen: nothing
    assert page.world.devices[A[0]].controls == []


def test_the_active_device_does_not_matter(page):
    # Any connected board may be paired, whichever one the other pages act on
    listed(page)
    page.on_connected({"switched": True})
    assert "pair" in enabled(page)
    page.on_disconnected("switched")
    assert "pair" in enabled(page)


# ---- the real page --------------------------------------------------------------------------
def test_build_real_page(tk_root, fast):
    world = World(SimDevice(A[0]), SimDevice(B[0]), SimDevice(C[0]))
    world.devices[C[0]].has_service = False
    f = fpair.PairingFeature(Ctx(world))
    f.world = world
    frame = f.build(tk_root)                        # passive theme (theme.of)
    assert frame.winfo_children()
    assert "disabled" in f.pair_btn.state() and "disabled" in f.check_btn.state()
    assert f.found_pill.text == "None connected"
    listed(f)
    assert len(f.tree.get_children()) == 3, "every connected board is listed"
    assert f.tree.set(C[0], "status") == fpair.NO_SERVICE
    assert len(f._combos[0].cget("values")) == 2, "only boards with the Pairing service"
    assert f.found_pill.text == "2 connected"
    assert "disabled" not in f.pair_btn.state()
    f.role_vars["central"].set("CERT_EXCHANGE as central, peer x")
    assert f.role_pills["central"].text == "Cert Exchange"
    assert (f.steppers["central"].current, f.steppers["central"].state) == (2, "running")
    f.result_var.set("Paired: both")
    assert f.result_pill.text == "Paired"
