# SPDX-License-Identifier: MIT
"""The Host Access page (_TOOLS/BleHostGUI/blehost/features/host_access.py).

The page's logic (credential load/issue, which buttons are enabled, status,
authenticate, forget, abort, the pills and the step list) runs against
stand-in Tk variables and widgets, a fake AppContext whose run() executes the
coroutine at once, and a fake HostAuthSession (the protocol itself is
test_host_auth.py). One test builds the real page on conftest's shared Tk root;
it is skipped where Tk has no display (headless CI).
"""

import asyncio
import os

import pytest

from blehost.core.gatt_server import PcGattServer
from blehost.features import host_access as fh
from blehost.pki.authority import CertificateAuthority
from blehost.protocols import host_auth as ha
from blehost.protocols import setu as setu_proto

OPEN = ha.AuthStatus(ha.OPEN, ha.FLAG_WINDOW_OPEN)
TRUSTED = ha.AuthStatus(ha.TRUSTED, ha.FLAG_HOST_BOND)


class Var:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Button:
    def __init__(self):
        self.enabled = True
        self.after_calls = []

    def state(self, spec):
        self.enabled = spec == ["!disabled"]

    def after(self, ms, fn):
        self.after_calls.append((ms, fn))


class Pill:
    def __init__(self):
        self.text, self.tone = "", ""

    def set(self, text, tone):
        self.text, self.tone = text, tone


class Disclosure:
    def __init__(self):
        self.is_open = None

    def set_open(self, value):
        self.is_open = value


class Bus:
    def call(self, fn, *args):
        fn(*args)


class Future:
    def __init__(self, on_cancel=None):
        self.cancelled = False
        self._on_cancel = on_cancel

    def cancel(self):
        self.cancelled = True
        if self._on_cancel:
            self._on_cancel()


class Link:
    def __init__(self):
        self.connected = True
        self.unpairs = 0
        self.pins = []

    async def pair_with_pin(self, pin):
        self.pins.append(pin)

    async def unpair(self):
        self.unpairs += 1
        return "unpaired"


class Ctx:
    def __init__(self):
        self.bus = Bus()
        self.link = Link()
        self.setu_svc = type("S", (), {"available": True, "new_client": lambda s: "device-client"})()
        self.pc = type("Pc", (), {"available": True, "receiver": "pc-receiver"})()
        self.services = {setu_proto.SETUService.NAME: self.setu_svc, PcGattServer.NAME: self.pc}
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


class Session:
    made = []
    fail = None
    status = OPEN

    def __init__(self, client, receiver, cred, pair, log, step):
        Session.made.append(self)
        self.client, self.receiver, self.cred, self.pair, self.log, self.step = (
            client, receiver, cred, pair, log, step)
        self.calls = []

    async def get_status(self):
        self.calls.append("status")
        return Session.status

    async def run(self):
        self.calls.append("run")
        self.step("sending HELLO")
        if Session.fail:
            raise ha.HostAuthError(Session.fail, 0x05)
        await self.pair(123456)
        self.step("trusted")
        Session.status = TRUSTED


@pytest.fixture
def dialogs(monkeypatch):
    seen = {"errors": [], "ask": True, "dir": ""}
    monkeypatch.setattr(fh.messagebox, "showerror", lambda t, m: seen["errors"].append(m))
    monkeypatch.setattr(fh.messagebox, "askyesno", lambda t, m: seen["ask"])
    monkeypatch.setattr(fh.filedialog, "askdirectory", lambda **kw: seen["dir"])
    return seen


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority.create(str(tmp_path / "ca"), {"CN": "Page CA"})


@pytest.fixture
def page(tmp_path, monkeypatch, dialogs, ca):
    Session.made, Session.fail, Session.status = [], None, OPEN
    monkeypatch.setattr(fh.ha, "HostAuthSession", Session)
    f = fh.HostAccessFeature(Ctx())
    for name in ("dev_var", "hint_var", "step_var", "cred_var", "folder_var", "ca_folder_var",
                 "name_var", "days_var"):
        setattr(f, name, Var())
    f.folder_var.set(str(tmp_path / "host"))
    f.ca_folder_var.set(ca.folder)
    f.name_var.set("Laptop")
    f.days_var.set("30")
    for name in ("auth_btn", "status_btn", "abort_btn", "forget_btn"):
        setattr(f, name, Button())
    f.state_pill, f.cred_pill = Pill(), Pill()
    f._settings = Disclosure()
    return f


def enabled(f):
    return {n for n in ("auth", "status", "abort", "forget") if getattr(f, f"{n}_btn").enabled}


def logged(f):
    return "\n".join(t for _, t in f.ctx.logs)


# ---- helpers ---------------------------------------------------------------------
def test_step_position_and_pill():
    assert fh.step_position("") == (0, "idle")
    assert fh.step_position("sending HELLO") == (1, "running")
    assert fh.step_position("waiting for the device's CHALLENGE") == (1, "running")
    assert fh.step_position("pairing (passkey entry)") == (4, "running")
    assert fh.step_position("trusted") == (5, "done")
    assert fh.step_position("failed", 3) == (3, "failed")
    assert fh.step_position("something else", 2) == (2, "running")
    assert fh.state_pill("Device: TRUSTED") == ("Trusted", "ok")
    assert fh.state_pill("Device: HOST_BONDED, window open") == ("Another host", "warn")
    assert fh.state_pill("Device: -") == ("Unknown", "idle")


# ---- credential ------------------------------------------------------------------
def test_issue_and_load(page, dialogs, ca):
    page._issue()
    assert dialogs["errors"] == []
    assert page.cred is not None and page.cred.name == "CN=Laptop"
    assert os.path.exists(os.path.join(page.folder_var.get(), "host_key.pem"))
    assert page.cred_pill.text == "Loaded" and page._settings.is_open is False
    assert "keep this folder private" in logged(page)
    page.cred = None
    page._load()
    assert page.cred is not None and "CA CN=Page CA" in page.cred_var.get()


def test_issue_errors(page, dialogs, tmp_path):
    page.days_var.set("x")
    page._issue()
    assert "invalid literal" in dialogs["errors"][-1]
    page.days_var.set("30")
    page.ca_folder_var.set(str(tmp_path / "no_ca"))
    page._issue()
    assert "no CA in" in dialogs["errors"][-1]
    assert page.cred is None


def test_load_missing(page, dialogs):
    page._load(quiet=True)
    assert page.cred is None and dialogs["errors"] == []
    assert page.cred_pill.text == "None" and page._settings.is_open is True
    page._load()
    assert "no host credential" in dialogs["errors"][-1]


def test_browse(page, dialogs):
    before = page.folder_var.get()
    page._browse(page.folder_var, "x")
    assert page.folder_var.get() == before
    dialogs["dir"] = "C:/creds"
    page._browse(page.folder_var, "x")
    assert page.folder_var.get() == "C:/creds"


# ---- buttons ---------------------------------------------------------------------
def test_buttons(page):
    page.ctx.link.connected = False
    page._update()
    assert enabled(page) == set()
    page.ctx.link.connected = True
    page._update()
    assert enabled(page) == {"status", "forget"}, "authenticating needs a credential"
    page._issue()
    assert enabled(page) == {"status", "forget", "auth"}
    page.ctx.pc.available = False
    page._update()
    assert "auth" not in enabled(page), "CHALLENGE needs the PC's service"
    page.ctx.pc.available = True
    page.status = TRUSTED
    page._update()
    assert "auth" not in enabled(page), "trusted already"


def test_busy_enables_only_abort(page):
    page._issue()
    page.ctx.hold = True
    page._authenticate()
    assert page.busy and enabled(page) == {"abort"}
    page.cancel()
    assert not page.busy and page.step_var.get() == "aborted"


# ---- device ----------------------------------------------------------------------
def test_status_shows_state_and_hint(page):
    page._get_status()
    page.ctx.flush()
    assert page.dev_var.get() == "Device: OPEN, window open"
    assert "authenticate this PC" in page.hint_var.get()
    Session.status = ha.AuthStatus(ha.HOST_BONDED, ha.FLAG_HOST_BOND)
    page._get_status()
    page.ctx.flush()
    assert "Button 3" in page.hint_var.get()


def test_status_needs_a_link(page):
    page.ctx.link.connected = False
    page._get_status()
    assert Session.made == []


def test_status_failure_is_quiet(page, monkeypatch):
    async def boom(self):
        raise ha.HostAuthError("no AUTH_STATUS from the device")
    monkeypatch.setattr(Session, "get_status", boom)
    page._get_status()
    page.ctx.flush()
    assert page.step_var.get() == "" and ("warn", "host access: failed: no AUTH_STATUS from the device") \
        in page.ctx.logs


def test_authenticate(page):
    page._issue()
    page._authenticate()
    page.ctx.flush()
    s = Session.made[-1]
    assert (s.client, s.receiver, s.cred) == ("device-client", "pc-receiver", page.cred)
    assert s.calls == ["run", "status"]
    assert page.ctx.link.pins == [123456], "the passkey goes to the link's pairing"
    assert page.dev_var.get() == "Device: TRUSTED" and page.step_var.get() == "trusted"
    assert "now the device's trusted host" in logged(page)


def test_authenticate_failure(page):
    page._issue()
    Session.fail = "another host is bonded"
    page._authenticate()
    page.ctx.flush()
    assert page.step_var.get() == "failed"
    assert ("error", "host access: failed: another host is bonded") in page.ctx.logs
    # The page stays usable: retry at once, and the device's state is read again
    assert page.hint_var.get() == fh.RETRY_HINT
    assert "auth" in enabled(page) and not page.busy
    assert page.auth_btn.after_calls and page.auth_btn.after_calls[-1][1] == page._get_status


def test_retry_after_windows_drops_the_link(page):
    # The pairing fails, Windows drops the link, the user reconnects and retries
    page._issue()
    Session.fail = "pairing failed: rejected_by_handler"
    page._authenticate()
    page.ctx.flush()
    page.ctx.link.connected = False
    page.on_disconnected("link lost")
    assert page.hint_var.get() == fh.RETRY_HINT, "the hint says how to retry"
    assert enabled(page) == set()
    page.ctx.link.connected = True
    page.on_connected({"address": "AA"})
    assert page.step_var.get() == "", "the step list starts again"
    assert "auth" in enabled(page)
    Session.fail = None
    page._authenticate()
    page.ctx.flush()
    assert page.step_var.get() == "trusted" and page.dev_var.get() == "Device: TRUSTED"


def test_abort_allows_a_retry(page):
    page._issue()
    page.ctx.hold = True
    page._authenticate()
    page.cancel()
    assert page.hint_var.get() == fh.RETRY_HINT and "auth" in enabled(page)


def test_plain_disconnect_resets_the_hint(page):
    page.hint_var.set(fh.HINTS["OPEN"])
    page.on_disconnected("link lost")
    assert page.hint_var.get() == fh.CONNECT_HINT


def test_forget_asks_first(page, dialogs):
    dialogs["ask"] = False
    page._forget()
    page.ctx.flush()
    assert page.ctx.link.unpairs == 0
    dialogs["ask"] = True
    page._forget()
    page.ctx.flush()
    assert page.ctx.link.unpairs == 1 and "keys removed on the PC (unpaired)" in logged(page)


def test_connect_and_disconnect(page):
    page.status = TRUSTED
    page.on_connected({"address": "AA"})
    assert page.status is None and page.dev_var.get() == "Device: -"
    assert page.auth_btn.after_calls, "the state is read after connecting"
    page.ctx.hold = True
    page._get_status()
    held = page.ctx.held
    page.on_disconnected("link lost")
    assert held.cancelled and not page.busy


# ---- the real page ---------------------------------------------------------------
def test_build_real_page(monkeypatch, tmp_path, ca, tk_root):
    folder = str(tmp_path / "host")
    ca.issue_host("Real", folder)
    monkeypatch.setattr(fh, "DEFAULT_FOLDER", folder)
    f = fh.HostAccessFeature(Ctx())
    f.ctx.link.connected = False
    frame = f.build(tk_root)
    assert frame.winfo_children()
    assert f.cred is not None, "an existing credential is loaded at start-up"
    assert f.cred_pill.text == "Loaded"
    assert "disabled" in f.auth_btn.state()
    f.dev_var.set("Device: TRUSTED")
    assert f.state_pill.text == "Trusted"
    f.step_var.set("sending FINISH")
    assert f.stepper.current == 3
