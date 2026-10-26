# SPDX-License-Identifier: MIT
"""The Provisioning tab (_TOOLS/BleHostGUI/blehost/features/provisioning.py).

The tab's logic (CA create/load, which buttons are enabled, status, provision,
deprovision, abort, save) runs against stand-in Tk variables and buttons, a
fake AppContext whose run() executes the coroutine at once, and a fake
ProvisioningSession (the protocol itself is test_provisioning.py). One test
builds the real Tk tab on conftest's shared Tk root; it is skipped where Tk has
no display (headless CI).
"""

import asyncio
import os
import types

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from blehost.core.gatt_server import PcGattServer
from blehost.features import provisioning as fp
from blehost.pki.authority import CertificateAuthority
from blehost.protocols import setu as setu_proto
from blehost.protocols import provisioning as prov

STATUS = prov.DeviceStatus(prov.KEY_READY, 0, 371, bytes(range(32)))
PROVISIONED = prov.DeviceStatus(3, 0, 0, bytes(range(32)))


# ---- stand-ins for Tk ------------------------------------------------------------
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


# ---- fakes for the context ---------------------------------------------------------
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


class Ctx:
    """run() executes the coroutine at once, but, like AppContext.run (through
    the Tk event queue), calls back only later: flush() delivers the callbacks.
    With hold=True the work stays in progress until cancelled."""

    def __init__(self):
        self.bus = Bus()
        self.link = type("Link", (), {"connected": True, "forgets": 0,
                                      "forget_keys_after_disconnect":
                                      lambda self: setattr(self, "forgets", self.forgets + 1)})()
        self.setu_client = type("Bx", (), {"available": True, "new_client": lambda s: "device-client"})()
        self.pc = type("Pc", (), {"available": True, "subscribers": 0, "error": None,
                                  "receiver": "pc-receiver"})()
        self.services = {setu_proto.SETUService.NAME: self.setu_client, PcGattServer.NAME: self.pc}
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
    """Stands in for ProvisioningSession; records how it was made and used."""
    made = []
    fail = None

    def __init__(self, client, receiver, log, step):
        Session.made.append(self)
        self.client, self.receiver, self.log, self.step = client, receiver, log, step
        self.calls = []

    async def get_status(self):
        self.calls.append("status")
        return Session.status

    async def deprovision(self):
        self.calls.append("deprovision")
        if Session.fail:
            raise prov.ProvisioningError(Session.fail)

    async def provision(self, ca, days):
        self.calls.append(("provision", ca, days))
        self.log("CSR received")
        self.step("sending certificates")
        if Session.fail:
            raise prov.ProvisioningError(Session.fail, 0x05)
        return Session.outcome


@pytest.fixture
def dialogs(monkeypatch):
    seen = {"errors": [], "ask": True, "dir": "", "save": ""}
    monkeypatch.setattr(fp.messagebox, "showerror", lambda t, m: seen["errors"].append(m))
    monkeypatch.setattr(fp.messagebox, "askyesno", lambda t, m: seen["ask"])
    monkeypatch.setattr(fp.filedialog, "askdirectory", lambda **kw: seen["dir"])
    monkeypatch.setattr(fp.filedialog, "asksaveasfilename", lambda **kw: seen["save"])
    return seen


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority.create(str(tmp_path / "ca"), {"CN": "Tab CA"})


@pytest.fixture
def tab(tmp_path, monkeypatch, dialogs, ca):
    """A ProvisioningFeature with stand-in widgets, as build() would leave it."""
    Session.made, Session.fail = [], None
    Session.status = STATUS
    Session.outcome = prov.Outcome(PROVISIONED, b"csr", ca.certificate,
                                   ca.cert_der, "1a2b")
    monkeypatch.setattr(fp.prov, "ProvisioningSession", Session)
    f = fp.ProvisioningFeature(Ctx())
    for name in ("folder_var", "cn_var", "o_var", "c_var", "ca_days_var", "ca_var", "pc_var",
                 "dev_days_var", "dev_var", "step_var"):
        setattr(f, name, Var())
    f.folder_var.set(str(tmp_path / "new_ca"))
    f.cn_var.set("Tab CA 2")
    f.o_var.set("Org")
    f.c_var.set("in")
    f.ca_days_var.set("30")
    f.dev_days_var.set("365")
    for name in ("status_btn", "prov_btn", "abort_btn", "deprov_btn", "save_btn"):
        setattr(f, name, Button())
    return f


def logged(f) -> str:
    """What the tab wrote to the application log (it has no log of its own)."""
    return "\n".join(text for _, text in f.ctx.logs)


def enabled(f):
    return {n for n in ("status", "prov", "abort", "deprov", "save")
            if getattr(f, f"{n}_btn").enabled}


# ---- buttons -------------------------------------------------------------------------
def test_buttons_follow_link_service_ca_and_pc(tab, ca):
    tab.ctx.link.connected = False
    tab._update()
    assert enabled(tab) == set()

    tab.ctx.link.connected = True
    tab._update()
    assert enabled(tab) == {"status", "deprov"}, "Provision needs a CA"

    tab.ca = ca
    tab._update()
    assert enabled(tab) == {"status", "deprov", "prov"}

    tab.ctx.pc.available, tab.ctx.pc.error = False, "no peripheral role"
    tab._update()
    assert "prov" not in enabled(tab), "Provision needs the PC service"
    assert tab.pc_var.get().startswith("PC SETU service: not available (no peripheral role)")

    tab.ctx.setu_client.available = False
    tab._update()
    assert enabled(tab) == set()


def test_pc_service_line(tab):
    tab._show_pc()
    assert tab.pc_var.get() == "PC SETU service: published"
    tab.ctx.pc.subscribers = 1
    tab._tick()
    assert tab.pc_var.get() == "PC SETU service: published, device subscribed"
    assert tab.prov_btn.after_calls, "the line refreshes every second"
    tab.ctx.pc.available = False
    tab._show_pc()
    assert "(starting)" in tab.pc_var.get()


def test_busy_enables_only_abort(tab, ca):
    tab.ca = ca
    tab.ctx.hold = True
    tab._get_status()
    tab.ctx.flush()
    assert tab.busy and enabled(tab) == {"abort"}
    tab.cancel()
    assert not tab.busy and tab.step_var.get() == "aborted"
    assert ("warn", "provisioning: aborted") in tab.ctx.logs
    assert enabled(tab) == {"status", "deprov", "prov"}


# ---- CA ------------------------------------------------------------------------------
def test_create_ca(tab, dialogs):
    tab._create_ca()
    assert dialogs["errors"] == []
    assert tab.ca is not None and tab.ca.subject == "CN=Tab CA 2,O=Org,C=IN"
    assert os.path.exists(os.path.join(tab.folder_var.get(), "ca_key.pem"))
    assert "SHA-256" in tab.ca_var.get() and "0 certificate(s) issued" in tab.ca_var.get()
    assert "keep this folder private" in logged(tab)


@pytest.mark.parametrize("days, exists, match", [
    ("abc", False, "invalid literal"),
    ("0", False, "at least one day"),
    ("30", True, "already exists"),
])
def test_create_ca_errors(tab, dialogs, days, exists, match):
    tab.ca_days_var.set(days)
    if exists:
        tab._create_ca()
        tab.ca = None
    tab._create_ca()
    assert tab.ca is None and match in dialogs["errors"][-1]


def test_load_ca(tab, dialogs, ca):
    tab.folder_var.set(ca.folder)
    tab._load_ca()
    assert tab.ca is not None and tab.ca.fingerprint == ca.fingerprint
    assert dialogs["errors"] == []
    assert f"CA loaded from {ca.folder}" in logged(tab)


def test_load_ca_missing(tab, dialogs, tmp_path):
    tab.folder_var.set(str(tmp_path / "nothing"))
    tab._load_ca(quiet=True)
    assert tab.ca is None and dialogs["errors"] == [] and tab.ca_var.get() == "No CA loaded"
    tab._load_ca()
    assert "no CA in" in dialogs["errors"][-1]


def test_browse(tab, dialogs):
    before = tab.folder_var.get()
    tab._browse()
    assert tab.folder_var.get() == before, "a cancelled dialog keeps the folder"
    dialogs["dir"] = "C:/elsewhere"
    tab._browse()
    assert tab.folder_var.get() == "C:/elsewhere"


# ---- device ----------------------------------------------------------------------------
def test_session_is_wired_to_the_link_and_the_pc_service(tab):
    s = tab._session()
    assert (s.client, s.receiver) == ("device-client", "pc-receiver")
    s.log("hello")
    s.step("step 1")
    assert "hello" in logged(tab) and tab.step_var.get() == "step 1"
    assert ("info", "provisioning: hello") in tab.ctx.logs


def test_get_status(tab):
    tab._get_status()
    tab.ctx.flush()
    assert tab.dev_var.get() == ("Device: KEY_READY, CSR 371 B, key SHA-256 "
                                 + bytes(range(8)).hex() + "…")
    Session.status = prov.DeviceStatus(prov.KEY_READY, prov.FLAG_CSR_TX_BUSY, 371, bytes(32))
    tab._get_status()
    tab.ctx.flush()
    assert "CSR transfer running" in tab.dev_var.get()


def test_provision(tab, ca):
    tab.ca = ca
    tab.dev_days_var.set("90")
    tab._provision()
    tab.ctx.flush()
    assert Session.made[-1].calls == [("provision", ca, 90)]
    assert tab._outcome is Session.outcome and not tab.busy
    assert tab.dev_var.get() == "Device: PROVISIONED, certificate serial 1a2b"
    assert "serial 1a2b" in logged(tab) and "CSR received" in logged(tab)
    assert tab.step_var.get() == "sending certificates"
    assert "save" in enabled(tab)


def test_provision_needs_a_number_of_days(tab, dialogs, ca):
    tab.ca = ca
    tab.dev_days_var.set("a year")
    tab._provision()
    tab.ctx.flush()
    assert Session.made == [] and "number of days" in dialogs["errors"][-1]


def test_provision_failure(tab, ca):
    tab.ca = ca
    Session.fail = "device answered BAD_SIG"
    tab._provision()
    tab.ctx.flush()
    assert tab.step_var.get() == "failed" and tab._outcome is None and not tab.busy
    assert ("error", "provisioning: failed: device answered BAD_SIG") in tab.ctx.logs
    assert "save" not in enabled(tab)


def test_deprovision_asks_first(tab, dialogs):
    dialogs["ask"] = False
    tab._deprovision()
    tab.ctx.flush()
    assert Session.made == []

    dialogs["ask"] = True
    tab._outcome = Session.outcome
    tab._deprovision()
    tab.ctx.flush()
    assert Session.made[-1].calls == ["deprovision", "status"]
    assert tab._outcome is None, "a wipe forgets the last result"
    assert "provisioning removed: device KEY_READY" in logged(tab)
    assert tab.ctx.link.forgets == 1, "the device deleted its bond: the PC's keys go after the link"


def test_deprovision_failure(tab, dialogs):
    Session.fail = "refused"
    tab._deprovision()
    tab.ctx.flush()
    assert tab.step_var.get() == "failed"
    assert tab.ctx.link.forgets == 0, "nothing was wiped"


@pytest.mark.parametrize("ext, loader", [(".pem", x509.load_pem_x509_certificate),
                                          (".der", x509.load_der_x509_certificate)])
def test_save_certificate(tab, dialogs, ca, tmp_path, ext, loader):
    tab._save_cert()                           # nothing issued yet: no dialog, no file
    tab._outcome = Session.outcome
    tab._save_cert()                           # dialog cancelled
    assert list(tmp_path.glob("device*")) == []
    dialogs["save"] = str(tmp_path / f"device{ext}")
    tab._save_cert()
    with open(dialogs["save"], "rb") as fh:
        assert loader(fh.read()).public_bytes(serialization.Encoding.DER) == ca.cert_der
    assert f"saved to device{ext}" in logged(tab)


def test_connect_and_disconnect(tab):
    tab.dev_var.set("Device: PROVISIONED")
    tab.on_connected({"address": "AA", "name": "dev", "mtu": 247})
    assert tab.dev_var.get() == "Device: -"
    tab.ctx.hold = True
    tab._get_status()
    tab.ctx.flush()
    held = tab.ctx.held
    tab.on_disconnected("link lost")
    assert held.cancelled and not tab.busy


def test_follow_wrap_sets_wraplength_only_when_the_width_changes():
    """Setting wraplength changes the label's height, which can start another
    <Configure>: an unchanged width must not touch it."""
    class Label:
        def __init__(self):
            self.wrap, self.sets = 0, 0

        def cget(self, _opt):
            return self.wrap

        def configure(self, wraplength):
            self.wrap, self.sets = wraplength, self.sets + 1

    class Frame:
        def bind(self, _seq, fn):
            self.handler = fn

    label, frame = Label(), Frame()
    fp.follow_wrap(label, frame, 40, 200)
    event = types.SimpleNamespace
    frame.handler(event(width=500))
    frame.handler(event(width=500))
    assert (label.wrap, label.sets) == (460, 1)
    frame.handler(event(width=100))
    assert label.wrap == 200, "never narrower than the minimum"
    frame.handler(event(width=150))
    assert label.sets == 2


# ---- the real tab ------------------------------------------------------------------------
def test_build_real_tab(monkeypatch, tmp_path, ca, tk_root):
    root = tk_root
    monkeypatch.setattr(fp.CertificateAuthority, "exists", staticmethod(lambda folder: True))
    monkeypatch.setattr(fp, "DEFAULT_FOLDER", ca.folder)
    f = fp.ProvisioningFeature(Ctx())
    f.ctx.link.connected = False
    frame = f.build(root)
    assert frame.winfo_children()
    assert f.ca is not None, "an existing CA folder is loaded at start-up"
    assert f.folder_var.get() == ca.folder
    assert "disabled" in f.prov_btn.state()
    assert not f._ca_settings.is_open, "a loaded CA closes the CA settings"
    assert not f.save_btn.enabled and not f.deprov_btn.enabled, "More menu: not connected"
    f.ctx.link.connected = True
    f._update()
    assert f.deprov_btn.enabled and not f.save_btn.enabled, "nothing to save yet"
    assert f.pc_pill.text == "PC service: published" and "CSR" in f._pc_tip.text
    f.ca = None
    f.ca_var.set("No CA loaded")
    assert f._ca_settings.is_open, "no CA: the settings open again"
