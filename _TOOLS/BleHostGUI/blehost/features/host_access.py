"""Host access: authenticate this PC to the connected device and bond with it
(_DOC/HostAuth/PROTOCOL.md).

A provisioned device lets only its one trusted host reach its functions (hex
upload, files, UDS, provisioning, pairing). This page holds the PC's host
credential (a host certificate of the device's CA, issued here from a CA
folder or copied from the PC that holds the CA), runs the handshake (HELLO,
CHALLENGE, FINISH), then pairs with the passkey the handshake derived. Once
bonded, Windows re-encrypts every later connection with the stored keys and the
device trusts the PC again without a handshake.

The device advertises for a host only while its host window is open: a short
press of its Button 3 opens it; holding the button 3 s forgets the bonded host
first.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..core.gatt_server import PcGattServer
from ..pki.authority import DEFAULT_FOLDER as CA_FOLDER, CaError, CertificateAuthority
from ..pki.host import DEFAULT_FOLDER, HostCredential, HostError
from ..protocols import host_auth as ha, setu
from ..ui import theme as th
from ..ui.widgets import Disclosure, MoreMenu, Pill, Stepper, card, set_icon
from .base import Feature
from .provisioning import follow_wrap

# The steps HostAuthSession.run() reports -> (index in the list, final)
STEP_TEXTS = {"reading the device's state": 0, "sending HELLO": 1,
              "waiting for the device's CHALLENGE": 1, "checking the device's certificate": 2,
              "sending FINISH": 3, "pairing (passkey entry)": 4,
              "waiting for the device to trust this host": 4, "trusted": 5}
STEPS = ("Read the device's state", "Send HELLO", "Verify the device", "Prove this host",
         "Pair (passkey entry)", "Trusted")

# Device state (AuthStatus.state_name) -> pill text and tone
STATE_PILL = {"TRUSTED": ("Trusted", "ok"), "OPEN": ("No host yet", "info"),
              "HOST_BONDED": ("Another host", "warn"), "AWAIT_FINISH": ("Handshake", "info"),
              "AWAIT_PAIRING": ("Pairing", "info"), "UNPROVISIONED": ("Not provisioned", "warn")}

HINTS = {
    "TRUSTED": "This PC is the device's trusted host: every page can use the device.",
    "OPEN": "No host is bonded: authenticate this PC to make it the trusted host.",
    "HOST_BONDED": "Another host is bonded. Hold the device's Button 3 for 3 s to forget it, "
                   "then reconnect while its LED1 blinks.",
    "UNPROVISIONED": "Provision the device first (Provisioning page): a host authenticates "
                     "against the device's certificate.",
}


def step_position(text: str, current: int = 0):
    """(index, state) of the step list for the page's step text."""
    if not text:
        return 0, "idle"
    if text in STEP_TEXTS:
        i = STEP_TEXTS[text]
        return i, "done" if i == len(STEPS) - 1 else "running"
    if text in ("failed", "aborted"):
        return current, text
    return current, "running"


def state_pill(text: str):
    """(pill text, tone) for the page's "Device: ..." line."""
    state = text.removeprefix("Device:").strip().split(" ")[0].strip(",")
    return STATE_PILL.get(state, ("Unknown", "idle"))


class HostAccessFeature(Feature):
    title = "Host access"
    icon = "key"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.cred = None
        self.status = None
        self._future = None

    # ---- UI ----------------------------------------------------------------
    def build(self, parent):
        theme = th.of(self.ctx)
        sp = theme.sp
        f = ttk.Frame(parent)
        f.columnconfigure((0, 1), weight=1, uniform="col")
        f.rowconfigure(0, weight=1)

        dev, head = card(f, "Device access")
        dev.grid(row=0, column=0, sticky="new", padx=(0, sp("s")))
        self.state_pill = Pill(head, theme, "Unknown", "idle")
        self.state_pill.grid(row=0, column=2, sticky="e")
        self.dev_var = tk.StringVar(value="Device: -")
        ttk.Label(dev, textvariable=self.dev_var).pack(anchor="w")
        self.hint_var = tk.StringVar(value="Connect to a device (open its host window with Button 3).")
        hint = ttk.Label(dev, textvariable=self.hint_var, style="Caption.TLabel", wraplength=360,
                         justify="left")
        hint.pack(anchor="w", fill="x", pady=(sp("xs"), 0))
        follow_wrap(hint, dev, theme.px(40), theme.px(200))
        self.stepper = Stepper(dev, theme, STEPS)
        self.stepper.pack(anchor="w", fill="x", pady=(sp("m"), sp("xs")))
        self.step_var = tk.StringVar()
        ttk.Label(dev, textvariable=self.step_var, style="Caption.TLabel").pack(anchor="w")
        btns = ttk.Frame(dev)
        btns.pack(fill="x", pady=(sp("m"), 0))
        self.auth_btn = ttk.Button(btns, text="Authenticate & pair", style="Accent.TButton",
                                   command=self._authenticate)
        self.auth_btn.pack(side="left")
        self.status_btn = ttk.Button(btns, text="Refresh", command=self._get_status)
        self.status_btn.pack(side="left", padx=sp("s"))
        self.abort_btn = ttk.Button(btns, text="Abort", command=self.cancel)
        self.abort_btn.pack(side="left")
        set_icon(self.auth_btn, theme, "key", accent=True)
        set_icon(self.status_btn, theme, "refresh")
        set_icon(self.abort_btn, theme, "stop")
        more = MoreMenu(btns, theme)
        more.pack(side="right")
        self.forget_btn = more.add("Forget this device on the PC…", self._forget)

        cr, head = card(f, "Host credential (this PC)")
        cr.grid(row=0, column=1, sticky="new", padx=(sp("s"), 0))
        self.cred_pill = Pill(head, theme, "None", "warn")
        self.cred_pill.grid(row=0, column=2, sticky="e")
        self.cred_var = tk.StringVar(value="No host credential loaded")
        label = ttk.Label(cr, textvariable=self.cred_var, wraplength=360, justify="left")
        label.pack(anchor="w", fill="x")
        follow_wrap(label, cr, theme.px(40), theme.px(200))

        self._settings = Disclosure(cr, "Credential settings", theme=theme)
        self._settings.pack(fill="x", pady=(sp("m"), 0))
        cs = self._settings.body
        ttk.Label(cs, text="Folder", style="Caption.TLabel").pack(anchor="w", pady=(0, theme.px(2)))
        row = ttk.Frame(cs)
        row.pack(fill="x")
        self.folder_var = tk.StringVar(value=DEFAULT_FOLDER)
        ttk.Entry(row, textvariable=self.folder_var).pack(side="left", fill="x", expand=True)
        browse = ttk.Button(row, text="Browse…", command=lambda: self._browse(self.folder_var, "Host credential folder"))
        browse.pack(side="left", padx=(sp("s"), 0))
        set_icon(browse, theme, "folder")
        ttk.Button(row, text="Load", command=self._load).pack(side="left", padx=(sp("s"), 0))

        ttk.Label(cs, text="Or issue a new one (needs the CA folder with its key)",
                  style="Caption.TLabel").pack(anchor="w", pady=(sp("m"), theme.px(2)))
        new = ttk.Frame(cs)
        new.pack(fill="x")
        new.columnconfigure(1, weight=1)
        self.ca_folder_var = tk.StringVar(value=CA_FOLDER)
        self.name_var = tk.StringVar(value="Service laptop")
        self.days_var = tk.StringVar(value="730")
        for i, (text, var, width) in enumerate((("CA folder", self.ca_folder_var, 26),
                                                ("Host name", self.name_var, 26),
                                                ("Valid (days)", self.days_var, 6))):
            ttk.Label(new, text=text).grid(row=i, column=0, sticky="w", pady=2)
            ttk.Entry(new, textvariable=var, width=width).grid(row=i, column=1,
                                                               sticky="w" if width < 10 else "ew",
                                                               padx=(8, 0), pady=2)
        issue = ttk.Button(new, text="Issue host credential", command=self._issue)
        issue.grid(row=3, column=1, sticky="w", padx=(sp("s"), 0), pady=(theme.px(6), 0))
        set_icon(issue, theme, "certificate")

        self.dev_var.trace_add("write", lambda *a: self.state_pill.set(*state_pill(self.dev_var.get())))
        self.step_var.trace_add("write", lambda *a: self.stepper.show(
            *step_position(self.step_var.get(), self.stepper.current)))

        if HostCredential.exists(self.folder_var.get()):
            self._load(quiet=True)
        self._show_cred()
        self._update()
        if self.ctx.link.connected:
            f.after(200, self._get_status)
        return f

    def _show_cred(self):
        c = self.cred
        if c is None:
            self.cred_pill.set("None", "warn")
            self.cred_var.set("No host credential loaded")
            self._settings.set_open(True)
            return
        self.cred_pill.set("Loaded", "ok")
        self.cred_var.set(f"{c.name}\nCA {c.ca_certificate.subject.rfc4514_string()}\n"
                          f"SHA-256 {c.fingerprint[:23]}…, valid until {c.not_after:%Y-%m-%d}")
        self._settings.set_open(False)

    def _update(self):
        busy = self.busy
        ready = self.ctx.link.connected and self._setu().available and not busy
        trusted = self.status is not None and self.status.trusted
        self.status_btn.state(["!disabled"] if ready else ["disabled"])
        self.auth_btn.state(["!disabled"] if ready and self.cred and self._pc().available and not trusted
                            else ["disabled"])
        self.abort_btn.state(["!disabled"] if busy else ["disabled"])
        self.forget_btn.state(["!disabled"] if self.ctx.link.connected and not busy else ["disabled"])

    def _log(self, text: str, level: str = "info"):
        self.ctx.log(f"host access: {text}", level)

    def _setu(self):
        return self.ctx.services[setu.SETUService.NAME]

    def _pc(self) -> PcGattServer:
        return self.ctx.services[PcGattServer.NAME]

    # ---- credential ----------------------------------------------------------
    def _browse(self, var, title):
        path = filedialog.askdirectory(title=title, initialdir=var.get())
        if path:
            var.set(path)

    def _load(self, quiet=False):
        try:
            self.cred = HostCredential.load(self.folder_var.get())
        except (HostError, ValueError, OSError) as e:
            self.cred = None
            if not quiet:
                messagebox.showerror("Host credential", str(e))
        else:
            self._log(f"host credential loaded from {self.folder_var.get()}")
        self._show_cred()
        self._update()

    def _issue(self):
        try:
            days = int(self.days_var.get())
            ca = CertificateAuthority.load(self.ca_folder_var.get())
            self.cred = ca.issue_host(self.name_var.get().strip(), self.folder_var.get(), days)
        except (CaError, HostError, ValueError, OSError) as e:
            messagebox.showerror("Host credential", str(e))
            return
        self._log(f"host credential issued to {self.cred.name} in {self.folder_var.get()} "
                  "(keep this folder private: it holds the host key)")
        self._show_cred()
        self._update()

    # ---- device --------------------------------------------------------------
    def _session(self) -> ha.HostAuthSession:
        """On the BLE loop."""
        call = self.ctx.bus.call
        link = self.ctx.link
        return ha.HostAuthSession(self._setu().new_client(), self._pc().receiver, self.cred,
                                  pair=link.pair_with_pin,
                                  log=lambda t: call(self._log, t),
                                  step=lambda t: call(self.step_var.set, t))

    def _show_status(self, st: ha.AuthStatus):
        self.status = st
        window = ", window open" if st.window_open else ""
        self.dev_var.set(f"Device: {st.state_name}{window}")
        self.hint_var.set(HINTS.get(st.state_name, ""))

    def _get_status(self):
        if not (self.ctx.link.connected and self._setu().available) or self.busy:
            return

        async def go():
            return await self._session().get_status()
        self._run(go(), self._show_status, quiet=True)

    def _authenticate(self):
        async def go():
            s = self._session()
            await s.run()
            return await s.get_status()

        def done(st):
            self._show_status(st)
            self._log("this PC is now the device's trusted host")
        self._log("authenticating this PC to the device")
        self._run(go(), done)

    def _forget(self):
        if not messagebox.askyesno(
                "Forget the device",
                "Remove this device's keys from the PC?\n\nThe device keeps its bond with this "
                "PC until its Button 3 is held; to authenticate again, forget the host on the "
                "device too."):
            return

        async def go():
            return await self.ctx.link.unpair()
        self._run(go(), lambda r: self._log(f"keys removed on the PC ({r})"))

    def _run(self, coro, on_done, quiet=False):
        def finished(result):
            self._future = None
            on_done(result)
            self._update()

        def failed(exc):
            self._future = None
            if not quiet:
                self.step_var.set("failed")
            self._log(f"failed: {exc}", "warn" if quiet else "error")
            self._update()

        def aborted():
            self._future = None
            self.step_var.set("aborted")
            self._update()
        self._future = self.ctx.run(coro, on_done=finished, on_error=failed, on_cancel=aborted)
        self._update()

    # ---- Feature -------------------------------------------------------------
    @property
    def busy(self) -> bool:
        return self._future is not None

    def cancel(self):
        if self._future is not None:
            self._future.cancel()

    def on_connected(self, info):
        self.status = None
        self.dev_var.set("Device: -")
        self._update()
        self.auth_btn.after(200, self._get_status)

    def on_disconnected(self, reason):
        self.cancel()
        self.status = None
        self.dev_var.set("Device: -")
        self._update()
