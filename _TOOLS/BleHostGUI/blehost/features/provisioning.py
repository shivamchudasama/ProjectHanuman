"""Provisioning: act as the Certificate Authority and provision the connected
device (_DOC/Provisioning/PROTOCOL.md).

The page holds a CA (create or load a folder), reads the device's STATUS, and
runs the whole sequence: CSR from the device (over the PC's own SETU
service, core/gatt_server.py), sign it, send the CA certificate and the device
certificate, each verified by the device, which then stores both. A provisioned
device refuses another run: "Remove provisioning" wipes it (DEPROVISION) and it
makes a fresh key and CSR.
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.hazmat.primitives import serialization

from ..core.gatt_server import PcGattServer
from ..pki.authority import DEFAULT_FOLDER, CaError, CertificateAuthority
from ..protocols import setu, provisioning as prov
from ..ui import theme as th
from ..ui.widgets import Disclosure, MoreMenu, Pill, Stepper, Tooltip, card, set_icon, set_var
from .base import Feature

# The steps ProvisioningSession.provision() reports, and their labels in the list
STEP_TEXTS = ("reading device status", "requesting the CSR", "signing the CSR",
              "sending the CA certificate", "sending the device certificate", "provisioned")
STEPS = ("Read device status", "Request the CSR", "Sign the CSR",
         "Send the CA certificate", "Send the device certificate", "Provisioned")

# Device state (DeviceStatus.state_name) -> pill tone
STATE_TONE = {"PROVISIONED": "ok", "KEY_READY": "info", "CA_OK": "info", "NO_KEY": "warn"}


def step_position(text: str, current: int = 0):
    """(index, state) of the step list for the tab's step text."""
    if not text:
        return 0, "idle"
    if text in STEP_TEXTS:
        i = STEP_TEXTS.index(text)
        return i, "done" if i == len(STEP_TEXTS) - 1 else "running"
    if text in ("failed", "aborted"):
        return current, text
    return current, "running"


def follow_wrap(label, frame, margin: int, minimum: int):
    """Wrap label's text to frame's width (less margin) as the frame resizes.
    wraplength changes only when the width does: setting it changes the
    label's height, which would otherwise start another <Configure>."""
    def on_configure(e):
        width = max(minimum, e.width - margin)
        if int(str(label.cget("wraplength")) or 0) != width:
            label.configure(wraplength=width)
    frame.bind("<Configure>", on_configure)


def device_pill(text: str):
    """(pill text, tone) for the tab's "Device: ..." line."""
    state = text.removeprefix("Device:").strip().split(",")[0].strip()
    if not state or state == "-":
        return "Unknown", "idle"
    return state, STATE_TONE.get(state, "idle")


class ProvisioningFeature(Feature):
    title = "Provisioning"
    icon = "shield"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.ca = None
        self._future = None
        self._outcome = None
        self._ca_shown = None            # CA loaded, as the settings section last showed it

    # ---- UI ----------------------------------------------------------------
    def build(self, parent):
        theme = th.of(self.ctx)
        sp = theme.sp
        f = ttk.Frame(parent)
        f.columnconfigure((0, 1), weight=1, uniform="col")
        f.rowconfigure(0, weight=1)

        # Device: status, the step list and the actions
        dev, head = card(f, "Device")
        dev.grid(row=0, column=0, sticky="new", padx=(0, sp("s")))
        pills = ttk.Frame(head)
        pills.grid(row=0, column=2, sticky="e")
        self.pc_pill = Pill(pills, theme, "starting", "idle")
        self.pc_pill.pack(side="left", padx=(0, sp("s")))
        self.pc_var = tk.StringVar()
        self._pc_tip = Tooltip(self.pc_pill, "", theme)
        self.dev_pill = Pill(pills, theme, "Unknown", "idle")
        self.dev_pill.pack(side="left")
        self.dev_var = tk.StringVar(value="Device: -")
        self._dev_label = ttk.Label(dev, textvariable=self.dev_var, style="Caption.TLabel",
                                    wraplength=360, justify="left")
        self._dev_label.pack(anchor="w", fill="x")
        follow_wrap(self._dev_label, dev, theme.px(40), theme.px(200))
        self.stepper = Stepper(dev, theme, STEPS)
        self.stepper.pack(anchor="w", fill="x", pady=(sp("m"), sp("xs")))
        self.step_var = tk.StringVar()
        ttk.Label(dev, textvariable=self.step_var, style="Caption.TLabel").pack(anchor="w")

        days = ttk.Frame(dev)
        days.pack(fill="x", pady=(sp("m"), 0))
        ttk.Label(days, text="Device certificate valid (days)").pack(side="left")
        self.dev_days_var = tk.StringVar(value="365")
        ttk.Entry(days, textvariable=self.dev_days_var, width=6).pack(side="left", padx=(sp("s"), 0))
        btns = ttk.Frame(dev)
        btns.pack(fill="x", pady=(sp("s"), 0))
        self.prov_btn = ttk.Button(btns, text="Provision", style="Accent.TButton", command=self._provision)
        self.prov_btn.pack(side="left")
        self.status_btn = ttk.Button(btns, text="Get Status", command=self._get_status)
        self.status_btn.pack(side="left", padx=sp("s"))
        self.abort_btn = ttk.Button(btns, text="Abort", command=self.cancel)
        self.abort_btn.pack(side="left")
        set_icon(self.prov_btn, theme, "shield", accent=True)
        set_icon(self.status_btn, theme, "refresh")
        set_icon(self.abort_btn, theme, "stop")
        more = MoreMenu(btns, theme)
        more.pack(side="right")
        self.save_btn = more.add("Save certificate…", self._save_cert)
        self.deprov_btn = more.add("Remove provisioning…", self._deprovision)

        # Certificate Authority: a summary; folder and a new CA behind "CA settings"
        ca, head = card(f, "Certificate Authority (this PC)")
        ca.grid(row=0, column=1, sticky="new", padx=(sp("s"), 0))
        self.ca_pill = Pill(head, theme, "No CA", "warn")
        self.ca_pill.grid(row=0, column=2, sticky="e")
        self.ca_var = tk.StringVar(value="No CA loaded")
        self._ca_label = ttk.Label(ca, textvariable=self.ca_var, wraplength=360, justify="left")
        self._ca_label.pack(anchor="w", fill="x")
        follow_wrap(self._ca_label, ca, theme.px(40), theme.px(200))

        self._ca_settings = Disclosure(ca, "CA settings", theme=theme)
        self._ca_settings.pack(fill="x", pady=(sp("m"), 0))
        cs = self._ca_settings.body
        ttk.Label(cs, text="Folder", style="Caption.TLabel").pack(anchor="w", pady=(0, theme.px(2)))
        row = ttk.Frame(cs)
        row.pack(fill="x")
        self.folder_var = tk.StringVar(value=DEFAULT_FOLDER)
        ttk.Entry(row, textvariable=self.folder_var).pack(side="left", fill="x", expand=True)
        browse = ttk.Button(row, text="Browse…", command=self._browse)
        browse.pack(side="left", padx=(sp("s"), 0))
        set_icon(browse, theme, "folder")
        ttk.Button(row, text="Load", command=self._load_ca).pack(side="left", padx=(sp("s"), 0))

        ttk.Label(cs, text="Or create a new CA in that folder", style="Caption.TLabel").pack(
            anchor="w", pady=(sp("m"), theme.px(2)))
        new = ttk.Frame(cs)
        new.pack(fill="x")
        new.columnconfigure(1, weight=1)
        self.cn_var = tk.StringVar(value="BLE Host Provisioning CA")
        self.o_var = tk.StringVar(value="Bajaj Auto Technology Limited")
        self.c_var = tk.StringVar(value="IN")
        self.ca_days_var = tk.StringVar(value="3650")
        for i, (label, var, width) in enumerate((("CN", self.cn_var, 26), ("O", self.o_var, 26),
                                                 ("C", self.c_var, 4), ("Valid (days)", self.ca_days_var, 6))):
            ttk.Label(new, text=label).grid(row=i, column=0, sticky="w", pady=2)
            ttk.Entry(new, textvariable=var, width=width).grid(row=i, column=1, sticky="w" if width < 10 else "ew",
                                                               padx=(8, 0), pady=2)
        create = ttk.Button(new, text="Create CA", command=self._create_ca)
        create.grid(row=4, column=1, sticky="w", padx=(sp("s"), 0), pady=(theme.px(6), 0))
        set_icon(create, theme, "certificate")

        # The pills and the step list follow the text the logic writes
        self.pc_var.trace_add("write", lambda *a: self._show_pc_pill())
        self.ca_var.trace_add("write", lambda *a: self._show_ca_pill())
        self.dev_var.trace_add("write", lambda *a: self.dev_pill.set(*device_pill(self.dev_var.get())))
        self.step_var.trace_add("write", lambda *a: self.stepper.show(
            *step_position(self.step_var.get(), self.stepper.current)))

        if CertificateAuthority.exists(self.folder_var.get()):
            self._load_ca(quiet=True)
        self._show_ca_pill()
        self._update()
        f.after(1000, self._tick)
        return f

    # ---- display (pills, step list) -----------------------------------------
    def _show_pc_pill(self):
        text = self.pc_var.get()
        if text.startswith("PC SETU service: published"):
            sub = "subscribed" in text
            self.pc_pill.set("PC service: subscribed" if sub else "PC service: published", "ok")
            self._pc_tip.text = "The PC's SETU service: the device sends its CSR to it."
        else:
            self.pc_pill.set("PC service: not available", "warn")
            self._pc_tip.text = text

    def _show_ca_pill(self):
        """The CA's pill; its settings open while there is no CA, and close
        once one is loaded (only when that changes: the user may reopen them)."""
        loaded = self.ca is not None
        self.ca_pill.set("Loaded" if loaded else "No CA", "ok" if loaded else "warn")
        if loaded != self._ca_shown:
            self._ca_shown = loaded
            self._ca_settings.set_open(not loaded)

    def _update(self):
        busy = self.busy
        ready = self.ctx.link.connected and self._setu().available and not busy
        self.status_btn.state(["!disabled"] if ready else ["disabled"])
        self.deprov_btn.state(["!disabled"] if ready else ["disabled"])
        self.prov_btn.state(["!disabled"] if ready and self.ca and self._pc().available else ["disabled"])
        self.abort_btn.state(["!disabled"] if busy else ["disabled"])
        self.save_btn.state(["!disabled"] if self._outcome and not busy else ["disabled"])
        self._show_pc()

    def _show_pc(self):
        pc = self._pc()
        if pc.available:
            subs = ", device subscribed" if pc.subscribers else ""
            set_var(self.pc_var, f"PC SETU service: published{subs}")
        else:
            set_var(self.pc_var, f"PC SETU service: not available ({pc.error or 'starting'}): "
                                 "the CSR cannot be received")

    def _tick(self):
        """The PC service starts and the device subscribes asynchronously.
        Runs every second; it changes nothing on screen unless they did."""
        self._show_pc()
        self.prov_btn.after(1000, self._tick)

    def _log(self, text: str, level: str = "info"):
        """To the application log (the Log page and the status line)."""
        self.ctx.log(f"provisioning: {text}", level)

    def _setu(self):
        return self.ctx.services[setu.SETUService.NAME]

    def _pc(self) -> PcGattServer:
        return self.ctx.services[PcGattServer.NAME]

    # ---- CA ----------------------------------------------------------------
    def _browse(self):
        path = filedialog.askdirectory(title="CA folder", initialdir=self.folder_var.get())
        if path:
            self.folder_var.set(path)

    def _show_ca(self):
        ca = self.ca
        self.ca_var.set(f"{ca.subject}\nSHA-256 {ca.fingerprint}\n"
                        f"valid until {ca.not_after:%Y-%m-%d}, {len(ca.issued())} certificate(s) issued")

    def _load_ca(self, quiet=False):
        try:
            self.ca = CertificateAuthority.load(self.folder_var.get())
        except (CaError, ValueError, OSError) as e:
            self.ca = None
            self.ca_var.set("No CA loaded")
            if not quiet:
                messagebox.showerror("Certificate Authority", str(e))
            self._update()
            return
        self._show_ca()
        self._log(f"CA loaded from {self.folder_var.get()}")
        self._update()

    def _create_ca(self):
        subject = {"CN": self.cn_var.get().strip(), "O": self.o_var.get().strip(),
                   "C": self.c_var.get().strip().upper()}
        try:
            days = int(self.ca_days_var.get())
            self.ca = CertificateAuthority.create(self.folder_var.get(), subject, days)
        except (CaError, ValueError, OSError) as e:
            messagebox.showerror("Certificate Authority", str(e))
            return
        self._show_ca()
        self._log(f"CA created in {self.folder_var.get()} (keep this folder private: it holds the CA key)")
        self._update()

    # ---- device ------------------------------------------------------------
    def _session(self) -> prov.ProvisioningSession:
        """On the BLE loop."""
        call = self.ctx.bus.call
        return prov.ProvisioningSession(self._setu().new_client(), self._pc().receiver,
                                        log=lambda t: call(self._log, t),
                                        step=lambda t: call(self.step_var.set, t))

    def _show_status(self, st: prov.DeviceStatus):
        busy = ", CSR transfer running" if st.csr_busy else ""
        self.dev_var.set(f"Device: {st.state_name}{busy}, CSR {st.csr_len} B, "
                         f"key SHA-256 {st.pubkey_sha256.hex()[:16]}…")

    def _get_status(self):
        async def go():
            return await self._session().get_status()
        self._run(go(), self._show_status)

    def _deprovision(self):
        if not messagebox.askyesno(
                "Remove provisioning",
                "Wipe the device's key, CSR, CA certificate and device certificate?\n\n"
                "The device then makes a new key and CSR and must be provisioned again; "
                "certificates issued for the old key no longer match it."):
            return
        self._outcome = None

        async def go():
            s = self._session()
            await s.deprovision()
            return await s.get_status()

        def done(st: prov.DeviceStatus):
            self._show_status(st)
            self._log(f"provisioning removed: device {st.state_name}, new key "
                      f"{st.pubkey_sha256.hex()[:16]}…")
            # The device deleted its bond with this PC: this PC's keys go when the link ends
            self.ctx.link.forget_keys_after_disconnect()
        self._log("removing the device's provisioning")
        self._run(go(), done)

    def _provision(self):
        try:
            days = int(self.dev_days_var.get())
        except ValueError:
            messagebox.showerror("Provisioning", "validity must be a number of days")
            return
        self._outcome = None

        async def go():
            return await self._session().provision(self.ca, days)

        def done(out: prov.Outcome):
            self._outcome = out
            self._show_status(out.status)
            self.dev_var.set(f"Device: PROVISIONED, certificate serial {out.serial_hex}")
            self._log(f"device certificate issued to {out.device_cert.subject.rfc4514_string()}, "
                      f"serial {out.serial_hex}; the device logs both certificates on its UART")
            self._show_ca()
        self._log("provisioning started")
        self._run(go(), done)

    def _run(self, coro, on_done):
        def finished(result):
            self._future = None
            on_done(result)
            self._update()

        def failed(exc):
            self._future = None
            self.step_var.set("failed")
            self._log(f"failed: {exc}", "error")
            self._update()

        def aborted():
            self._future = None
            self.step_var.set("aborted")
            self._log("aborted", "warn")
            self._update()
        self._future = self.ctx.run(coro, on_done=finished, on_error=failed, on_cancel=aborted)
        self._update()

    def _save_cert(self):
        if not self._outcome:
            return
        path = filedialog.asksaveasfilename(
            title="Save device certificate", defaultextension=".pem",
            initialfile=f"device_{self._outcome.serial_hex}.pem",
            filetypes=[("PEM certificate", "*.pem"), ("DER certificate", "*.der")])
        if not path:
            return
        enc = serialization.Encoding.DER if path.lower().endswith(".der") else serialization.Encoding.PEM
        with open(path, "wb") as fh:
            fh.write(self._outcome.device_cert.public_bytes(enc))
        self._log(f"device certificate saved to {os.path.basename(path)}")

    # ---- Feature -----------------------------------------------------------
    @property
    def busy(self) -> bool:
        return self._future is not None

    def cancel(self):
        if self._future is not None:
            self._future.cancel()

    def on_connected(self, info):
        self.dev_var.set("Device: -")
        self._update()

    def on_disconnected(self, reason):
        self.cancel()
        self._update()
