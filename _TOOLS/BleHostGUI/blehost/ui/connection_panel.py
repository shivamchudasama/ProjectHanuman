"""Scan / connect / disconnect / read CAPS: the window's Device page.

Every connection is made here, to as many boards as needed (core/devices.py).
On the left the active device (the board the feature pages act on: name,
address, link state), the connected boards with Make active / Disconnect /
Read Caps, the active link's details (ATT MTU and CAPS) in a section that
opens after Read Caps, and the base UUID in a collapsible section; on the
right the scan list with Connect. A board that comes up becomes the active
device unless a page has work running, and the active device is not switched
while one has. The Pairing page pairs two of the connected boards.

Stale keys: when a board forgets this PC (chip erase, wipe, DEPROVISION,
Button 3 held) Windows keeps its own keys, encrypts every new link with them,
fails and drops it (the board logs reason 0x13) - the board cannot be reached.
The board advertises whether it has a host bond: Connect first removes this
PC's keys for a board that has none (protocols/host_auth.forget_stale_keys),
silently. For a board that does not advertise it (older firmware), when its
link dies while connecting or within STALE_KEYS_WINDOW_S of it, the page asks
Windows whether it holds keys for that address and offers to forget them;
More -> "Forget pairing on this PC" does it for the selected nearby board."""

import time
import tkinter as tk
from tkinter import messagebox, ttk

from ..core.ble_link import LinkState
from ..core.winrt_pairing import PairingUnavailable
from ..protocols import host_auth
from ..protocols import pairing
from ..protocols import setu
from ..protocols.setu import setu_client
from . import theme as th
from .widgets import Disclosure, MoreMenu, Pill, card, set_icon, set_var

# A link that dies this soon after connecting may be Windows' stale keys
STALE_KEYS_WINDOW_S = 10.0

STALE_KEYS_TEXT = (
    "Windows still holds pairing keys for {name} [{addr}], and the link dropped as soon as "
    "it was made.\n\nThis happens when the board has forgotten this PC (chip erase, wipe, "
    "DEPROVISION or Button 3 held): Windows encrypts with its old keys, the board has none, "
    "and Windows drops the link.\n\nForget the keys on this PC now? Then connect again "
    "(press the board's Button 3 if LED1 is not blinking) and authenticate on Host access.\n\n"
    "If the board still trusts this PC, forgetting the keys here makes it refuse this PC "
    "until its Button 3 is held.")

BUSY_TEXT = ("A page has work running on the active device. Let it finish or stop it, then "
             "make another board active.")

# Link state -> (pill text, tone)
STATE_PILL = {
    LinkState.IDLE: ("Idle", "idle"),
    LinkState.SCANNING: ("Scanning…", "info"),
    LinkState.CONNECTING: ("Connecting…", "warn"),
    LinkState.CONNECTED: ("Connected", "ok"),
    LinkState.DISCONNECTING: ("Disconnecting…", "warn"),
}


def unreached(exc) -> bool:
    """The connect failed before reaching the board (not found, timed out)."""
    return isinstance(exc, TimeoutError) or type(exc).__name__ == "BleakDeviceNotFoundError"


def session_state(session, active) -> str:
    """The connected list's State column."""
    if session is active:
        return "Active"
    return STATE_PILL.get(session.state, (session.state.value, ""))[0]


class ConnectionPanel(ttk.Frame):
    def __init__(self, parent, ctx, is_busy):
        theme = th.of(ctx)
        super().__init__(parent)
        self.ctx = ctx
        self._is_busy = is_busy          # () -> True if a feature has work in progress
        self._results = []
        self._shown_active = None        # the session the link details describe
        s = ctx.settings
        self.columnconfigure(0, weight=2, uniform="col")
        self.columnconfigure(1, weight=3, uniform="col")
        self.rowconfigure(0, weight=1)
        left = ttk.Frame(self)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, theme.sp("s")))

        # ---- active device and the connected boards ----
        conn, head = card(left, "Active device")
        conn.pack(fill="both", expand=True)
        self.state_pill = Pill(head, theme, "Idle", "idle")
        self.state_pill.grid(row=0, column=2, sticky="e")
        self.name_var = tk.StringVar(value="Not connected")
        self.addr_var = tk.StringVar(value="Select a nearby device, then Connect.")
        ttk.Label(conn, textvariable=self.name_var, style="Title.TLabel").pack(anchor="w")
        ttk.Label(conn, textvariable=self.addr_var, style="MonoCaption.TLabel").pack(anchor="w")

        ttk.Label(conn, text="CONNECTED", style="Caption.TLabel").pack(anchor="w", pady=(theme.sp("m"), 0))
        body = ttk.Frame(conn)
        body.pack(fill="both", expand=True, pady=(theme.px(2), 0))
        cols = ("name", "address", "state", "pair")
        self.dev_tree = ttk.Treeview(body, columns=cols, show="headings", height=4, selectmode="browse")
        for c, text, w in (("name", "Name", 110), ("address", "Address", 120),
                           ("state", "State", 80), ("pair", "Pairing", 56)):
            self.dev_tree.heading(c, text=text, anchor="w")
            self.dev_tree.column(c, width=theme.px(w), minwidth=theme.px(36), anchor="w",
                                 stretch=(c == "name"))
        dsb = ttk.Scrollbar(body, orient="vertical", command=self.dev_tree.yview)
        self.dev_tree.configure(yscrollcommand=dsb.set)
        self.dev_tree.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        self.dev_tree.bind("<<TreeviewSelect>>", lambda e: self.update_state())
        self.dev_tree.bind("<Double-1>", lambda e: self._make_active())

        btns = ttk.Frame(conn)
        btns.pack(fill="x", pady=(theme.sp("s"), 0))
        # As wide as each needs, the rest shared: equal thirds clipped "Disconnect"
        btns.columnconfigure((0, 1, 2), weight=1)
        self.active_btn = ttk.Button(btns, text="Make active", command=self._make_active)
        self.active_btn.grid(row=0, column=0, sticky="ew")
        self.disconnect_btn = ttk.Button(btns, text="Disconnect", command=self._disconnect)
        self.disconnect_btn.grid(row=0, column=1, sticky="ew", padx=theme.px(6))
        self.caps_btn = ttk.Button(btns, text="Read Caps", command=self._read_caps)
        self.caps_btn.grid(row=0, column=2, sticky="ew")
        set_icon(self.active_btn, theme, "device")
        set_icon(self.disconnect_btn, theme, "disconnect")
        set_icon(self.caps_btn, theme, "info")
        ttk.Label(conn, text="The pages act on the active device. Double-click a board to make "
                             "it active; the Pairing page pairs two connected boards.",
                  style="Caption.TLabel", wraplength=theme.px(320), justify="left").pack(
            anchor="w", pady=(theme.px(6), 0))

        # ---- link details (closed until Read Caps) ----
        self.details = Disclosure(conn, "Link details", theme=theme)
        self.details.pack(fill="x", pady=(theme.sp("m"), 0))
        grid = ttk.Frame(self.details.body)
        grid.pack(fill="x", pady=(0, theme.sp("xs")))
        self._facts = {}
        for i, key in enumerate(("ATT MTU", "Protocol", "Window", "Max frame")):
            cell = ttk.Frame(grid)
            cell.grid(row=i // 2, column=i % 2, sticky="w", padx=(0, theme.sp("l")), pady=theme.px(2))
            ttk.Label(cell, text=key.upper(), style="Caption.TLabel").pack(anchor="w")
            var = tk.StringVar(value="–")
            ttk.Label(cell, textvariable=var, style="Strong.TLabel").pack(anchor="w")
            self._facts[key] = var
        grid.columnconfigure((0, 1), weight=1, uniform="facts")
        self.caps_var = tk.StringVar(value="")
        ttk.Label(self.details.body, textvariable=self.caps_var, style="Caption.TLabel",
                  wraplength=theme.px(320), justify="left").pack(anchor="w")

        # ---- advanced ----
        adv = Disclosure(left, "Advanced: base UUID", theme=theme)
        adv.pack(fill="x", pady=(theme.sp("m"), 0))
        row = ttk.Frame(adv.body)
        row.pack(fill="x")
        ttk.Label(row, text="B1C0xxxx-", style="Mono.TLabel").pack(side="left")
        self.base_var = tk.StringVar(value=s.base_uuid)
        self.base_entry = ttk.Entry(row, textvariable=self.base_var, width=30)
        self.base_entry.pack(side="left", fill="x", expand=True, padx=(theme.sp("xs"), 0))

        # ---- scan card ----
        scan, _ = card(self, "Nearby devices")
        scan.grid(row=0, column=1, sticky="nsew", padx=(theme.sp("s"), 0))
        top = ttk.Frame(scan)
        top.pack(fill="x")
        ttk.Label(top, text="Name filter").pack(side="left")
        self.filter_var = tk.StringVar(value=s.name_filter)
        self.filter_var.trace_add("write", lambda *a: self._show_results())
        ttk.Entry(top, textvariable=self.filter_var).pack(side="left", fill="x", expand=True, padx=theme.px(6))
        self.scan_btn = ttk.Button(top, text="Scan", command=self._scan)
        self.scan_btn.pack(side="left")
        self.connect_btn = ttk.Button(top, text="Connect", style="Accent.TButton", command=self._connect)
        self.connect_btn.pack(side="left", padx=(theme.px(6), 0))
        more = MoreMenu(top, theme)
        more.pack(side="left", padx=(theme.px(6), 0))
        self.forget_btn = more.add("Forget pairing on this PC…", self._forget_selected)
        set_icon(self.scan_btn, theme, "search")
        set_icon(self.connect_btn, theme, "connect", accent=True)

        cols = ("name", "address", "rssi", "svc")
        body = ttk.Frame(scan)
        body.pack(fill="both", expand=True, pady=(theme.sp("s"), 0))
        self.tree = ttk.Treeview(body, columns=cols, show="headings", height=6, selectmode="browse")
        for c, text, w in (("name", "Name", 140), ("address", "Address", 130),
                           ("rssi", "RSSI", 50), ("svc", "SETU", 70)):
            self.tree.heading(c, text=text, anchor="w")
            self.tree.column(c, width=theme.px(w), minwidth=theme.px(36), anchor="w", stretch=(c == "name"))
        sb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.update_state())
        self.tree.bind("<Double-1>", lambda e: self._connect())
        ttk.Label(scan, text="Double-click a device to connect. Connect as many boards as "
                             "needed; each is listed under Connected.",
                  style="Caption.TLabel").pack(anchor="w", pady=(theme.px(6), 0))

        theme.on_change(self._recolour)
        self.update_state()

    def _recolour(self, p):
        self.tree.tag_configure("setu", foreground=p["ok"][0])
        self.dev_tree.tag_configure("active", foreground=p["accent"])

    # ---- state -------------------------------------------------------------
    def _selected(self):
        """The selected nearby board's address."""
        sel = self.tree.selection()
        return sel[0] if sel else None

    def _selected_session(self):
        """The selected connected board, else the active one."""
        devices = self.ctx.devices
        sel = self.dev_tree.selection()
        return (devices.get(sel[0]) if sel else None) or devices.active

    def update_state(self):
        devices = self.ctx.devices
        active = devices.active
        sessions = list(devices.sessions.values())
        connecting = any(s.state == LinkState.CONNECTING for s in sessions)
        sel = self._selected()
        free = bool(sel) and devices.get(sel) is None          # not connected (yet)
        chosen = self._selected_session()
        self.scan_btn.state(["!disabled"] if not devices.scanning and not connecting else ["disabled"])
        self.connect_btn.state(["!disabled"] if free and not devices.scanning else ["disabled"])
        self.forget_btn.state(["!disabled"] if free and not devices.scanning else ["disabled"])
        self.active_btn.state(["!disabled"] if chosen is not None and chosen.connected
                              and chosen is not active and not self._is_busy() else ["disabled"])
        self.disconnect_btn.state(["!disabled"] if chosen is not None and chosen.state in (
            LinkState.CONNECTED, LinkState.CONNECTING) else ["disabled"])
        self.caps_btn.state(["!disabled"] if active is not None and active.connected else ["disabled"])
        self.base_entry.state(["!disabled"] if not sessions else ["disabled"])
        if active is not None:
            self.state_pill.set(*STATE_PILL.get(active.state, (active.state.value, "idle")))
        elif devices.scanning:
            self.state_pill.set(*STATE_PILL[LinkState.SCANNING])
        elif connecting:
            self.state_pill.set(*STATE_PILL[LinkState.CONNECTING])
        else:
            self.state_pill.set(*STATE_PILL[LinkState.IDLE])

    def show_devices(self, payload):
        """A board's link changed, or the active device or the scan
        (MainWindow, Tk thread, the DEVICES event)."""
        session, state, info = payload
        self._show_sessions()
        self._show_active()
        if (session is not None and state == LinkState.IDLE and info.get("reason") == "link lost"
                and self._dropped_early(session)):
            self._check_stale_keys((session.address, session.name))
        self._show_results()                # Connect follows what is connected
        self.update_state()

    def _show_sessions(self):
        devices = self.ctx.devices
        tree = self.dev_tree
        prev = tree.selection()
        tree.delete(*tree.get_children())
        for s in devices.sessions.values():
            tree.insert("", "end", iid=s.key, tags=("active",) if s is devices.active else (),
                        values=(s.name or "(no name)", s.address, session_state(s, devices.active),
                                "yes" if s.has_characteristic(pairing.STATUS_UUID) else ""))
        if prev and tree.exists(prev[0]):
            tree.selection_set(prev[0])
        elif devices.active is not None and tree.exists(devices.active.key):
            tree.selection_set(devices.active.key)

    def _show_active(self):
        """The card's device lines and link details: the active device."""
        devices = self.ctx.devices
        active = devices.active
        if active is not self._shown_active:        # the details described another board
            self._shown_active = active
            set_var(self.caps_var, "")
            for var in self._facts.values():
                set_var(var, "–")
            self.details.set_open(False)
        if active is not None:
            set_var(self.name_var, active.name or "(no name)")
            set_var(self.addr_var, active.address)
            if active.connected:
                set_var(self._facts["ATT MTU"], str(active.link.mtu_size or "–"))
        elif devices.connected():
            set_var(self.name_var, "No active device")
            set_var(self.addr_var, "Make a connected board active.")
        else:
            set_var(self.name_var, "Not connected")
            set_var(self.addr_var, "Select a nearby device, then Connect.")

    def _dropped_early(self, session) -> bool:
        """The board's link died while connecting or soon after."""
        return (session.connected_at is None
                or time.monotonic() - session.connected_at < STALE_KEYS_WINDOW_S)

    # ---- scan --------------------------------------------------------------
    def _scan(self):
        self.ctx.settings.name_filter = self.filter_var.get()
        self.ctx.run(self.ctx.devices.scan(self.ctx.settings.scan_timeout),
                     on_done=self._scan_done, on_error=self._error("Scan"))

    def _scan_done(self, results):
        self._results = results
        self._show_results()
        self.ctx.log(f"scan: {len(results)} device(s)")

    def _show_results(self):
        svc = setu_client.char_uuid(0, self.base_var.get().strip())
        flt = self.filter_var.get().strip().lower()
        prev = self._selected()
        self.tree.delete(*self.tree.get_children())
        rows = []
        for r in self._results:
            has = svc in r.service_uuids
            if flt and flt not in r.name.lower() and not has:
                continue
            rows.append((not has, -r.rssi, r))
        for _, _, r in sorted(rows, key=lambda t: t[:2]):
            has = svc in r.service_uuids
            connected = self.ctx.devices.get(r.address) is not None
            name = (r.name or "(no name)") + (" (connected)" if connected else "")
            self.tree.insert("", "end", iid=r.address, tags=("setu",) if has else (),
                             values=(name, r.address, r.rssi, "yes" if has else ""))
        if prev and self.tree.exists(prev):
            self.tree.selection_set(prev)
        elif self.tree.get_children():
            self.tree.selection_set(self.tree.get_children()[0])
        self.update_state()

    def _result(self, addr):
        return next((r for r in self._results if r.address == addr), None)

    # ---- connect -----------------------------------------------------------
    def _connect(self):
        addr = self._selected()
        devices = self.ctx.devices
        if not addr or devices.get(addr) is not None or devices.scanning:
            return
        base = self.base_var.get().strip().lower()
        if len(base) != 27 or base.count("-") != 3:
            messagebox.showerror("Base UUID", "Expected the 96-bit base as xxxx-xxxx-xxxx-xxxxxxxxxxxx")
            return
        self.ctx.settings.base_uuid = base
        found = self._result(addr)
        name = found.name if found else self.tree.set(addr, "name")
        mdata = found.manufacturer_data if found else {}
        log = self.ctx.log                                # any thread

        async def go():
            try:
                result = await host_auth.forget_stale_keys(addr, mdata, devices.is_paired_address,
                                                           devices.unpair_address)
            except PairingUnavailable:
                result = None                            # not Windows: nothing to clean
            except Exception as e:                       # noqa: BLE001 - connect anyway
                log(f"{name or addr}: could not check this PC's keys for it ({e})", "warn")
                result = None
            if result is not None:
                log(f"{name or addr} has no host bond: this PC's old keys for it removed ({result})")
            await devices.connect(addr, name, mdata)

        def failed(exc):                     # the board is no longer listed by now
            self._error("Connect")(exc)
            # A board that was not reached says nothing about keys (it may be a
            # trusted one out of range); one that was reached and dropped may
            if not unreached(exc):
                self._check_stale_keys((addr, name))
        self.ctx.run(go(), on_error=failed)

    def _make_active(self):
        session = self._selected_session()
        devices = self.ctx.devices
        if session is None or session is devices.active or not session.connected:
            return
        if not devices.set_active(session.address):
            messagebox.showinfo("Active device", BUSY_TEXT)
        self.update_state()

    # ---- stale keys ----------------------------------------------------------
    def _check_stale_keys(self, attempt):
        """Ask Windows whether it holds keys for attempt's (address, name); if
        so, offer to forget them. Quiet where Windows cannot tell."""
        addr, name = attempt

        def done(paired):
            if paired:
                self.ctx.log(f"{name or addr}: Windows holds pairing keys the board may have lost", "warn")
                if messagebox.askyesno("Stale pairing keys",
                                       STALE_KEYS_TEXT.format(name=name or "this board", addr=addr)):
                    self._forget(addr, name)

        def unknown(exc):
            self.ctx.log(f"pairing state of {addr} unknown: {exc}", "warn")
        self.ctx.run(self.ctx.devices.is_paired_address(addr), on_done=done, on_error=unknown)

    def _forget_selected(self):
        addr = self._selected()
        if not addr or self.ctx.devices.get(addr) is not None:
            return
        found = self._result(addr)
        name = found.name if found else self.tree.set(addr, "name")
        if messagebox.askyesno(
                "Forget pairing",
                f"Remove this PC's pairing keys for {name or 'this board'} [{addr}]?\n\n"
                "Use it when the board has forgotten this PC (chip erase, wipe, DEPROVISION or "
                "Button 3 held). If the board still trusts this PC, it will refuse this PC "
                "until its Button 3 is held."):
            self._forget(addr, name)

    def _forget(self, addr, name):
        def done(result):
            self.ctx.log(f"{name or addr}: pairing keys forgotten on this PC ({result}); connect "
                         "again, then authenticate on Host access")
        self.ctx.run(self.ctx.devices.unpair_address(addr), on_done=done,
                     on_error=self._error("Forget pairing"))

    def _disconnect(self):
        session = self._selected_session()
        if session is None:
            return
        if self._is_busy() and not messagebox.askyesno(
                "Disconnect", "A page has work in progress. Abort it and disconnect "
                              f"{session.name or session.address}?"):
            return
        self.ctx.run(self.ctx.devices.disconnect(session.address), on_error=self._error("Disconnect"))

    def _read_caps(self):
        svc = self.ctx.services[setu.SETUService.NAME]
        self.ctx.run(svc.read_caps(), on_done=self._caps_done, on_error=self._error("Read Caps"))

    def _caps_done(self, caps):
        ver, max_frame, window, mtu = caps
        frame = min(mtu - 3, max_frame)
        self.caps_var.set(f"protocol v{ver} · max frame {max_frame} B · window {window} · "
                          f"ATT MTU {mtu} → {frame - 4} B per DATA frame")
        for key, value in (("ATT MTU", str(mtu)), ("Protocol", f"v{ver}"),
                           ("Window", str(window)), ("Max frame", f"{max_frame} B")):
            self._facts[key].set(value)
        self.details.set_open(True)
        self.ctx.log(f"caps: v{ver}, max frame {max_frame}, window {window}, ATT MTU {mtu}")

    def _error(self, what):
        def show(exc):
            self.ctx.log(f"{what}: {type(exc).__name__}: {exc}", "error")
            messagebox.showerror(what, f"{type(exc).__name__}: {exc}")
            self.update_state()
        return show
