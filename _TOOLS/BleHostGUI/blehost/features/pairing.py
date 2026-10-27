"""Pairing: orchestrate certificate-based OOB pairing of two provisioned devices
(_DOC/Pairing/PROTOCOL.md).

The boards are connected on the Device page (ctx.devices); this page lists
them, and those with the Pairing service (provisioned ones) can be chosen as
the central and the peripheral. It checks the two chosen devices' STATUS
(Check) and runs the pairing over their links: START to both, then both
STATUS followed live in a step list per device until both are PAIRED or one
FAILED. Two devices already paired with each other are not paired again:
UNPAIR one of them first (it deletes that device's bond). The links stay up
afterwards, so the boards can be used on the other pages at once.
"""

import re
import tkinter as tk
from tkinter import messagebox, ttk

from ..protocols import pairing
from ..ui import theme as th
from ..ui.widgets import MoreMenu, Pill, Stepper, card, set_icon, set_var
from .base import Feature

ROLES = ("central", "peripheral")

# First word of a role's status text (PairStatus.describe()) -> pill tone
STATE_TONE = {"PAIRED": "ok", "FAILED": "err", "IDLE": "idle"}


def choice_text(name: str, address: str) -> str:
    """A device as the role selectors show it."""
    return f"{name or '(no name)'} [{address}]"


def choice_address(text: str) -> str:
    """The address in a choice_text(), or ''."""
    m = re.search(r"\[([0-9A-Fa-f:]{17})\]$", text or "")
    return m.group(1).upper() if m else ""


def choice_name(text: str) -> str:
    return re.sub(r"\s*\[[0-9A-Fa-f:]{17}\]$", "", text or "")


NO_SERVICE = "no Pairing service (not provisioned?)"
CONNECT_HINT = ("Connect both boards on the Device page: provisioned boards that trust this "
                "PC (Host access).")


def row_status(result) -> str:
    """The devices list's Status column for a PairStatus or an exception."""
    if result is None:
        return ""
    if isinstance(result, Exception):
        return f"error: {result}"
    if not result.provisioned:
        return "not provisioned"
    if result.paired:
        return f"paired with {result.peer}" if result.peer else "paired"
    if result.running:
        return "pairing…"
    if result.failed:
        return f"ready (last run failed: {result.error_name})"
    return "ready"


def role_pill(text: str):
    """(pill text, tone) for a role's status text."""
    state = (text or "").split(" ")[0].strip(":,")
    if not state:
        return "Not started", "idle"
    return state.replace("_", " ").title(), STATE_TONE.get(state, "info")


def step_position(text: str, current: int = 0):
    """(index, state) of a role's step list for its status text."""
    state = (text or "").split(" ")[0].strip(":,")
    names = [s.name for s in pairing.State]
    if state not in names:
        return 0, "idle"
    value = pairing.State[state]
    if value == pairing.State.PAIRED:
        return len(pairing.STEPS) - 1, "done"
    if value == pairing.State.FAILED:
        return current, "failed"
    if value == pairing.State.IDLE:
        return 0, "idle"
    return value - pairing.State.ARMED, "running"


def check_text(central, peripheral) -> str:
    """The progress pane's result line after Check: each chosen device's
    PairStatus (or exception, or None if not chosen)."""
    if pairing.paired_with_each_other(central, peripheral):
        return ("Paired with each other already (bonded). "
                "Unpair one of them to pair them again.")
    parts = [f"{label} {row_status(res)}" for label, res in
             (("central", central), ("peripheral", peripheral)) if res is not None]
    return "Checked: " + "; ".join(parts)


def result_pill(text: str):
    """(pill text, tone) for the run's result line."""
    if not text:
        return "Idle", "idle"
    if text.startswith("Paired"):
        return "Paired", "ok"
    if text.startswith("Running"):
        return "Running", "info"
    if text.startswith("Cancelled"):
        return "Cancelled", "warn"
    if text.startswith("Checked"):
        return "Checked", "info"
    return "Failed", "err"


class PairingFeature(Feature):
    title = "Pairing"
    icon = "pair"

    def __init__(self, ctx):
        super().__init__(ctx)
        self._found = {}                 # address -> DeviceSession with the Pairing service
        self._checked = {}               # address -> PairStatus or exception
        self._future = None
        self._task = ""                  # "check" | "pair" | "unpair" while busy
        self._outcome = None
        pairing.register_decoders(ctx.decoders)

    # ---- UI ----------------------------------------------------------------
    def build(self, parent):
        theme = th.of(self.ctx)
        sp = theme.sp
        f = ttk.Frame(parent)
        f.columnconfigure((0, 1), weight=1, uniform="col")
        f.rowconfigure(0, weight=1)

        # Devices: the boards connected on the Device page, check each, choose the roles
        dev, head = card(f, "Devices")
        dev.grid(row=0, column=0, sticky="nsew", padx=(0, sp("s")))
        self.found_pill = Pill(head, theme, "None connected", "warn")
        self.found_pill.grid(row=0, column=2, sticky="e")
        top = ttk.Frame(dev)
        top.pack(fill="x")
        self.check_btn = ttk.Button(top, text="Check", command=self._check)
        self.check_btn.pack(side="left")
        set_icon(self.check_btn, theme, "refresh")

        body = ttk.Frame(dev)
        body.pack(fill="both", expand=True, pady=(sp("s"), 0))
        cols = ("name", "address", "status")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", height=6, selectmode="browse")
        for c, text, w in (("name", "Name", 120), ("address", "Address", 130),
                           ("status", "Status", 170)):
            self.tree.heading(c, text=text, anchor="w")
            self.tree.column(c, width=theme.px(w), minwidth=theme.px(36), anchor="w",
                             stretch=(c == "status"))
        sb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        ttk.Label(dev, text="The boards connected on the Device page. Those with the "
                            "Pairing service (provisioned) can be chosen; Check reads the "
                            "pairing status of the chosen central and peripheral.",
                  style="Caption.TLabel", wraplength=theme.px(360), justify="left").pack(
            anchor="w", pady=(theme.px(6), 0))

        roles = ttk.Frame(dev)
        roles.pack(fill="x", pady=(sp("m"), 0))
        roles.columnconfigure(1, weight=1)
        self.central_var = tk.StringVar()
        self.peripheral_var = tk.StringVar()
        self._combos = []
        for i, (label, var) in enumerate((("Central", self.central_var),
                                          ("Peripheral", self.peripheral_var))):
            ttk.Label(roles, text=label).grid(row=i, column=0, sticky="w", pady=2)
            combo = ttk.Combobox(roles, textvariable=var, state="readonly", values=())
            combo.grid(row=i, column=1, sticky="ew", padx=(sp("s"), 0), pady=2)
            self._combos.append(combo)
        self.swap_btn = ttk.Button(roles, text="Swap", command=self._swap)
        self.swap_btn.grid(row=0, column=2, rowspan=2, sticky="ns", padx=(sp("s"), 0), pady=2)

        # Pairing: one step list per device, the result, the actions
        run, head = card(f, "Pairing")
        run.grid(row=0, column=1, sticky="nsew", padx=(sp("s"), 0))
        self.result_pill = Pill(head, theme, "Idle", "idle")
        self.result_pill.grid(row=0, column=2, sticky="e")
        self.result_var = tk.StringVar()
        ttk.Label(run, textvariable=self.result_var, style="Caption.TLabel",
                  wraplength=theme.px(360), justify="left").pack(anchor="w", fill="x")

        self.role_vars, self.role_pills, self.steppers = {}, {}, {}
        for role in ROLES:
            row = ttk.Frame(run)
            row.pack(fill="x", pady=(sp("m"), 0))
            ttk.Label(row, text=role.title(), style="Strong.TLabel").pack(side="left")
            pill = Pill(row, theme, "Not started", "idle")
            pill.pack(side="right")
            var = tk.StringVar()
            stepper = Stepper(run, theme, pairing.STEPS)
            stepper.pack(anchor="w", fill="x", pady=(sp("xs"), 0))
            self.role_vars[role], self.role_pills[role], self.steppers[role] = var, pill, stepper

        self.hint_var = tk.StringVar()
        ttk.Label(run, textvariable=self.hint_var, style="Caption.TLabel",
                  wraplength=theme.px(360), justify="left").pack(anchor="w", pady=(sp("s"), 0))
        btns = ttk.Frame(run)
        btns.pack(fill="x", pady=(sp("s"), 0))
        self.pair_btn = ttk.Button(btns, text="Pair", style="Accent.TButton", command=self._pair)
        self.pair_btn.pack(side="left")
        self.cancel_btn = ttk.Button(btns, text="Cancel", command=self.cancel)
        self.cancel_btn.pack(side="left", padx=sp("s"))
        set_icon(self.pair_btn, theme, "pair", accent=True)
        set_icon(self.cancel_btn, theme, "stop")
        more = MoreMenu(btns, theme)
        more.pack(side="right")
        self.unpair_c_btn = more.add("Unpair the central device…", lambda: self._unpair("central"))
        self.unpair_p_btn = more.add("Unpair the peripheral device…", lambda: self._unpair("peripheral"))

        # Pills and step lists follow the text the logic writes
        self.result_var.trace_add("write", lambda *a: self.result_pill.set(
            *result_pill(self.result_var.get())))
        for role in ROLES:
            self.role_vars[role].trace_add("write", lambda *a, r=role: self._show_role(r))
        for var in (self.central_var, self.peripheral_var):
            var.trace_add("write", lambda *a: self._update())
        self._show_found()
        self._update()
        return f

    # ---- display -----------------------------------------------------------
    def _show_role(self, role: str):
        text = self.role_vars[role].get()
        self.role_pills[role].set(*role_pill(text))
        stepper = self.steppers[role]
        stepper.show(*step_position(text, stepper.current))

    def _show_found(self):
        """The devices list, the role choices and the count, from the boards
        connected now. A choice whose board is gone is cleared."""
        sessions = self.ctx.devices.connected()
        self._found = {s.key: s for s in sessions if s.has_characteristic(pairing.STATUS_UUID)}
        self._checked = {a: st for a, st in self._checked.items() if a in self._found}
        if not self.busy:
            for var in (self.central_var, self.peripheral_var):
                if choice_address(var.get()) and choice_address(var.get()) not in self._found:
                    var.set("")
        if hasattr(self, "tree"):
            self.tree.delete(*self.tree.get_children())
            for s in sessions:
                status = row_status(self._checked.get(s.key)) if s.key in self._found else NO_SERVICE
                self.tree.insert("", "end", iid=s.key, values=(s.name or "(no name)", s.key, status))
            choices = [choice_text(s.name, a) for a, s in self._found.items()]
            for combo in self._combos:
                combo.configure(values=choices)
        n = len(self._found)
        if hasattr(self, "found_pill"):
            self.found_pill.set(f"{n} connected" if n else "None connected", "ok" if n >= 2 else "warn")
        # Default roles: the first two boards connected
        addrs = list(self._found)
        if len(addrs) >= 2 and not choice_address(self.central_var.get()) \
                and not choice_address(self.peripheral_var.get()):
            self.central_var.set(choice_text(self._found[addrs[0]].name, addrs[0]))
            self.peripheral_var.set(choice_text(self._found[addrs[1]].name, addrs[1]))

    def _selected(self):
        """[(role, address, name)] for each role with a device chosen."""
        out = []
        for role, var in (("central", self.central_var), ("peripheral", self.peripheral_var)):
            addr = choice_address(var.get())
            if addr:
                out.append((role, addr, choice_name(var.get())))
        return out

    def _already_paired(self, roles) -> bool:
        """The chosen devices were last seen paired with each other."""
        return roles is not None and pairing.paired_with_each_other(
            self._checked.get(roles[0][0]), self._checked.get(roles[1][0]))

    def _reset_progress(self):
        """The progress pane back to its state before any run."""
        self._outcome = None
        for role in ROLES:
            self.role_vars[role].set("")
        self.result_var.set("")

    def _roles(self):
        """((address, name) central, (address, name) peripheral), or None if incomplete."""
        c, p = self.central_var.get(), self.peripheral_var.get()
        ca, pa = choice_address(c), choice_address(p)
        if not ca or not pa:
            return None
        return (ca, choice_name(c)), (pa, choice_name(p))

    def _update(self):
        busy = self.busy
        roles = self._roles()
        distinct = roles is not None and roles[0][0] != roles[1][0]
        paired = distinct and self._already_paired(roles)
        idle = not busy
        self.swap_btn.state(["!disabled"] if idle else ["disabled"])
        self.check_btn.state(["!disabled"] if idle and self._selected() else ["disabled"])
        self.pair_btn.state(["!disabled"] if idle and distinct and not paired else ["disabled"])
        self.cancel_btn.state(["!disabled"] if busy else ["disabled"])
        self.unpair_c_btn.state(["!disabled"] if idle and roles else ["disabled"])
        self.unpair_p_btn.state(["!disabled"] if idle and roles else ["disabled"])
        if not busy and len(self._found) < 2:
            set_var(self.hint_var, CONNECT_HINT)
        elif roles is not None and not distinct:
            set_var(self.hint_var, "Choose two different devices.")
        elif paired:
            set_var(self.hint_var, "These devices are paired with each other already. Unpair "
                                   "one of them (⋯ menu) to pair them again.")
        else:
            set_var(self.hint_var, "")

    def _log(self, text: str, level: str = "info"):
        self.ctx.log(f"pairing: {text}", level)

    # ---- work --------------------------------------------------------------
    def _link_for(self, address: str):
        """The connected link to a board, or None."""
        session = self.ctx.devices.get(address)
        return session.link if session is not None and session.connected else None

    def _orchestrator(self) -> pairing.PairingOrchestrator:
        """On the BLE loop; its callbacks come back to the Tk thread. It works
        on the Device page's links and never opens or closes one."""
        call = self.ctx.bus.call
        return pairing.PairingOrchestrator(
            existing=self._link_for, log=lambda t: call(self._log, t),
            on_status=lambda label, st: call(self._status_arrived, label, st))

    def _status_arrived(self, label: str, st: pairing.PairStatus):
        if label in self.role_vars and self._task == "pair":
            self.role_vars[label].set(st.describe())

    def _check(self):
        """Read the pairing status of the chosen central and peripheral, and show
        it in the progress pane and the devices list."""
        selected = self._selected()
        if not selected:
            return
        devices = {addr: name for _, addr, name in selected}

        async def go():
            orch = self._orchestrator()
            results = {}
            for addr, name in devices.items():
                try:
                    results[addr] = await orch.probe(addr, name)
                except Exception as e:          # noqa: BLE001 - shown per device
                    results[addr] = e
            return results

        def done(results):
            self._checked.update(results)
            self._outcome = None
            shown = dict.fromkeys(ROLES)
            for role, addr, _ in selected:
                shown[role] = results[addr]
            for role in ROLES:
                res = shown[role]
                self.role_vars[role].set(res.describe() if isinstance(res, pairing.PairStatus)
                                         else "")
            self.result_var.set(check_text(shown["central"], shown["peripheral"]))
            self._show_found()
            for role, addr, name in selected:
                self._log(f"{role} {name or addr}: {row_status(results[addr])}")
        self._run("check", go(), done)

    def _swap(self):
        c, p = self.central_var.get(), self.peripheral_var.get()
        self.central_var.set(p)
        self.peripheral_var.set(c)

    def _pair(self):
        roles = self._roles()
        if roles is None or roles[0][0] == roles[1][0]:
            messagebox.showerror("Pairing", "Choose two different devices: one central, one peripheral.")
            return
        if self._already_paired(roles):
            messagebox.showerror("Pairing", "These devices are paired with each other already. "
                                            "Unpair one of them first.")
            return
        central, peripheral = roles
        self._reset_progress()
        self.result_var.set("Running…")

        async def go():
            return await self._orchestrator().pair(central, peripheral)

        def done(out: pairing.PairingOutcome):
            self._outcome = out
            self._checked[central[0]] = out.central
            self._checked[peripheral[0]] = out.peripheral
            self.role_vars["central"].set(out.central.describe())
            self.role_vars["peripheral"].set(out.peripheral.describe())
            if out.ok:
                self.result_var.set(f"Paired: {out.message()}")
                self._log(f"{central[1] or central[0]} and {peripheral[1] or peripheral[0]} paired; "
                          "the devices keep their encrypted link, the peripheral lights LED0")
            else:
                self.result_var.set(f"Failed: {out.message()}")
                self._log(f"failed: {out.message()}", "error")
            self._show_found()
        self._log(f"pairing {central[1] or central[0]} (central) with "
                  f"{peripheral[1] or peripheral[0]} (peripheral)")
        self._run("pair", go(), done)

    def _unpair(self, role: str):
        roles = self._roles()
        if roles is None:
            return
        addr, name = roles[0] if role == "central" else roles[1]
        if not messagebox.askyesno("Unpair", f"Delete the bond of {name or addr} and drop its "
                                             "link to its peer?"):
            return

        async def go():
            return await self._orchestrator().unpair(addr, name)

        def done(st: pairing.PairStatus):
            self._checked[addr] = st
            self.role_vars[role].set(st.describe())
            self._show_found()
            self._log(f"{name or addr} unpaired: {st.describe()}")
        self._run("unpair", go(), done)

    def _run(self, task: str, coro, on_done):
        def finished(result):
            self._future, self._task = None, ""
            on_done(result)
            self._update()

        def failed(exc):
            self._future, self._task = None, ""
            if task == "pair":
                self.result_var.set(f"Not started: {exc}")
            self._log(f"{task} failed: {exc}", "error")
            self._update()

        def cancelled():
            self._future, self._task = None, ""
            if task == "pair":
                self.result_var.set("Cancelled (CANCEL sent to both devices)")
            self._log(f"{task} cancelled", "warn")
            self._update()
        self._task = task
        self._future = self.ctx.run(coro, on_done=finished, on_error=failed, on_cancel=cancelled)
        self._update()

    # ---- Feature -----------------------------------------------------------
    @property
    def busy(self) -> bool:
        return self._future is not None

    def cancel(self):
        if self._future is not None:
            self._future.cancel()

    def on_connected(self, info):
        self._update()

    def on_disconnected(self, reason):
        self._update()

    def on_devices_changed(self):
        """A board connected or disconnected on the Device page."""
        self._show_found()
        self._update()
