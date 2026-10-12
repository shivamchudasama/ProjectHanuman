"""ECU: UDS diagnostics and flashing on the device's CAN bus (_DOC/UDS/PROTOCOL.md).

The device talks UDS over ISO-TP to an ECU; this page tells it what to do, as
`setu_client.py uds` / `flash` do. Three views, one shown at a time:
  - Profile: the target (CAN / CAN FD, IDs, timing) and the flash sequence,
    loaded from and saved to the JSON profiles of _TOOLS/EcuSim/profiles;
  - Diagnostics: raw requests (and a few common ones), SecurityAccess with an
    on-device key algorithm, the responses with their NRC named;
  - Flash: a stored upload (/FLASH_DISK:/FW/<name>) flashed with the profile's
    sequence, followed by STATUS: steps, records, bytes, rate, last NRC.
Apply target sends TARGET from the form. A flash job runs on the device: a
lost link stops only the following, and the page picks the job up again
(STATUS_REQ) when it connects.
"""

import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..protocols import filesystem as fsp
from ..protocols import setu
from ..protocols import uds
from ..ui import theme as th
from ..ui.widgets import MoreMenu, Pill, StatTile, Stepper, Tooltip, card, set_icon, set_var
from .base import Feature

FILE_DIR = "/FLASH_DISK:/FW/"
PROFILE_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "EcuSim", "profiles"))
RESPONSE_LINES = 500                     # kept in the responses pane
VIEWS = (("profile", "Profile"), ("diag", "Diagnostics"), ("flash", "Flash"))

# Quick requests: (hex, what it does)
QUICK = (
    ("10 01", "DiagnosticSessionControl: default session"),
    ("10 03", "DiagnosticSessionControl: extended session"),
    ("3E 00", "TesterPresent"),
    ("22 F1 90", "ReadDataByIdentifier: VIN"),
    ("19 02 FF", "ReadDTCInformation: DTCs by status mask"),
    ("14 FF FF FF", "ClearDiagnosticInformation: all groups"),
    ("11 01", "ECUReset: hard reset"),
)

# Form fields: name -> default text
TARGET_TEXT = ("bitrate", "data_bitrate", "tx_id", "rx_id", "func_id", "dl", "p2", "p2star")
TARGET_BOOL = ("fd", "brs", "ext_ids", "padding")
SEQ_TEXT = ("level", "algo", "comm_control", "comm_type", "fp_did", "fp_data", "erase_rid", "check_rid",
            "reset_type", "alfid", "dfi", "max_block")
OTHER_TEXT = ("file", "request", "unlock_level", "unlock_algo")
OTHER_BOOL = ("functional",)
# Buttons that send something (enabled while the link is ready and nothing runs)
SEND_BUTTONS = ("apply_btn", "send_btn", "unlock_btn", "refresh_btn", "flash_btn")
CAN_FD_DL = (0, 8, 12, 16, 20, 24, 32, 48, 64)

# Stepper rows: (job steps shown on the row, label)
_STEP_ROWS = {
    "EXT_SESSION": ((1,), "Extended session (10 03)"),
    "DTC_OFF": ((2,), "DTC setting off (85 02)"),
    "COMM_OFF": ((3,), "Communication off (28)"),
    "PROG": ((4,), "Programming session (10 02)"),
    "SECURITY": ((5,), "Security access (27)"),
    "FINGERPRINT": ((6,), "Fingerprint (2E)"),
    "ERASE": ((7,), "Erase (31 01)"),
    "DOWNLOAD": ((8, 9, 10), "Download (34 / 36 / 37)"),
    "ERASE_DOWNLOAD": ((7, 8, 9, 10), "Erase and download per record"),
    "CHECK": ((11,), "Check (31 01)"),
    "RESET": ((12,), "ECU reset (11)"),
    "DONE": ((13,), "Done"),
}
JOB_TONES = {0: "idle", 1: "info", 2: "ok", 3: "err", 4: "warn"}
STEPPER_STATES = {0: "idle", 1: "running", 2: "done", 3: "failed", 4: "aborted"}


# ---- form values ---------------------------------------------------------------------
def parse_int(text: str, what: str, lo: int, hi: int) -> int:
    """A number in decimal or 0x hex, lo..hi; ValueError naming the field otherwise."""
    t = str(text).strip()
    try:
        v = int(t, 0)
    except ValueError:
        raise ValueError(f"{what}: '{t}' is not a number") from None
    if not lo <= v <= hi:
        fmt = (lambda n: f"0x{n:X}") if t.lower().startswith("0x") else str
        raise ValueError(f"{what} must be {fmt(lo)}…{fmt(hi)}")
    return v


def parse_bitrate(text: str, what: str, lo: int, hi: int) -> int:
    """500000, 500k, 2M, 2.5M -> bit/s."""
    t = str(text).strip().lower().replace("_", "")
    scale = 1
    if t.endswith("k"):
        t, scale = t[:-1], 1000
    elif t.endswith("m"):
        t, scale = t[:-1], 1000000
    try:
        v = round(float(t) * scale)
    except ValueError:
        raise ValueError(f"{what}: '{text}' is not a bitrate") from None
    if not lo <= v <= hi:
        raise ValueError(f"{what} must be {lo:,}…{hi:,} bit/s")
    return v


def parse_level(text: str) -> int:
    v = parse_int(text, "Security level", 0x01, 0x7D)
    if not v & 1:
        raise ValueError("Security level must be odd (the requestSeed level)")
    return v


def parse_algo(text: str) -> int:
    t = str(text).strip()
    for name, v in uds.ALGOS.items():
        if t.upper() == name:
            return v
    return parse_int(t, "Key algorithm", 0, 0xFF)


def algo_text(v: int) -> str:
    return next((n for n, a in uds.ALGOS.items() if a == v), f"0x{v:02X}")


def parse_request(text: str, functional: bool = False) -> bytes:
    t = str(text).replace(" ", "").replace(",", "").replace("0x", "")
    try:
        req = bytes.fromhex(t)
    except ValueError:
        raise ValueError("the request is not hex (for example 22 F1 90)") from None
    if not 1 <= len(req) <= uds.DIAG_REQ_MAX:
        raise ValueError(f"a request is 1…{uds.DIAG_REQ_MAX} bytes")
    if functional and len(req) > 7:
        raise ValueError("a functional request is at most 7 bytes")
    return req


def check_file_name(name: str) -> str:
    name = name.strip()
    if not uds.FILE_NAME_RE.fullmatch(name):
        raise ValueError("the file name is 1…32 characters of A-Z a-z 0-9 . _ -")
    return name


def bitrate_text(v: int) -> str:
    if v % 1000000 == 0:
        return f"{v // 1000000}M"
    return f"{v // 1000}k" if v % 1000 == 0 else str(v)


def target_summary(t: uds.Target) -> str:
    can = f"CAN FD {bitrate_text(t.bitrate)}/{bitrate_text(t.data_bitrate)}{' BRS' if t.brs else ''}" \
        if t.fd else f"CAN {bitrate_text(t.bitrate)}"
    width = 8 if t.extended_ids else 3
    ids = f"tx 0x{t.tx_id:0{width}X} rx 0x{t.rx_id:0{width}X}"
    if t.func_id is not None:
        ids += f" func 0x{t.func_id:0{width}X}"
    return f"{can} · {ids} · DL {t.dl or (64 if t.fd else 8)}"


def flash_steps(params: uds.FlashParams) -> list:
    """The stepper's rows for this sequence: [(job steps, label)]."""
    f, ff = params.flags, uds.FF
    keys = [k for k in ("EXT_SESSION", "DTC_OFF", "COMM_OFF") if f & ff[k]] + ["PROG"]
    keys += [k for k in ("SECURITY", "FINGERPRINT") if f & ff[k]]
    if f & ff["ERASE_PER_RECORD"]:
        keys.append("ERASE_DOWNLOAD")
    else:
        keys += (["ERASE"] if f & ff["ERASE"] else []) + ["DOWNLOAD"]
    keys += [k for k in ("CHECK", "RESET") if f & ff[k]] + ["DONE"]
    return [_STEP_ROWS[k] for k in keys]


def step_row(rows: list, step: int) -> int:
    """The row that shows job step `step` (0: the first)."""
    for i, (steps, _) in enumerate(rows):
        if step in steps:
            return i
    return next((i for i, (steps, _) in enumerate(rows) if min(steps) > step), 0)


class EcuFeature(Feature):
    title = "ECU"
    icon = "car"

    def __init__(self, ctx):
        super().__init__(ctx)
        self._runs = 0
        self._running = {}                 # "op" | "job" -> run number while it runs
        self._futures = {}
        self._uds = None                   # UdsSession on the routed client (BLE loop)
        self._seq = 0
        self.applied = None                # the Target the device accepted
        self.profile_path = None
        self.files = []                    # stored uploads (names), as listed
        self.responses = []                # lines of the responses pane
        self.last_status = None
        self.rows = flash_steps(uds.FlashParams())
        self._job_name = ""
        self._t0 = None                    # (time, bytes done) when following began
        self.rate = None                   # kbit/s of the job followed

    # ---- UI ----------------------------------------------------------------
    def build(self, parent):
        theme = th.of(self.ctx)
        sp = theme.sp
        f = ttk.Frame(parent)
        self.v = {n: tk.StringVar() for n in TARGET_TEXT + SEQ_TEXT + OTHER_TEXT}
        self.v.update({n: tk.BooleanVar() for n in TARGET_BOOL + OTHER_BOOL})
        self.flag_vars = {n: tk.BooleanVar() for n in uds.FF}
        self.view_var = tk.StringVar(value="profile")

        top, head = card(f, "ECU target")
        top.pack(fill="x")
        self.state_pill = Pill(head, theme, "Not connected", "idle")
        self.state_pill.grid(row=0, column=2, sticky="e")
        row = ttk.Frame(top)
        row.pack(fill="x")
        self.summary_var = tk.StringVar()
        ttk.Label(row, textvariable=self.summary_var, style="Mono.TLabel").pack(side="left", fill="x",
                                                                               expand=True)
        self.apply_btn = ttk.Button(row, text="Apply target", style="Accent.TButton", command=self.apply_target)
        self.apply_btn.pack(side="right")
        set_icon(self.apply_btn, theme, "connect", accent=True)

        seg = ttk.Frame(f)
        seg.pack(fill="x", pady=sp("m"))
        for key, text in VIEWS:
            ttk.Radiobutton(seg, text=text, value=key, variable=self.view_var, style="Toggle.TButton",
                            command=self._show_view).pack(side="left", padx=(0, sp("xs")))
        self.views = {"profile": self._build_profile(f, theme), "diag": self._build_diag(f, theme),
                      "flash": self._build_flash(f, theme)}

        self.fill_form(uds.Target(), uds.FlashParams())
        for var in list(self.v.values()) + list(self.flag_vars.values()):
            var.trace_add("write", lambda *a: self._update())
        self._show_view()
        self._update()
        if self._available:
            self._check_job()
        return f

    def _grid_entry(self, parent, row, col, label, name, width=12, tip=None):
        sp = th.of(self.ctx).sp
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="w", pady=2)
        e = ttk.Entry(parent, textvariable=self.v[name], width=width)
        e.grid(row=row, column=col + 1, sticky="w", padx=(sp("s"), sp("m")), pady=2)
        if tip:
            Tooltip(e, tip, th.of(self.ctx))
        return e

    def _build_profile(self, parent, theme):
        sp = theme.sp
        page = ttk.Frame(parent)
        prow = ttk.Frame(page)
        prow.pack(fill="x", pady=(0, sp("s")))
        self.profile_var = tk.StringVar(value="Profile: defaults (not saved)")
        ttk.Label(prow, textvariable=self.profile_var, style="Caption.TLabel").pack(side="left")
        for text, cmd, icon in (("New", self.new_profile, "add"), ("Save as…", self.save_profile, "save"),
                                ("Load…", self.load_profile, "folder")):
            b = ttk.Button(prow, text=text, command=cmd)
            b.pack(side="right", padx=(sp("s"), 0))
            set_icon(b, theme, icon)

        cols = ttk.Frame(page)
        cols.pack(fill="both", expand=True)
        cols.columnconfigure(0, weight=1, uniform="col")
        cols.columnconfigure(1, weight=1, uniform="col")

        can, _ = card(cols, "CAN and addressing")
        can.grid(row=0, column=0, sticky="nsew", padx=(0, sp("s")))
        g = ttk.Frame(can)
        g.pack(fill="x")
        self._grid_entry(g, 0, 0, "Bitrate", "bitrate", tip="Nominal bitrate: 500000, 500k, 1M")
        ttk.Checkbutton(g, text="CAN FD", variable=self.v["fd"]).grid(row=0, column=2, columnspan=2, sticky="w")
        self._grid_entry(g, 1, 0, "Data bitrate", "data_bitrate", tip="CAN FD data phase: 2M")
        ttk.Checkbutton(g, text="BRS", variable=self.v["brs"]).grid(row=1, column=2, columnspan=2, sticky="w")
        self._grid_entry(g, 2, 0, "TX ID", "tx_id", tip="Physical request ID (0x7E0)")
        self._grid_entry(g, 3, 0, "RX ID", "rx_id", tip="Response ID (0x7E8)")
        self._grid_entry(g, 4, 0, "Functional ID", "func_id", tip="Functional request ID (0x7DF); empty: none")
        ttk.Checkbutton(g, text="29-bit IDs", variable=self.v["ext_ids"]).grid(row=2, column=2, columnspan=2,
                                                                             sticky="w")
        ttk.Checkbutton(g, text="Padding (0xCC)", variable=self.v["padding"]).grid(row=3, column=2, columnspan=2,
                                                                                  sticky="w")
        self._grid_entry(g, 5, 0, "DL", "dl", width=6,
                         tip="ISO-TP frame length: 0 (8, or 64 with CAN FD), 8, or with CAN FD 12…64")
        self._grid_entry(g, 6, 0, "P2 ms", "p2", width=6, tip="0: 150 ms, then the ECU's own")
        self._grid_entry(g, 6, 2, "P2* ms", "p2star", width=6, tip="0: 5000 ms, then the ECU's own")
        ttk.Label(can, text="Padding must match the firmware build (on, 0xCC).",
                  style="Caption.TLabel").pack(anchor="w", pady=(sp("s"), 0))

        seq, _ = card(cols, "Flash sequence")
        seq.grid(row=0, column=1, sticky="nsew", padx=(sp("s"), 0))
        g = ttk.Frame(seq)
        g.pack(fill="x")
        checks = (("EXT_SESSION", "Extended session (10 03)"), ("DTC_OFF", "DTC setting off (85 02)"),
                  ("COMM_OFF", "Communication control (28)"), ("SECURITY", "Security access (27)"),
                  ("FINGERPRINT", "Fingerprint (2E)"), ("ERASE", "Erase routine (31)"),
                  ("ERASE_PER_RECORD", "… per record"), ("CHECK", "Check routine (31)"),
                  ("CHECK_CRC", "… with the CRC-32"), ("RESET", "ECU reset (11)"))
        for i, (flag, text) in enumerate(checks):
            ttk.Checkbutton(g, text=text, variable=self.flag_vars[flag]).grid(row=i // 2, column=(i % 2) * 2,
                                                                             columnspan=2, sticky="w")
        g2 = ttk.Frame(seq)
        g2.pack(fill="x", pady=(sp("s"), 0))
        self._grid_entry(g2, 0, 0, "Level", "level", width=6, tip="requestSeed level (odd)")
        self._grid_entry(g2, 0, 2, "Key algo", "algo", width=10, tip="BENCH_XOR, or 0x80…0xFF (OEM builds)")
        self._grid_entry(g2, 1, 0, "Comm control", "comm_control", width=6, tip="0x28 controlType")
        self._grid_entry(g2, 1, 2, "Comm type", "comm_type", width=6, tip="0x28 communicationType")
        self._grid_entry(g2, 2, 0, "Fingerprint DID", "fp_did", width=8)
        self._grid_entry(g2, 2, 2, "Data (hex)", "fp_data", width=18, tip="1…16 bytes")
        self._grid_entry(g2, 3, 0, "Erase RID", "erase_rid", width=8)
        self._grid_entry(g2, 3, 2, "Check RID", "check_rid", width=8)
        self._grid_entry(g2, 4, 0, "Reset type", "reset_type", width=6)
        self._grid_entry(g2, 4, 2, "ALFID", "alfid", width=6,
                         tip="addressAndLengthFormatIdentifier: size and address bytes, 1…4 each")
        self._grid_entry(g2, 5, 0, "DFI", "dfi", width=6, tip="dataFormatIdentifier")
        self._grid_entry(g2, 5, 2, "Max block", "max_block", width=6,
                         tip="Cap on a TransferData request; 0: the ECU's (the device caps at 2048)")
        return page

    def _build_diag(self, parent, theme):
        sp = theme.sp
        page = ttk.Frame(parent)
        req, _ = card(page, "Request")
        req.pack(fill="x")
        row = ttk.Frame(req)
        row.pack(fill="x")
        e = ttk.Entry(row, textvariable=self.v["request"], font=theme.fonts["mono"])
        e.pack(side="left", fill="x", expand=True)
        e.bind("<Return>", lambda _e: self.send_request())
        ttk.Checkbutton(row, text="Functional", variable=self.v["functional"]).pack(side="left", padx=sp("s"))
        self.send_btn = ttk.Button(row, text="Send", style="Accent.TButton", command=self.send_request)
        self.send_btn.pack(side="left")
        set_icon(self.send_btn, theme, "play", accent=True)
        qrow = ttk.Frame(req)
        qrow.pack(fill="x", pady=(sp("s"), 0))
        self.quick_btns = []
        for hex_, what in QUICK:
            b = ttk.Button(qrow, text=hex_, command=lambda h=hex_: self.quick(h))
            b.pack(side="left", padx=(0, sp("xs")))
            Tooltip(b, what, theme)
            self.quick_btns.append(b)

        sec, _ = card(page, "Security access")
        sec.pack(fill="x", pady=(sp("m"), 0))
        row = ttk.Frame(sec)
        row.pack(fill="x")
        ttk.Label(row, text="Level").pack(side="left")
        ttk.Entry(row, textvariable=self.v["unlock_level"], width=6).pack(side="left", padx=sp("s"))
        ttk.Label(row, text="Algorithm").pack(side="left")
        algo = ttk.Combobox(row, textvariable=self.v["unlock_algo"], values=list(uds.ALGOS), width=12)
        algo.pack(side="left", padx=sp("s"))
        theme.on_change(lambda p: th.style_combobox(algo, p))
        self.unlock_btn = ttk.Button(row, text="Unlock", command=self.unlock)
        self.unlock_btn.pack(side="left")
        set_icon(self.unlock_btn, theme, "shield")
        ttk.Label(sec, text="The device computes the key (27 level, then 27 level+1).",
                  style="Caption.TLabel").pack(anchor="w", pady=(sp("s"), 0))

        rsp, head = card(page, "Responses")
        rsp.pack(fill="both", expand=True, pady=(sp("m"), 0))
        clear = ttk.Button(head, text="Clear", command=self.clear_responses)
        clear.grid(row=0, column=2, sticky="e")
        set_icon(clear, theme, "clear")
        body = ttk.Frame(rsp)
        body.pack(fill="both", expand=True)
        self.rsp_text = tk.Text(body, height=8, wrap="none", font=theme.fonts["mono"], state="disabled")
        self.rsp_text.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(body, orient="vertical", command=self.rsp_text.yview)
        sb.pack(side="right", fill="y")
        self.rsp_text.configure(yscrollcommand=sb.set)
        theme.on_change(lambda p: th.style_text(self.rsp_text, p))
        return page

    def _build_flash(self, parent, theme):
        sp = theme.sp
        page = ttk.Frame(parent)
        job, head = card(page, "Flash a stored upload")
        job.pack(fill="x")
        self.job_pill = Pill(head, theme, "No job", "idle")
        self.job_pill.grid(row=0, column=2, sticky="e")
        row = ttk.Frame(job)
        row.pack(fill="x")
        ttk.Label(row, text=FILE_DIR).pack(side="left")
        self.file_box = ttk.Combobox(row, textvariable=self.v["file"], values=(), width=24)
        self.file_box.pack(side="left", padx=sp("s"))
        theme.on_change(lambda p: th.style_combobox(self.file_box, p))
        self.refresh_btn = ttk.Button(row, text="Refresh", command=self.refresh_files)
        self.refresh_btn.pack(side="left")
        set_icon(self.refresh_btn, theme, "refresh")
        more = MoreMenu(row, theme)
        more.pack(side="right")
        self.status_entry = more.add("Get job status", self.get_status)
        self.abort_btn = ttk.Button(row, text="Abort", style="Danger.TButton", command=self.abort)
        self.abort_btn.pack(side="right", padx=(sp("s"), sp("s")))
        set_icon(self.abort_btn, theme, "stop")
        self.flash_btn = ttk.Button(row, text="Flash", style="Accent.TButton", command=self.flash)
        self.flash_btn.pack(side="right")
        set_icon(self.flash_btn, theme, "upload", accent=True)
        ttk.Label(job, text="Store the file first: Hex Upload with Store as. The sequence is the profile's.",
                  style="Caption.TLabel").pack(anchor="w", pady=(sp("s"), 0))
        self.progress = ttk.Progressbar(job, mode="determinate")
        self.progress.pack(fill="x", pady=(sp("s"), 0))

        body = ttk.Frame(page)
        body.pack(fill="both", expand=True, pady=(sp("m"), 0))
        tiles = ttk.Frame(body)
        tiles.pack(side="left", fill="both", expand=True)
        self.tile_rec = StatTile(tiles, "Record", "–", "of the file")
        self.tile_data = StatTile(tiles, "Data", "–", "bytes transferred")
        self.tile_rate = StatTile(tiles, "Rate", "–", "kbit/s")
        self.tile_nrc = StatTile(tiles, "Last NRC", "–", "none")
        for i, t in enumerate((self.tile_rec, self.tile_data, self.tile_rate, self.tile_nrc)):
            t.grid(row=i // 2, column=i % 2, sticky="ew", padx=(0 if i % 2 == 0 else sp("m"), 0),
                   pady=(0 if i < 2 else sp("m"), 0))
            tiles.columnconfigure(i % 2, weight=1, uniform="tile")
        steps, _ = card(body, "Sequence")
        steps.pack(side="right", fill="y", padx=(sp("m"), 0))
        self.stepper = Stepper(steps, theme, [label for _, label in self.rows])
        self.stepper.pack(anchor="nw")
        return page

    def _show_view(self):
        key = self.view_var.get()
        for k, frame in self.views.items():
            if k != key:
                frame.pack_forget()
        self.views[key].pack(fill="both", expand=True)

    # ---- the form --------------------------------------------------------------
    def fill_form(self, target: uds.Target, params: uds.FlashParams):
        v = self.v
        width = 8 if target.extended_ids else 3
        values = {
            "bitrate": bitrate_text(target.bitrate), "data_bitrate": bitrate_text(target.data_bitrate),
            "tx_id": f"0x{target.tx_id:0{width}X}", "rx_id": f"0x{target.rx_id:0{width}X}",
            "func_id": "" if target.func_id is None else f"0x{target.func_id:0{width}X}",
            "dl": str(target.dl), "p2": str(target.p2_ms), "p2star": str(target.p2star_ms),
            "fd": target.fd, "brs": target.brs, "ext_ids": target.extended_ids, "padding": target.padding,
            "level": str(params.security_level), "algo": algo_text(params.key_algo),
            "comm_control": f"0x{params.comm_control:02X}", "comm_type": f"0x{params.comm_type:02X}",
            "fp_did": f"0x{params.fingerprint_did:04X}", "fp_data": bytes(params.fingerprint).hex().upper(),
            "erase_rid": f"0x{params.erase_rid:04X}", "check_rid": f"0x{params.check_rid:04X}",
            "reset_type": f"0x{params.reset_type:02X}", "alfid": f"0x{params.alfid:02X}",
            "dfi": f"0x{params.dfi:02X}", "max_block": str(params.max_block),
        }
        for name, value in values.items():
            set_var(v[name], value)
        if not v["unlock_level"].get():
            v["unlock_level"].set(values["level"])
            v["unlock_algo"].set(values["algo"])
        for name, var in self.flag_vars.items():
            set_var(var, bool(params.flags & uds.FF[name]))

    def target_from_form(self) -> uds.Target:
        v = self.v
        fd, ext = bool(v["fd"].get()), bool(v["ext_ids"].get())
        id_max = 0x1FFFFFFF if ext else 0x7FF
        what = "29-bit" if ext else "11-bit"
        tx = parse_int(v["tx_id"].get(), f"TX ID ({what})", 0, id_max)
        rx = parse_int(v["rx_id"].get(), f"RX ID ({what})", 0, id_max)
        if tx == rx:
            raise ValueError("TX and RX IDs must differ")
        func = v["func_id"].get().strip()
        func_id = parse_int(func, f"Functional ID ({what})", 0, id_max) if func else None
        bitrate = parse_bitrate(v["bitrate"].get(), "Bitrate", 10000, 1000000)
        data_bitrate = uds.Target.data_bitrate
        if fd:
            data_bitrate = parse_bitrate(v["data_bitrate"].get(), "Data bitrate", 10000, 12000000)
        dl = parse_int(v["dl"].get(), "DL", 0, 64)
        if dl not in (CAN_FD_DL if fd else (0, 8)):
            raise ValueError("DL must be 0 or 8" + (", 12, 16, 20, 24, 32, 48 or 64" if fd else
                                                    " (12…64 needs CAN FD)"))
        return uds.Target(tx_id=tx, rx_id=rx, func_id=func_id, bitrate=bitrate, fd=fd, data_bitrate=data_bitrate,
                          brs=fd and bool(v["brs"].get()), extended_ids=ext, dl=dl,
                          padding=bool(v["padding"].get()), p2_ms=parse_int(v["p2"].get(), "P2", 0, 0xFFFF),
                          p2star_ms=parse_int(v["p2star"].get(), "P2*", 0, 0xFFFF))

    def params_from_form(self) -> uds.FlashParams:
        v, ff = self.v, uds.FF
        flags = 0
        for name, var in self.flag_vars.items():
            if var.get():
                flags |= ff[name]
        if not flags & ff["ERASE"]:
            flags &= ~ff["ERASE_PER_RECORD"]
        if not flags & ff["CHECK"]:
            flags &= ~ff["CHECK_CRC"]
        alfid = parse_int(v["alfid"].get(), "ALFID", 0, 0xFF)
        if not (1 <= alfid >> 4 <= 4 and 1 <= alfid & 0xF <= 4):
            raise ValueError("ALFID: size and address bytes must be 1…4 each (0x44)")
        fp = v["fp_data"].get().replace(" ", "")
        try:
            fingerprint = bytes.fromhex(fp)
        except ValueError:
            raise ValueError("Fingerprint data is not hex") from None
        if len(fingerprint) > uds.FP_MAX or (flags & ff["FINGERPRINT"] and not fingerprint):
            raise ValueError(f"Fingerprint data is 1…{uds.FP_MAX} bytes")
        return uds.FlashParams(
            flags=flags, security_level=parse_level(v["level"].get()), key_algo=parse_algo(v["algo"].get()),
            comm_control=parse_int(v["comm_control"].get(), "Comm control", 0, 0xFF),
            comm_type=parse_int(v["comm_type"].get(), "Comm type", 0, 0xFF),
            reset_type=parse_int(v["reset_type"].get(), "Reset type", 0, 0xFF), alfid=alfid,
            dfi=parse_int(v["dfi"].get(), "DFI", 0, 0xFF),
            erase_rid=parse_int(v["erase_rid"].get(), "Erase RID", 0, 0xFFFF),
            check_rid=parse_int(v["check_rid"].get(), "Check RID", 0, 0xFFFF),
            max_block=parse_int(v["max_block"].get(), "Max block", 0, 0xFFFF),
            fingerprint_did=parse_int(v["fp_did"].get(), "Fingerprint DID", 0, 0xFFFF), fingerprint=fingerprint)

    # ---- profiles ----------------------------------------------------------------
    def _set_profile(self, path):
        self.profile_path = path
        set_var(self.profile_var, f"Profile: {os.path.basename(path)}" if path else
                "Profile: defaults (not saved)")

    def new_profile(self):
        self.fill_form(uds.Target(), uds.FlashParams())
        self._set_profile(None)

    def load_profile(self):
        path = filedialog.askopenfilename(title="ECU profile", filetypes=[("Profile", "*.json"), ("All", "*")],
                                          initialdir=PROFILE_DIR if os.path.isdir(PROFILE_DIR) else None)
        if not path:
            return
        try:
            target, params = uds.load_profile(path)
        except (OSError, ValueError, KeyError, TypeError) as e:
            messagebox.showerror("Load profile", f"{os.path.basename(path)}: {e}")
            return
        self.fill_form(target, params)
        self._set_profile(path)
        self.ctx.log(f"ecu: profile {os.path.basename(path)} loaded")

    def save_profile(self):
        try:
            target, params = self.target_from_form(), self.params_from_form()
        except ValueError as e:
            messagebox.showerror("Save profile", str(e))
            return
        path = filedialog.asksaveasfilename(title="Save the ECU profile", defaultextension=".json",
                                            filetypes=[("Profile", "*.json")],
                                            initialfile=os.path.basename(self.profile_path or "ecu.json"))
        if not path:
            return
        try:
            uds.save_profile(path, target, params)
        except OSError as e:
            messagebox.showerror("Save profile", str(e))
            return
        self._set_profile(path)
        self.ctx.log(f"ecu: profile saved to {path}")

    # ---- state shown ---------------------------------------------------------------
    @property
    def _available(self) -> bool:
        svc = self.ctx.services.get(setu.SETUService.NAME)
        return bool(self.ctx.link.connected and svc is not None and svc.available)

    def _update(self):
        try:
            target = self.target_from_form()
            summary = target_summary(target)
        except ValueError as e:
            target, summary = None, f"⚠ {e}"
        set_var(self.summary_var, summary)
        flashing = "job" in self._running
        ready = self._available and not self.busy
        for name in SEND_BUTTONS:
            need_target = name in ("send_btn", "unlock_btn", "flash_btn")
            ok = ready and (self.applied is not None or not need_target)
            getattr(self, name).state(["!disabled"] if ok else ["disabled"])
        for b in self.quick_btns:
            b.state(["!disabled"] if ready and self.applied is not None else ["disabled"])
        self.status_entry.state(["!disabled"] if ready else ["disabled"])
        self.abort_btn.state(["!disabled"] if flashing and self._available else ["disabled"])
        if not self.ctx.link.connected:
            self.state_pill.set("Not connected", "idle")
        elif not self._available:
            self.state_pill.set("No SETU service", "warn")
        elif flashing:
            self.state_pill.set("Flashing", "info")
        elif self.busy:
            self.state_pill.set("Busy", "info")
        elif self.applied is None:
            self.state_pill.set("No target", "idle")
        elif target != self.applied:
            self.state_pill.set("Target changed: apply", "warn")
        else:
            self.state_pill.set("Target set", "ok")

    def _respond(self, line: str):
        """A line in the responses pane (the last RESPONSE_LINES kept)."""
        self.responses.append(line)
        t = self.rsp_text
        t.configure(state="normal")
        t.insert("end", line + "\n")
        if len(self.responses) > RESPONSE_LINES:
            drop = len(self.responses) - RESPONSE_LINES
            del self.responses[:drop]
            t.delete("1.0", f"{drop + 1}.0")
        t.see("end")
        t.configure(state="disabled")

    def clear_responses(self):
        self.responses = []
        self.rsp_text.configure(state="normal")
        self.rsp_text.delete("1.0", "end")
        self.rsp_text.configure(state="disabled")

    def _show_files(self, names: list):
        self.files = names
        self.file_box.configure(values=names)
        if names and self.v["file"].get().strip() not in names:
            self.v["file"].set(names[0])

    def _set_rows(self, params):
        self.rows = flash_steps(params)
        self.stepper.set_steps([label for _, label in self.rows])

    def show_status(self, st: uds.Status):
        """Show a STATUS: the stepper, tiles, progress and job pill."""
        self.last_status = st
        self.stepper.show(step_row(self.rows, st.step), STEPPER_STATES.get(st.state, "idle"))
        self.job_pill.set(st.state_name + (f": {uds.status_name(st.status)}" if st.state == 3 else ""),
                          JOB_TONES.get(st.state, "idle"))
        if st.rec_cnt:
            self.tile_rec.set(f"{min(st.rec_idx + 1, st.rec_cnt)} / {st.rec_cnt}", "of the file")
        else:
            self.tile_rec.set("–", "of the file")
        if st.total:
            self.tile_data.set(f"{st.done:,} / {st.total:,}", f"bytes, {100 * st.done // st.total} %")
        else:
            self.tile_data.set("–", "bytes transferred")
        self.progress.configure(maximum=max(st.total, 1), value=st.done)
        if self._t0 is None:
            self._t0 = (time.perf_counter(), st.done)
        dt = time.perf_counter() - self._t0[0]
        if st.running and dt > 0.5 and st.done > self._t0[1]:
            self.rate = (st.done - self._t0[1]) * 8 / dt / 1000
            self.tile_rate.set(f"{self.rate:.1f}", "kbit/s")
        if st.last_nrc:
            self.tile_nrc.set(f"0x{st.last_nrc:02X}", f"SID 0x{st.last_sid:02X}: {uds.nrc_name(st.last_nrc)}")
        elif st.running:
            self.tile_nrc.set("–", "none")

    # ---- running work -------------------------------------------------------------
    def _session(self) -> uds.UdsSession:
        """The UDS session on the client routed 0x50-0x5F: it keeps the job's
        messages whichever client another page takes. BLE loop only."""
        if self._uds is None:
            cli = self.ctx.services[setu.SETUService.NAME].routed_client(uds.APP_FIRST, uds.APP_LAST)
            self._uds = uds.UdsSession(cli, log=lambda t: self.ctx.log(f"ecu: {t}"))
            self._uds.seq = self._seq
        return self._uds

    def _launch(self, kind: str, coro, on_done, on_error=None):
        self._runs += 1
        run_id = self._runs
        self._running[kind] = run_id

        def finish(handler, *args):
            if self._running.get(kind) == run_id:
                del self._running[kind]
                self._futures.pop(kind, None)
            if self._uds is not None:
                self._seq = self._uds.seq
            if handler:
                handler(*args)
            self._update()
        fut = self.ctx.run(coro, on_done=lambda r: finish(on_done, r),
                           on_error=lambda e: finish(on_error or self._failed, e),
                           on_cancel=lambda: finish(self._cancelled if kind == "op" else self._stopped))
        if self._running.get(kind) == run_id:
            self._futures[kind] = fut
        self._update()

    def _failed(self, exc):
        self.ctx.log(f"ecu: {exc}", "error")

    def _cancelled(self):
        self.ctx.log("ecu: cancelled", "warn")

    def _stopped(self):
        self.ctx.log("ecu: stopped following the flash job; it goes on on the device", "warn")

    def _ready(self, need_target=True) -> bool:
        return self._available and not self.busy and (self.applied is not None or not need_target)

    # ---- commands ------------------------------------------------------------------
    def apply_target(self):
        if not self._ready(need_target=False):
            return
        try:
            target = self.target_from_form()
        except ValueError as e:
            self.ctx.log(f"ecu: {e}", "warn")
            return
        self.applied = None

        async def work():
            await self._session().target(target)
            return target

        def done(t):
            self.applied = t
            self.ctx.log(f"ecu: target set: {target_summary(t)}")
        self._launch("op", work(), done)

    def send_request(self):
        if not self._ready():
            return
        functional = bool(self.v["functional"].get())
        try:
            req = parse_request(self.v["request"].get(), functional)
        except ValueError as e:
            self.ctx.log(f"ecu: {e}", "warn")
            return
        self._respond(f"→ {'func ' if functional else ''}{req.hex(' ')}")

        async def work():
            return await self._session().diag(req, functional)

        def done(res):
            st, rsp = res
            self._respond(f"← {uds.status_name(st)}  {uds.describe_response(rsp)}")

        def failed(e):
            self._respond(f"← {e}")
            self._failed(e)
        self._launch("op", work(), done, failed)

    def quick(self, hex_: str):
        set_var(self.v["request"], hex_)
        set_var(self.v["functional"], False)
        self.send_request()

    def unlock(self):
        if not self._ready():
            return
        try:
            level = parse_level(self.v["unlock_level"].get())
            algo = parse_algo(self.v["unlock_algo"].get())
        except ValueError as e:
            self.ctx.log(f"ecu: {e}", "warn")
            return
        self._respond(f"→ unlock level 0x{level:02X} ({algo_text(algo)})")

        async def work():
            await self._session().unlock(level, algo)

        def done(_):
            self._respond(f"← level 0x{level:02X} unlocked")
            self.ctx.log(f"ecu: security level 0x{level:02X} unlocked")

        def failed(e):
            nrc = getattr(e, "nrc", None)
            self._respond(f"← {e}" + (f" {uds.nrc_name(nrc)}" if nrc else ""))
            self._failed(e)
        self._launch("op", work(), done, failed)

    def refresh_files(self):
        """List the stored uploads (LS, entries under /FLASH_DISK:/FW)."""
        if not self._ready(need_target=False):
            return

        async def work():
            s = fsp.FileSystemSession(self.ctx.services[setu.SETUService.NAME].new_client(),
                                      log=lambda t: self.ctx.log(f"ecu: {t}"))
            return await s.ls()

        def done(entries):
            names = sorted(e.path[len(FILE_DIR):] for e in entries
                           if not e.is_dir and e.path.startswith(FILE_DIR) and "/" not in e.path[len(FILE_DIR):])
            self._show_files(names)
            self.ctx.log(f"ecu: {len(names)} stored upload(s)" + (f": {', '.join(names)}" if names else
                                                                   " (store one with Hex Upload, Store as)"))
        self._launch("op", work(), done)

    def flash(self, confirm=True):
        if not self._ready():
            return
        try:
            name = check_file_name(self.v["file"].get())
            params = self.params_from_form()
        except ValueError as e:
            self.ctx.log(f"ecu: {e}", "warn")
            return
        if confirm and not messagebox.askyesno(
                "Flash", f"Flash {name} into the ECU ({target_summary(self.applied)})?\n\n"
                         f"Steps: {', '.join(params.steps()) or 'download only'}"):
            return
        self._set_rows(params)
        self._job_name, self._t0, self.rate = name, None, None
        self.tile_rate.set("–", "kbit/s")
        self.tile_nrc.set("–", "none")
        call = self.ctx.bus.call

        async def work():
            s = self._session()
            await s.start_flash(name, params)
            call(self.ctx.log, f"ecu: flash {name} accepted, steps: {', '.join(params.steps())}")
            return await s.follow_flash(name, lambda st: call(self.show_status, st))
        self._launch("job", work(), self._flashed, self._flash_failed)

    def _follow(self):
        """Follow a job found running on the device."""
        call = self.ctx.bus.call
        try:
            self._set_rows(self.params_from_form())
        except ValueError:
            pass
        self._t0, self.rate = None, None

        async def work():
            return await self._session().follow_flash(self._job_name, lambda st: call(self.show_status, st))
        self._launch("job", work(), self._flashed, self._flash_failed)

    def _flashed(self, st: uds.Status):
        self.show_status(st)
        self.ctx.log(f"ecu: flashed {self._job_name or 'the file'}: {st.total:,} bytes"
                     + (f", {self.rate:.1f} kbit/s" if self.rate else ""))

    def _flash_failed(self, exc):
        if self.last_status is not None and self.last_status.state == 4:
            self.ctx.log(f"ecu: {exc}", "warn")
        else:
            self._failed(exc)

    def abort(self):
        if "job" not in self._running or not self._available:
            return

        async def work():
            await self._session().request_abort()
        self.ctx.log("ecu: abort requested")
        self.ctx.run(work(), on_error=self._failed)

    def get_status(self):
        if not self._ready(need_target=False):
            return

        async def work():
            return await self._session().status()

        def done(st):
            self.show_status(st)
            self.ctx.log(f"ecu: job {st.describe()}")
        self._launch("op", work(), done)

    def _check_job(self):
        """On connecting: is a flash job running on the device? Then follow it."""
        async def work():
            return await self._session().status()

        def done(st):
            if st.state != 0:
                self.show_status(st)
            if st.running:
                self.ctx.log(f"ecu: a flash job runs on the device ({st.describe()}); following it")
                self._follow()

        def failed(e):
            self.ctx.log(f"ecu: no UDS on this device? ({e})", "warn")
        self._launch("op", work(), done, failed)

    # ---- Feature -------------------------------------------------------------------
    @property
    def busy(self) -> bool:
        return bool(self._running)

    def cancel(self):
        for fut in list(self._futures.values()):
            fut.cancel()

    def on_connected(self, info):
        # The device keeps its target until a reset, but which one is not known
        self.applied = None
        self._uds = None
        self._update()
        if self._available:
            self._check_job()

    def on_disconnected(self, reason):
        self.cancel()
        self.applied = None
        self._uds = None
        self._update()
