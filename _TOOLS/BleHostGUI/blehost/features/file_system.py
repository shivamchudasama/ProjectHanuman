"""Files: the device's file system on its external flash (_DOC/FileSysManager/PROTOCOL.md).

The FileSystemPoC's UART test harness, through the GUI: its command lines
(mkdir, cd, openr, openw, write, read, ls, delfile, deldir, close, abort, help)
run as typed, and each has a button. A listing fills the table; read data is
shown as a hex dump. Read (and `read [N]`) reads the open file to its end, or N
bytes, in as many READs as that takes; Stop ends it after the READ in flight.
Download… reads a whole file to the PC, Write file… writes a PC file into the
file open for writing.
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ..protocols import setu
from ..protocols import filesystem as fsp
from ..ui import theme as th
from ..ui.widgets import Disclosure, Pill, StatTile, Tooltip, card, set_icon, set_var
from .base import Feature

ROOT = "/FLASH_DISK:"
SHOW_MAX = 64 * 1024                      # read data shown as a hex dump (4096 lines)

# Path buttons: (attribute, text, op, icon)
PATH_BUTTONS = (
    ("mkdir_btn", "Make dir", "MKDIR", "add"),
    ("cd_btn", "Change dir", "CD", "folder"),
    ("openr_btn", "Open read", "OPENR", None),
    ("openw_btn", "Open write", "OPENW", None),
    ("delfile_btn", "Delete file", "DELFILE", "delete"),
    ("deldir_btn", "Delete dir", "DELDIR", "delete"),
)
# Every button that sends something
BUTTONS = ("run_btn",) + tuple(b[0] for b in PATH_BUTTONS) + (
    "write_btn", "writefile_btn", "read_btn", "ls_btn", "close_btn", "abort_btn", "download_btn")


def entry_row(e: fsp.Entry) -> tuple:
    """Listing table values: (path, type, size)."""
    return (e.path, "dir" if e.is_dir else "file", "" if e.is_dir else f"{e.size:,}")


class FileSystemFeature(Feature):
    title = "Files"
    icon = "files"

    def __init__(self, ctx):
        super().__init__(ctx)
        self._future = None
        self._runs = 0                    # works launched
        self._running = None              # the one in progress (its number)
        self._seq = 0
        self.cwd = None                   # current directory, once a reply has told it
        self.open_file = None             # (path, "read" | "write") while one is open
        self.entries = []
        self.read_data = b""
        self._reading = False             # a Read (several READs) in progress
        self._stop_read = False           # Stop asked for it to end

    # ---- UI ----------------------------------------------------------------
    def build(self, parent):
        theme = th.of(self.ctx)
        sp = theme.sp
        f = ttk.Frame(parent)

        cmd, head = card(f, "Command line")
        cmd.pack(fill="x")
        self.state_pill = Pill(head, theme, "Not connected", "idle")
        self.state_pill.grid(row=0, column=2, sticky="e")
        row = ttk.Frame(cmd)
        row.pack(fill="x")
        self.cmd_var = tk.StringVar()
        self.cmd_entry = ttk.Entry(row, textvariable=self.cmd_var, font=theme.fonts["mono"])
        self.cmd_entry.pack(side="left", fill="x", expand=True)
        self.cmd_entry.bind("<Return>", lambda e: self.run_line())
        self.run_btn = ttk.Button(row, text="Run", style="Accent.TButton", command=self.run_line)
        self.run_btn.pack(side="left", padx=(sp("s"), 0))
        set_icon(self.run_btn, theme, "play", accent=True)
        ttk.Label(cmd, text="The UART test harness's commands: " + ", ".join(fsp.HARNESS) + ", help",
                  style="Caption.TLabel").pack(anchor="w", pady=(sp("s"), 0))

        tiles = ttk.Frame(f)
        tiles.pack(fill="x", pady=sp("m"))
        self.tile_dir = StatTile(tiles, "Directory", "–", "not known yet")
        self.tile_file = StatTile(tiles, "Open file", "–", "none")
        for i, t in enumerate((self.tile_dir, self.tile_file)):
            t.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else sp("m"), 0))
            tiles.columnconfigure(i, weight=1, uniform="tile")

        ops, _ = card(f, "Commands")
        ops.pack(fill="x")
        prow = ttk.Frame(ops)
        prow.pack(fill="x")
        ttk.Label(prow, text="Path").pack(side="left")
        self.path_var = tk.StringVar()
        ttk.Entry(prow, textvariable=self.path_var).pack(side="left", fill="x", expand=True,
                                                        padx=(sp("s"), 0))
        brow = ttk.Frame(ops)
        brow.pack(fill="x", pady=(sp("s"), 0))
        for attr, text, op, icon in PATH_BUTTONS:
            b = ttk.Button(brow, text=text, command=lambda o=op: self.path_command(o))
            b.pack(side="left", padx=(0, sp("s")))
            if icon:
                set_icon(b, theme, icon)
            setattr(self, attr, b)

        wrow = ttk.Frame(ops)
        wrow.pack(fill="x", pady=(sp("m"), 0))
        ttk.Label(wrow, text="Data").pack(side="left")
        self.payload_var = tk.StringVar()
        ttk.Entry(wrow, textvariable=self.payload_var, font=theme.fonts["mono"]).pack(
            side="left", fill="x", expand=True, padx=sp("s"))
        self.hex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(wrow, text="Hex", variable=self.hex_var).pack(side="left")
        self.write_btn = ttk.Button(wrow, text="Write", command=self.write)
        self.write_btn.pack(side="left", padx=(sp("s"), 0))
        self.writefile_btn = ttk.Button(wrow, text="Write file…", command=self.write_file)
        self.writefile_btn.pack(side="left", padx=(sp("s"), 0))
        set_icon(self.writefile_btn, theme, "upload")

        rrow = ttk.Frame(ops)
        rrow.pack(fill="x", pady=(sp("m"), 0))
        ttk.Label(rrow, text="Bytes").pack(side="left")
        self.count_var = tk.StringVar()
        count_entry = ttk.Entry(rrow, textvariable=self.count_var, width=8)
        count_entry.pack(side="left", padx=sp("s"))
        Tooltip(count_entry, "Empty: to the end of the file; a number: that many bytes", theme)
        self.read_btn = ttk.Button(rrow, text="Read", command=self.read)
        self.read_btn.pack(side="left")
        self.stop_btn = ttk.Button(rrow, text="Stop", command=self.stop_read)
        self.stop_btn.pack(side="left", padx=(sp("s"), 0))
        set_icon(self.stop_btn, theme, "stop")
        self.ls_btn = ttk.Button(rrow, text="List", command=lambda: self.start("LS"))
        self.ls_btn.pack(side="left", padx=(sp("m"), 0))
        set_icon(self.ls_btn, theme, "refresh")
        self.close_btn = ttk.Button(rrow, text="Close", command=lambda: self.start("CLOSE"))
        self.close_btn.pack(side="left", padx=(sp("s"), 0))
        self.abort_btn = ttk.Button(rrow, text="Abort", style="Danger.TButton",
                                    command=lambda: self.start("ABORT"))
        self.abort_btn.pack(side="left", padx=(sp("s"), 0))
        set_icon(self.abort_btn, theme, "stop")
        self.download_btn = ttk.Button(rrow, text="Download…", command=self.download)
        self.download_btn.pack(side="right")
        set_icon(self.download_btn, theme, "download")

        self.list_section = Disclosure(f, "Listing", open_=True, theme=theme, fill="both")
        self.list_section.pack(fill="both", expand=True, pady=(sp("m"), 0))
        body = ttk.Frame(self.list_section.body)
        body.pack(fill="both", expand=True)
        cols = ("path", "type", "size")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", height=6)
        for c, text, w in (("path", "Path", 360), ("type", "Type", 60), ("size", "Size (bytes)", 110)):
            self.tree.heading(c, text=text, anchor="w")
            self.tree.column(c, width=theme.px(w), anchor="w", stretch=(c == "path"))
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._pick_entry())
        sb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        self.read_section = Disclosure(f, "Read data", theme=theme, fill="both")
        self.read_section.pack(fill="both", expand=True, pady=(sp("m"), 0))
        self.read_text = tk.Text(self.read_section.body, height=8, wrap="none",
                                 font=theme.fonts["mono"], state="disabled")
        self.read_text.pack(fill="both", expand=True)
        theme.on_change(lambda p: th.style_text(self.read_text, p))

        self._update()
        return f

    # ---- state shown ---------------------------------------------------------
    @property
    def _available(self) -> bool:
        svc = self.ctx.services.get(setu.SETUService.NAME)
        return bool(self.ctx.link.connected and svc is not None and svc.available)

    def _update(self):
        ready = self._available and not self.busy
        for name in BUTTONS:
            btn = getattr(self, name, None)
            if btn is not None:
                btn.state(["!disabled"] if ready else ["disabled"])
        stop_btn = getattr(self, "stop_btn", None)
        if stop_btn is not None:
            stop_btn.state(["!disabled"] if self._reading and not self._stop_read else ["disabled"])
        if not self.ctx.link.connected:
            self.state_pill.set("Not connected", "idle")
        elif not self._available:
            self.state_pill.set("No SETU service", "warn")
        elif self.busy:
            self.state_pill.set("Busy", "info")
        else:
            self.state_pill.set("Ready", "ok")
        self.tile_dir.set(self.cwd or "–", "current directory" if self.cwd else "not known yet")
        if self.open_file:
            self.tile_file.set(os.path.basename(self.open_file[0]) or self.open_file[0],
                               f"open for {self.open_file[1]}")
        else:
            self.tile_file.set("–", "none")

    def _show_entries(self):
        self.tree.delete(*self.tree.get_children())
        for i, e in enumerate(self.entries):
            self.tree.insert("", "end", iid=str(i), values=entry_row(e))
        self.list_section.set_title(f"Listing ({len(self.entries)})")

    def _show_read(self, data: bytes, note: str):
        """Read data as a hex dump (its first SHOW_MAX bytes), titled "Read data (note)"."""
        self.read_data = data
        self.read_text.configure(state="normal")
        self.read_text.delete("1.0", "end")
        self.read_text.insert("1.0", "\n".join(fsp.hexdump(data[:SHOW_MAX])) if data else "(end of file)")
        self.read_text.configure(state="disabled")
        if len(data) > SHOW_MAX:
            note += f", first {SHOW_MAX // 1024} KiB shown"
        self.read_section.set_title(f"Read data ({note})")
        self.read_section.set_open(True)

    def _pick_entry(self):
        """A listed entry fills the path field."""
        sel = self.tree.selection()
        if sel and sel[0].isdigit() and int(sel[0]) < len(self.entries):
            set_var(self.path_var, self.entries[int(sel[0])].path)

    # ---- what a reply means ---------------------------------------------------
    def apply_reply(self, r: fsp.Reply):
        """Follow the device's state from a REPLY, and log it as the harness did."""
        level = "info" if r.ok else "warn"
        for line in fsp.describe(r):
            self.ctx.log(f"files: {line}", level)
        if r.ok:
            if r.op in (fsp.OPS["MKDIR"], fsp.OPS["CD"]):
                self.cwd = r.text
            elif r.op in (fsp.OPS["OPENR"], fsp.OPS["OPENW"]):
                self.open_file = (r.text, "read" if r.op == fsp.OPS["OPENR"] else "write")
            elif r.op == fsp.OPS["CLOSE"]:
                self.open_file = None
            elif r.op == fsp.OPS["ABORT"]:
                # Without an open file the device also resets its current directory
                if self.open_file is None:
                    self.cwd = ROOT
                self.open_file = None
            elif r.op == fsp.OPS["LS"]:
                self.entries = list(r.entries)
                self._show_entries()
            elif r.op == fsp.OPS["READ"]:
                self._show_read(r.data, f"{len(r.data)} bytes" + (", end of file" if r.eof else ""))
        else:
            if r.op == fsp.OPS["READ"] and r.data:
                # read_to(): what came before the failed READ
                self._show_read(r.data, f"{len(r.data)} bytes, then {r.status_name}")
            if r.closes_file:
                self.open_file = None

    # ---- commands ------------------------------------------------------------
    def _session(self) -> fsp.FileSystemSession:
        """A session on a fresh SETU client (another page may have taken
        the shared one); the sequence number carries on. BLE loop only."""
        setu_cli = self.ctx.services[setu.SETUService.NAME].new_client()
        s = fsp.FileSystemSession(setu_cli, log=lambda t: self.ctx.log(f"files: {t}"))
        s.seq = self._seq
        return s

    def _launch(self, coro, on_done):
        self._runs += 1
        run_id = self._runs
        self._running = run_id
        fut = self.ctx.run(coro, on_done=lambda res: self._done(on_done, res),
                           on_error=self._failed, on_cancel=self._cancelled)
        # Kept only while the work runs: it may already have finished
        if self._running == run_id:
            self._future = fut
        self._update()

    def start(self, op: str, arg: bytes = b""):
        """Send one command; the REPLY updates the page."""
        if self.busy or not self._available:
            return

        async def work():
            s = self._session()
            try:
                return await s.command(op, arg)
            finally:
                self._seq = s.seq
        self._launch(work(), self.apply_reply)

    def run_line(self):
        """Run the command line as the UART harness would."""
        line = self.cmd_var.get()
        if not line.strip():
            return
        try:
            op, arg = fsp.parse_line(line)
        except ValueError as e:
            self.ctx.log(f"files: {e}", "warn")
            return
        if op == "help":
            for h in fsp.HELP:
                self.ctx.log(f"files: {h}")
            return
        if op == "READ":
            self._read(arg)
            return
        self.start(op, arg)

    def path_command(self, op: str):
        path = self.path_var.get().strip()
        if not path:
            self.ctx.log("files: give a path", "warn")
            return
        arg = path.encode("utf-8")
        if len(arg) > fsp.ARG_MAX:
            self.ctx.log(f"files: path longer than {fsp.ARG_MAX} bytes", "warn")
            return
        self.start(op, arg)

    def _payload(self) -> bytes:
        text = self.payload_var.get()
        if self.hex_var.get():
            try:
                return bytes.fromhex(text)
            except ValueError:
                raise ValueError("data is not hex") from None
        return text.encode("utf-8")

    def write(self):
        """Write the data field to the file open for writing (any length)."""
        try:
            data = self._payload()
        except ValueError as e:
            self.ctx.log(f"files: {e}", "warn")
            return
        if not data:
            self.ctx.log("files: nothing to write", "warn")
            return
        self._write(data, "data")

    def write_file(self):
        """Write a PC file into the file open for writing."""
        path = filedialog.askopenfilename(title="File to write to the device")
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            messagebox.showerror("Write file", str(e))
            return
        if not data:
            self.ctx.log(f"files: {os.path.basename(path)} is empty", "warn")
            return
        self._write(data, os.path.basename(path))

    def _write(self, data: bytes, what: str):
        if self.busy or not self._available:
            return

        async def work():
            s = self._session()
            r = None
            try:
                for i in range(0, len(data), fsp.ARG_MAX):
                    r = await s.command("WRITE", data[i:i + fsp.ARG_MAX])
                    if not r.ok:
                        break
            finally:
                self._seq = s.seq
            return r

        def done(r):
            self.apply_reply(r)
            if r.ok:
                self.ctx.log(f"files: {what}: {len(data)} bytes written")
        self._launch(work(), done)

    def read(self):
        """Read the open file: the Bytes field's count, or to its end when empty."""
        text = self.count_var.get().strip()
        try:
            n = int(text, 10) if text else None
        except ValueError:
            n = 0
        if n is not None and n <= 0:
            self.ctx.log("files: bytes must be a positive number, or empty for the whole file", "warn")
            return
        self._read(n)

    def _read(self, count):
        """READs until `count` bytes (None: the end of the file) or Stop."""
        if self.busy or not self._available:
            return
        call = self.ctx.bus.call

        async def work():
            s = self._session()
            try:
                return await s.read_to(count, progress=lambda n: call(self._read_progress, n),
                                       stop=lambda: self._stop_read)
            finally:
                self._seq = s.seq

        def done(r):
            stopped = self._stop_read and r.ok and not r.eof and (count is None or len(r.data) < count)
            self._end_read()
            self.apply_reply(r)
            if stopped:
                self.ctx.log(f"files: read stopped after {len(r.data)} bytes", "warn")
        self._reading, self._stop_read = True, False
        self._launch(work(), done)

    def _read_progress(self, n: int):
        if self._reading:
            self.read_section.set_title(f"Read data (reading… {n:,} bytes)")

    def stop_read(self):
        """End the Read in progress after the READ in flight."""
        if self._reading:
            self._stop_read = True
            self._update()

    def _end_read(self):
        self._reading = self._stop_read = False

    def download(self):
        """Read the file in the path field to a PC file."""
        remote = self.path_var.get().strip()
        if not remote:
            self.ctx.log("files: give the path of the file to download", "warn")
            return
        if self.busy or not self._available:
            return
        local = filedialog.asksaveasfilename(title="Save the device file as",
                                             initialfile=os.path.basename(remote))
        if not local:
            return

        async def work():
            s = self._session()
            try:
                return await s.get(remote)
            finally:
                self._seq = s.seq

        def done(data):
            with open(local, "wb") as fh:
                fh.write(data)
            self.open_file = None
            self._show_read(data[:4096], f"{len(data)} bytes downloaded, first 4 KiB")
            self.ctx.log(f"files: {remote}: {len(data)} bytes saved to {local}")
        self._launch(work(), done)

    # ---- completion ----------------------------------------------------------
    def _done(self, handler, result):
        self._future = None
        self._running = None
        try:
            handler(result)
        except OSError as e:
            messagebox.showerror("Files", str(e))
        self._update()

    def _failed(self, exc):
        self._future = None
        self._running = None
        self._end_read()
        if isinstance(exc, fsp.FsError) and exc.status is not None:
            if exc.op in (fsp.OPS["WRITE"], fsp.OPS["READ"], fsp.OPS["CLOSE"]) and \
                    exc.status not in (fsp.ST_BAD_ARG, fsp.ST_BAD_STATE, fsp.ST_BUSY):
                self.open_file = None
        self.ctx.log(f"files: {exc}", "error")
        self._update()

    def _cancelled(self):
        self._future = None
        self._running = None
        self._end_read()
        self.ctx.log("files: cancelled", "warn")
        self._update()

    # ---- Feature -------------------------------------------------------------
    @property
    def busy(self) -> bool:
        return self._running is not None

    def cancel(self):
        if self._future is not None:
            self._future.cancel()

    def on_connected(self, info):
        # The device keeps its state between connections; it is learnt again
        self.cwd = None
        self.open_file = None
        self._update()

    def on_disconnected(self, reason):
        self.cancel()
        self._update()
