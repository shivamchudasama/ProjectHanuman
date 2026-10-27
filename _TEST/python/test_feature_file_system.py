# SPDX-License-Identifier: MIT
"""The Files page (_TOOLS/BleHostGUI/blehost/features/file_system.py): the UART
test harness's command lines and buttons, run against FakeFsDevice (conftest.py)
through stand-in Tk variables and widgets and a fake AppContext whose run()
executes the coroutine at once. One test builds the real page on conftest's
shared Tk root (skipped without a display)."""

import asyncio
import struct

import pytest

from blehost.features import file_system as ffs
from blehost.protocols import setu as setu_proto
from blehost.protocols import filesystem as fsp
from conftest import FakeSETU


# ---- stand-ins for Tk ------------------------------------------------------------------
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

    def state(self, spec):
        self.enabled = spec == ["!disabled"]


class Shown:
    """Pill, StatTile, Disclosure: remembers what it was told to show."""

    def __init__(self):
        self.value, self.note, self.title, self.open = None, None, None, False

    def set(self, value, note=None):
        self.value, self.note = value, note

    def set_title(self, title):
        self.title = title

    def set_open(self, flag):
        self.open = flag


class Tree:
    def __init__(self):
        self.rows, self.sel = {}, ()

    def delete(self, *iids):
        for i in iids:
            del self.rows[i]

    def get_children(self):
        return tuple(self.rows)

    def insert(self, parent, where, iid, values):
        self.rows[iid] = values

    def selection(self):
        return self.sel


class Progress:
    """ttk.Progressbar: its mode, maximum and value, the steps taken without a size,
    and the timers armed on it (never run by themselves: a test runs them with fire())."""

    def __init__(self):
        self.mode, self.maximum, self.value, self.steps = None, None, None, 0
        self.timers, self.cancelled, self.armed = {}, [], 0

    def configure(self, **kw):
        self.mode = kw.get("mode", self.mode)
        self.maximum = kw.get("maximum", self.maximum)
        self.value = kw.get("value", self.value)

    def step(self, amount):
        self.steps += 1

    def after(self, ms, fn):
        tid = f"t{self.armed}"
        self.armed += 1
        self.timers[tid] = fn
        return tid

    def after_cancel(self, tid):
        self.timers.pop(tid, None)
        self.cancelled.append(tid)

    def fire(self):
        for tid in list(self.timers):
            self.timers.pop(tid)()


class Text:
    def __init__(self):
        self.text = ""

    def configure(self, **kw):
        pass

    def delete(self, a, b):
        self.text = ""

    def insert(self, at, text):
        self.text = text


# ---- the context -------------------------------------------------------------------------
class Future:
    def __init__(self, on_cancel=None):
        self.on_cancel = on_cancel

    def cancel(self):
        if self.on_cancel:
            self.on_cancel()


class Ctx:
    def __init__(self, device):
        self.link = type("Link", (), {"connected": True})()
        self.device = device
        self.clients = []
        svc = type("Svc", (), {"available": True})()
        svc.new_client = self._new_client
        self.svc = svc
        self.services = {setu_proto.SETUService.NAME: svc}
        self.logs = []
        self.hold = False
        self.bus = type("Bus", (), {"call": staticmethod(lambda fn, *a: fn(*a))})()

    def _new_client(self):
        setu_cli = FakeSETU(self.device)
        self.clients.append(setu_cli)
        return setu_cli

    def log(self, text, level="info"):
        self.logs.append((level, text))

    def run(self, coro, on_done=None, on_error=None, on_cancel=None):
        if self.hold:
            coro.close()
            return Future(on_cancel)
        try:
            result = asyncio.run(coro)
        except Exception as e:                  # noqa: BLE001 - as AppContext.run
            on_error(e)
        else:
            on_done(result)
        return Future()


@pytest.fixture
def page(fsdev, monkeypatch):
    monkeypatch.setattr(fsp, "TIMEOUT", 0.2)
    f = ffs.FileSystemFeature(Ctx(fsdev))
    for name in ("cmd_var", "path_var", "payload_var", "count_var", "progress_var"):
        setattr(f, name, Var())
    f.hex_var = Var(False)
    for name in ffs.BUTTONS + ("stop_btn",):
        setattr(f, name, Button())
    f.state_pill, f.tile_dir, f.tile_file, f.tile_xfer = Shown(), Shown(), Shown(), Shown()
    f.progress = Progress()
    f.list_section, f.read_section = Shown(), Shown()
    f.tree, f.read_text = Tree(), Text()
    f._update()
    return f


def logged(f) -> str:
    return "\n".join(t for _, t in f.ctx.logs)


def line(f, text):
    f.cmd_var.set(text)
    f.run_line()


# ---- the harness's command lines -----------------------------------------------------------
def test_help_and_bad_lines_stay_local(page, fsdev):
    line(page, "help")
    line(page, "format")
    line(page, "mkdir")
    line(page, "   ")
    assert "files:   openw <path>" in logged(page)
    assert "Unknown command: format" in logged(page) and "mkdir requires a path" in logged(page)
    assert fsdev.commands == [], "nothing reaches the device"


def test_write_and_read_back_by_command_line(page, fsdev):
    line(page, "mkdir FW")
    assert page.cwd == "/FLASH_DISK:/FW" and page.tile_dir.value == "/FLASH_DISK:/FW"
    line(page, "openw a.txt")
    assert page.open_file == ("/FLASH_DISK:/FW/a.txt", "write")
    assert (page.tile_file.value, page.tile_file.note) == ("a.txt", "open for write")
    line(page, "write hello")
    line(page, "close")
    assert page.open_file is None and page.tile_file.value == "–"
    line(page, "openr a.txt")
    line(page, "read 4")
    assert page.read_data == b"hell" and "68 65 6c 6c" in page.read_text.text and page.read_section.open
    assert page.read_section.title == "Read data (4 bytes)"
    line(page, "read")
    assert page.read_data == b"o" and page.read_section.title == "Read data (1 bytes, end of file)"
    line(page, "read")
    assert page.read_text.text == "(end of file)"
    assert page.open_file == ("/FLASH_DISK:/FW/a.txt", "read"), "a read leaves the file open"
    text = logged(page)
    assert "Directory active: /FLASH_DISK:/FW" in text and "File closed, 5 bytes written" in text
    # read 4, then "o" and the end (two READs), then the end again
    assert [c[0] for c in fsdev.commands] == list(range(1, 10)), "sequence numbers carry on"


def test_listing_fills_the_table_and_a_row_fills_the_path(page, fsdev):
    fsdev.dirs.add("/FLASH_DISK:/FW")
    fsdev.files["/FLASH_DISK:/FW/FW1"] = bytearray(6568)
    line(page, "ls")
    assert list(page.tree.rows.values()) == [("/FLASH_DISK:/FW", "dir", ""),
                                             ("/FLASH_DISK:/FW/FW1", "file", "6,568")]
    assert page.list_section.title == "Listing (2)"
    page.tree.sel = ("1",)
    page._pick_entry()
    assert page.path_var.get() == "/FLASH_DISK:/FW/FW1"
    page.tree.sel = ()
    page._pick_entry()


def test_errors_are_logged_and_failures_close_the_file(page, fsdev):
    line(page, "cd NONE")
    assert ("warn", "files: CD: NOT_FOUND") in page.ctx.logs
    line(page, "openw a")
    fsdev.fail["WRITE"] = 9
    line(page, "write x")
    assert page.open_file is None, "a failed write closed the file on the device"
    line(page, "openw b")
    fsdev.fail["WRITE"] = 6
    line(page, "write x")
    assert page.open_file is not None, "a refusal leaves it open"


def test_abort_resets_the_directory_only_without_an_open_file(page):
    line(page, "mkdir FW")
    line(page, "openw a")
    line(page, "abort")
    assert page.cwd == "/FLASH_DISK:/FW" and page.open_file is None
    line(page, "abort")
    assert page.cwd == ffs.ROOT


# ---- buttons ---------------------------------------------------------------------------------
def test_path_buttons(page, fsdev):
    page.path_command("MKDIR")
    assert "give a path" in logged(page) and fsdev.commands == []
    page.path_var.set("x" * 241)
    page.path_command("MKDIR")
    assert "longer than 240" in logged(page)
    for op, path in (("MKDIR", "FW"), ("CD", "FW"), ("OPENW", "f"), ("CLOSE", None),
                     ("OPENR", "f"), ("CLOSE", None), ("DELFILE", "f"), ("DELDIR", "/FW")):
        if path is None:
            page.start(op)
        else:
            page.path_var.set(path)
            page.path_command(op)
    assert [c[1] for c in fsdev.commands] == [1, 2, 4, 10, 3, 10, 8, 9]
    assert "/FLASH_DISK:/FW" not in fsdev.dirs


def test_write_button_text_hex_and_long_data(page, fsdev):
    line(page, "openw w.bin")
    page.payload_var.set("abc")
    page.write()
    page.hex_var.set(True)
    page.payload_var.set("00 ff 10")
    page.write()
    page.payload_var.set("zz")
    page.write()
    assert "data is not hex" in logged(page)
    page.payload_var.set("")
    page.write()
    assert "nothing to write" in logged(page)
    page.payload_var.set("41" * 500)
    page.write()
    page.start("CLOSE")
    assert fsdev.files["/FLASH_DISK:/w.bin"] == b"abc\x00\xff\x10" + b"A" * 500
    assert [len(c[2]) for c in fsdev.commands if c[1] == 5][-3:] == [240, 240, 20]
    assert "data: 500 bytes written" in logged(page)


def test_write_stops_at_the_first_failure(page, fsdev):
    line(page, "openw w.bin")
    fsdev.fail["WRITE"] = 4
    page.payload_var.set("x" * 600)
    page.write()
    assert len([c for c in fsdev.commands if c[1] == 5]) == 1
    assert "WRITE: NO_SPACE" in logged(page) and page.open_file is None


def test_write_file(page, fsdev, tmp_path, monkeypatch):
    src = tmp_path / "app.bin"
    src.write_bytes(bytes(range(256)))
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    errors = []
    monkeypatch.setattr(ffs.messagebox, "showerror", lambda t, m: errors.append(m))
    line(page, "openw app.bin")
    for chosen in ("", str(empty), str(tmp_path / "missing"), str(src)):
        monkeypatch.setattr(ffs.filedialog, "askopenfilename", lambda **kw: chosen)
        page.write_file()
    page.start("CLOSE")
    assert fsdev.files["/FLASH_DISK:/app.bin"] == bytes(range(256))
    assert "empty.bin is empty" in logged(page) and len(errors) == 1


# ---- a write's progress and summary ------------------------------------------------------------
def writes(fsdev) -> list:
    return [c[2] for c in fsdev.commands if c[1] == fsp.OPS["WRITE"]]


@pytest.fixture
def clock(monkeypatch):
    """The page's time.perf_counter(): 0.5 s more at each WRITE the device takes."""
    now = [100.0]
    monkeypatch.setattr(ffs, "time", type("T", (), {"perf_counter": staticmethod(lambda: now[0])}))
    return now


def on_write(fsdev, fn):
    """Call fn(number of WRITEs so far) as each WRITE reaches the device."""
    real = fsdev.handle

    def handle(payload):
        if payload[1] == fsp.OPS["WRITE"]:
            fn(len(writes(fsdev)))
        return real(payload)
    fsdev.handle = handle


def test_write_shows_progress_and_ends_with_a_summary(page, fsdev, clock):
    line(page, "openw big.bin")
    seen = []

    def step(n):
        if n == 2:                                       # third WRITE: the timer shows the second
            page.progress.fire()
            seen.append((page.progress.value, page.progress.maximum, page.progress_var.get(),
                         page.tile_xfer.value, page.tile_xfer.note))
        clock[0] += 0.5
    on_write(fsdev, step)
    page.payload_var.set("y" * 1000)                     # 240, 240, 240, 240, 40
    page.write()
    # 480 B in 1.0 s (two WRITEs done, the third arriving): 3.8 kbit/s
    assert seen == [(480, 1000, "480/1,000 B  48 %, 3.8 kbit/s", "480 B", "48 % of 1,000 B")]
    # 1000 B in 2.5 s: 3.2 kbit/s
    assert page.progress.value == 1000 and not page.progress.timers, "the end shows it at once"
    assert page.progress_var.get() == "done: 1,000 B in 2.5 s, 3.2 kbit/s"
    assert (page.tile_xfer.value, page.tile_xfer.note) == ("3.2 kbit/s", "average, 1,000 B in 2.5 s")
    assert "files: data: 1000 bytes written in 2.5 s, 3.2 kbit/s" in logged(page)
    assert page._xfer is None and not page.busy and not page.stop_btn.enabled


def test_progress_redraws_at_most_once_per_timer(page, fsdev, clock):
    line(page, "openw w")
    on_write(fsdev, lambda n: None)
    page.payload_var.set("z" * 2400)                     # ten WRITEs
    page.write()
    assert len(page.progress.cancelled) == 1, "one timer armed, cancelled by the end"
    page._progress(5)
    assert not page.progress.timers, "nothing after the write"


def test_stop_ends_a_write(page, fsdev, clock):
    line(page, "openw w")
    on_write(fsdev, lambda n: page.stop() if n == 1 else None)   # during the second WRITE
    page.payload_var.set("s" * 1000)
    page.write()
    assert len(writes(fsdev)) == 2, "it ended after the WRITE in flight"
    assert page.progress_var.get() == "stopped after 480 of 1,000 B"
    assert (page.tile_xfer.value, page.tile_xfer.note) == ("480 B", "stopped, 48 %")
    assert ("warn", "files: data: write stopped after 480 of 1000 bytes") in page.ctx.logs
    assert page.open_file is not None and not page._stop and not page.stop_btn.enabled
    page.payload_var.set("s" * 520)
    page.write()
    page.start("CLOSE")
    assert len(fsdev.files["/FLASH_DISK:/w"]) == 1000, "the next write carries on"


def test_a_failed_write_shows_how_far_it_came(page, fsdev, clock):
    line(page, "openw w")
    on_write(fsdev, lambda n: fsdev.fail.__setitem__("WRITE", 4) if n == 2 else None)
    page.payload_var.set("f" * 1000)
    page.write()
    assert page.progress_var.get() == "failed: NO_SPACE after 480 B"
    assert (page.tile_xfer.value, page.tile_xfer.note) == ("480 B", "failed, NO_SPACE")
    assert "WRITE: NO_SPACE" in logged(page) and page.open_file is None
    assert "bytes written" not in logged(page)


def test_stop_button_follows_the_write(page):
    page.ctx.hold = True
    page.payload_var.set("x" * 500)
    page.write()
    assert page.busy and page._xfer == "write" and page.stop_btn.enabled and not page.write_btn.enabled
    assert page.progress.maximum == 500 and page.progress.value == 0
    assert page.progress_var.get() == "0/500 B" and page.tile_xfer.note == "writing data"
    page.stop()
    assert page._stop and not page.stop_btn.enabled, "asked once"
    page.on_disconnected("gone")
    assert not page.busy and page._xfer is None and not page._stop
    assert page.progress_var.get() == "cancelled" and page.tile_xfer.note == "cancelled"


def test_a_failure_ends_the_write(page):
    page._xfer, page._stop = "write", True
    page._sent = 240
    page._failed(RuntimeError("link"))
    assert page._xfer is None and not page._stop
    assert page.progress_var.get() == "failed" and page.tile_xfer.value == "240 B"
    page._failed(RuntimeError("again"))
    assert page.tile_xfer.note == "failed", "nothing to end: left as it was"


def test_kbit_s():
    assert ffs.kbit_s(1000, 2.0) == "4.0" and ffs.kbit_s(1, 0) == "8.0"


# ---- a Read's and a download's progress and summary ----------------------------------------
def on_read(fsdev, fn):
    """Call fn(number of READs so far) as each READ reaches the device."""
    real = fsdev.handle

    def handle(payload):
        if payload[1] == fsp.OPS["READ"]:
            fn(len(read_args(fsdev)))
        return real(payload)
    fsdev.handle = handle


def tick(clock, page, at=None, seen=None):
    """A READ step: 0.5 s more, and at READ `at` the timer shows the progress so far."""
    def step(n):
        if n == at:
            page.progress.fire()
            seen.append((page.progress.mode, page.progress.value, page.progress.maximum,
                         page.progress_var.get(), page.tile_xfer.value, page.tile_xfer.note))
        clock[0] += 0.5
    return step


def test_device_path():
    assert ffs.device_path("/FLASH_DISK:/a", None) == "/FLASH_DISK:/a"
    assert ffs.device_path("/FW/a", None) == "/FLASH_DISK:/FW/a"
    assert ffs.device_path("a", "/FLASH_DISK:/FW") == "/FLASH_DISK:/FW/a"
    assert ffs.device_path("a", ffs.ROOT) == "/FLASH_DISK:/a"
    assert ffs.device_path("a", None) is None, "the current directory is not known"


def test_read_a_count_shows_progress_and_a_summary(page, fsdev, clock):
    fsdev.files["/FLASH_DISK:/r"] = bytearray(1000)
    line(page, "openr r")
    seen = []
    on_read(fsdev, tick(clock, page, at=2, seen=seen))
    page.count_var.set("600")                            # 239, 239, 122
    page.read()
    # Two READs (478 B) in 1.0 s: 3.8 kbit/s
    assert seen == [("determinate", 478, 600, "478/600 B  79 %, 3.8 kbit/s", "478 B", "79 % of 600 B")]
    assert page.progress_var.get() == "done: 600 B in 1.5 s, 3.2 kbit/s"
    assert (page.progress.value, page.progress.maximum) == (600, 600)
    assert (page.tile_xfer.value, page.tile_xfer.note) == ("3.2 kbit/s", "average, 600 B in 1.5 s")
    assert "files: read: 600 bytes in 1.5 s, 3.2 kbit/s" in logged(page)


def test_read_to_the_end_takes_the_size_from_the_listing(page, fsdev, clock):
    fsdev.files["/FLASH_DISK:/r"] = bytearray(1000)
    line(page, "ls")
    line(page, "openr r")
    line(page, "read 100")
    on_read(fsdev, lambda n: None)
    page.read()
    assert page.progress.maximum == 900, "the listed size less what was read"
    assert page.read_data == bytes(900) and page.progress_var.get().startswith("done: 900 B in ")
    # Opened again: from the start
    line(page, "close")
    line(page, "openr r")
    page.read()
    assert page.progress.maximum == 1000


def test_read_without_a_size_runs_without_an_end(page, fsdev, clock):
    fsdev.files["/FLASH_DISK:/r"] = bytearray(1000)
    line(page, "openr r")
    seen = []
    on_read(fsdev, tick(clock, page, at=2, seen=seen))
    page.read()
    assert seen == [("indeterminate", 0, 100, "478 B, 3.8 kbit/s", "478 B", "reading the open file")]
    assert page.progress.steps == 2, "the timer's, and the last READ's at the end"
    assert page.progress.mode == "determinate" and page.progress.value == page.progress.maximum == 1000
    # Five READs with data and one that finds the end: 3.0 s
    assert page.progress_var.get() == "done: 1,000 B in 3.0 s, 2.7 kbit/s"


def test_a_stale_listing_falls_back_to_bytes_only(page, fsdev, clock):
    fsdev.files["/FLASH_DISK:/r"] = bytearray(300)
    line(page, "ls")
    fsdev.files["/FLASH_DISK:/r"] = bytearray(1000)      # grown since
    line(page, "openr r")
    seen = []
    on_read(fsdev, tick(clock, page, at=2, seen=seen))
    page.read()
    assert seen[0][:4] == ("indeterminate", 0, 100, "478 B, 3.8 kbit/s")
    assert page.progress_var.get() == "done: 1,000 B in 3.0 s, 2.7 kbit/s"


def test_a_stopped_or_failed_read_says_how_far_it_came(page, fsdev, clock):
    fsdev.files["/FLASH_DISK:/r"] = bytearray(1000)
    line(page, "openr r")
    on_read(fsdev, lambda n: page.stop() if n == 1 else None)
    page.read()
    assert page.progress_var.get() == "stopped after 478 B"
    assert (page.tile_xfer.value, page.tile_xfer.note) == ("478 B", "stopped")
    assert (page.progress.mode, page.progress.value) == ("determinate", 0), "no size: left empty"
    page.count_var.set("500")
    on_read(fsdev, lambda n: fsdev.fail.__setitem__("READ", 9) if n == 3 else None)
    page.read()
    assert page.progress_var.get() == "failed: IO after 239 B"
    assert (page.tile_xfer.value, page.tile_xfer.note) == ("239 B", "failed, IO")
    assert page.progress.value == 239, "with a size: where it got to"


def test_download_shows_progress_and_a_summary(page, fsdev, tmp_path, monkeypatch, clock):
    fsdev.files["/FLASH_DISK:/FW1"] = bytearray(b"f" * 1000)
    line(page, "ls")
    dst = tmp_path / "fw1.bin"
    monkeypatch.setattr(ffs.filedialog, "asksaveasfilename", lambda **kw: str(dst))
    seen = []
    on_read(fsdev, tick(clock, page, at=2, seen=seen))
    page.path_var.set("/FW1")
    page.download()
    assert seen == [("determinate", 478, 1000, "478/1,000 B  47 %, 3.8 kbit/s", "478 B", "47 % of 1,000 B")]
    # Five READs with data and one that finds the end: 3.0 s
    assert page.progress_var.get() == "done: 1,000 B in 3.0 s, 2.7 kbit/s"
    assert (page.tile_xfer.value, page.tile_xfer.note) == ("2.7 kbit/s", "average, 1,000 B in 3.0 s")
    assert f"files: /FW1: 1000 bytes saved to {dst} in 3.0 s, 2.7 kbit/s" in logged(page)
    assert dst.read_bytes() == b"f" * 1000


def test_download_without_a_size_and_relative(page, fsdev, tmp_path, monkeypatch, clock):
    fsdev.dirs.add("/FLASH_DISK:/FW")
    fsdev.files["/FLASH_DISK:/FW/a"] = bytearray(500)
    monkeypatch.setattr(ffs.filedialog, "asksaveasfilename", lambda **kw: str(tmp_path / "a"))
    page.path_var.set("a")
    page.ctx.hold = True
    page.download()
    assert page.progress.mode == "indeterminate" and page.tile_xfer.note == "downloading a"
    assert not page.stop_btn.enabled, "a download is not stopped"
    page.stop()
    assert not page._stop
    page.on_disconnected("gone")
    assert page.progress_var.get() == "cancelled"
    page.ctx.hold = False
    line(page, "cd FW")
    line(page, "ls")
    page.download()
    assert page.progress.maximum == 500 and (tmp_path / "a").read_bytes() == bytes(500)


def test_a_download_that_fails_or_is_not_saved(page, fsdev, tmp_path, monkeypatch, clock):
    page.path_var.set("/NONE")
    monkeypatch.setattr(ffs.filedialog, "asksaveasfilename", lambda **kw: str(tmp_path / "x"))
    page.download()
    assert page.progress_var.get() == "failed" and page.tile_xfer.note == "failed"
    fsdev.files["/FLASH_DISK:/f"] = bytearray(b"x" * 10)
    errors = []
    monkeypatch.setattr(ffs.messagebox, "showerror", lambda t, m: errors.append(m))
    monkeypatch.setattr(ffs.filedialog, "asksaveasfilename", lambda **kw: str(tmp_path / "no" / "dir"))
    page.path_var.set("/f")
    page.download()
    assert errors and page.progress_var.get() == "read 10 B, not saved"
    assert (page.tile_xfer.value, page.tile_xfer.note) == ("10 B", "not saved")
    assert "saved to" not in logged(page)


def read_args(fsdev) -> list:
    return [c[2] for c in fsdev.commands if c[1] == fsp.OPS["READ"]]


def test_read_button_counts(page, fsdev):
    data = bytes(range(256)) * 4
    fsdev.files["/FLASH_DISK:/r"] = bytearray(data)
    line(page, "openr r")
    for text in ("x", "-1", "0"):
        page.count_var.set(text)
        page.read()
    assert logged(page).count("bytes must be a positive number") == 3 and read_args(fsdev) == []
    page.count_var.set("10")
    page.read()
    assert page.read_data == data[:10] and read_args(fsdev) == [b"\x0a\x00"]
    page.count_var.set(" 300 ")
    page.read()
    assert page.read_data == data[10:310] and read_args(fsdev)[1:] == [b"\xef\x00", b"\x3d\x00"]
    # Empty: the rest of the file, as many READs as it takes, and the end
    page.count_var.set("")
    page.read()
    assert page.read_data == data[310:] and read_args(fsdev)[3:] == [b""] * 4
    assert page.read_section.title == "Read data (714 bytes, end of file)"
    assert not page.busy and not page.stop_btn.enabled


def test_read_shows_at_most_64_kib(page, fsdev):
    fsdev.files["/FLASH_DISK:/big"] = bytearray(ffs.SHOW_MAX + 16)
    line(page, "openr big")
    page.read()
    assert len(page.read_data) == ffs.SHOW_MAX + 16
    assert page.read_text.text.count("\n") == ffs.SHOW_MAX // 16 - 1
    assert page.read_section.title == "Read data (65552 bytes, end of file, first 64 KiB shown)"


def test_stop_ends_a_read(page, fsdev):
    fsdev.files["/FLASH_DISK:/r"] = bytearray(1000)
    line(page, "openr r")
    page.stop()                                    # nothing to stop
    assert not page._stop
    real = fsdev.handle

    def handle(payload):
        if payload[1] == fsp.OPS["READ"] and len(read_args(fsdev)) == 1:
            page.stop()                            # during the second READ
        return real(payload)
    fsdev.handle = handle
    page.read()
    assert len(read_args(fsdev)) == 2, "it ended after the READ in flight"
    assert len(page.read_data) == 478 and "read stopped after 478 bytes" in logged(page)
    assert page.open_file is not None and not page.stop_btn.enabled and not page._stop
    page.read()
    assert len(page.read_data) == 1000 - 478, "the next Read carries on"
    assert logged(page).count("read stopped") == 1


def test_a_failed_read_shows_what_came_before(page, fsdev):
    fsdev.files["/FLASH_DISK:/r"] = bytearray(b"r" * 600)
    line(page, "openr r")
    real = fsdev.handle

    def handle(payload):
        if payload[1] == fsp.OPS["READ"] and len(read_args(fsdev)) == 1:
            fsdev.fail["READ"] = 9
        return real(payload)
    fsdev.handle = handle
    page.read()
    assert page.read_data == b"r" * 239 and page.read_section.title == "Read data (239 bytes, then IO)"
    assert ("warn", "files: READ: IO") in page.ctx.logs and page.open_file is None


def test_stop_button_follows_the_read(page):
    assert not page.stop_btn.enabled
    page.ctx.hold = True
    page.read()
    assert page.busy and page.stop_btn.enabled and not page.read_btn.enabled
    page.stop()
    assert not page.stop_btn.enabled, "asked once"
    page.on_disconnected("gone")
    assert not page.busy and page._xfer is None and not page._stop and not page.stop_btn.enabled
    page.ctx.hold = False
    line(page, "ls")
    assert not page.stop_btn.enabled, "only a Read or a write can be stopped"


def test_read_progress_only_while_reading(page):
    page._progress(1234)
    assert page.read_section.title is None
    page._xfer = "read"
    page._progress(1234)
    assert page.read_section.title == "Read data (reading… 1,234 bytes)"


def test_a_cancelled_or_failed_read_ends_it(page):
    page._xfer = "read"
    page._cancelled()
    assert page._xfer is None
    page._xfer, page._stop = "read", True
    page._failed(RuntimeError("link"))
    assert page._xfer is None and not page._stop


def test_download(page, fsdev, tmp_path, monkeypatch):
    fsdev.files["/FLASH_DISK:/FW1"] = bytearray(b"firmware" * 100)
    dst = tmp_path / "fw1.bin"
    page.download()
    assert "give the path" in logged(page)
    page.path_var.set("/FW1")
    monkeypatch.setattr(ffs.filedialog, "asksaveasfilename", lambda **kw: "")
    page.download()
    assert fsdev.commands == []
    monkeypatch.setattr(ffs.filedialog, "asksaveasfilename", lambda **kw: str(dst))
    page.download()
    assert dst.read_bytes() == b"firmware" * 100
    assert "800 bytes downloaded" in page.read_section.title and page.open_file is None
    page.path_var.set("/NONE")
    page.download()
    assert "OPENR: NOT_FOUND" in logged(page)


def test_download_save_error(page, fsdev, tmp_path, monkeypatch):
    fsdev.files["/FLASH_DISK:/f"] = bytearray(b"x")
    errors = []
    monkeypatch.setattr(ffs.messagebox, "showerror", lambda t, m: errors.append(m))
    monkeypatch.setattr(ffs.filedialog, "asksaveasfilename", lambda **kw: str(tmp_path / "no" / "dir"))
    page.path_var.set("/f")
    page.download()
    assert errors and not page.busy


# ---- link, busy, availability ---------------------------------------------------------------
def test_buttons_follow_the_link_and_the_work(page):
    assert all(getattr(page, b).enabled for b in ffs.BUTTONS) and page.state_pill.value == "Ready"
    page.ctx.svc.available = False
    page._update()
    assert not any(getattr(page, b).enabled for b in ffs.BUTTONS)
    assert page.state_pill.value == "No SETU service"
    page.ctx.svc.available = True
    page.ctx.link.connected = False
    page._update()
    assert page.state_pill.value == "Not connected"
    line(page, "ls")
    assert page.ctx.device.commands == [], "nothing runs without a link"

    page.ctx.link.connected = True
    page.ctx.hold = True
    line(page, "ls")
    assert page.busy and page.state_pill.value == "Busy"
    assert not any(getattr(page, b).enabled for b in ffs.BUTTONS)
    line(page, "ls")                                     # ignored while busy
    page.payload_var.set("x")
    page.write()
    page.path_var.set("/f")
    page.download()
    page.on_disconnected("gone")
    assert not page.busy and "files: cancelled" in logged(page)


def test_timeout_is_an_error(page, fsdev):
    fsdev.silent = True
    line(page, "ls")
    assert ("error", "files: LS: no reply from the device") in page.ctx.logs and not page.busy


def test_connect_forgets_what_was_known(page):
    line(page, "mkdir FW")
    line(page, "openw a")
    page.on_connected({})
    assert page.cwd is None and page.open_file is None and page.tile_dir.note == "not known yet"


def test_each_command_uses_a_fresh_client(page):
    line(page, "ls")
    line(page, "ls")
    assert len(page.ctx.clients) == 2, "another page may have taken the shared client"


def test_failed_reply_closing_rules_on_errors(page):
    page.open_file = ("/f", "write")
    page._failed(fsp.FsError("WRITE: IO", 9, fsp.OPS["WRITE"]))
    assert page.open_file is None
    page.open_file = ("/f", "write")
    page._failed(fsp.FsError("WRITE: BUSY", 7, fsp.OPS["WRITE"]))
    page._failed(RuntimeError("link"))
    assert page.open_file == ("/f", "write")


def test_entry_row():
    assert ffs.entry_row(fsp.Entry(False, 1234567, "/p")) == ("/p", "file", "1,234,567")
    assert ffs.entry_row(fsp.Entry(True, 0, "/d")) == ("/d", "dir", "")


# ---- the real page ----------------------------------------------------------------------------
def test_build_real_page(fsdev, tk_root, monkeypatch):
    monkeypatch.setattr(fsp, "TIMEOUT", 0.2)
    f = ffs.FileSystemFeature(Ctx(fsdev))
    frame = f.build(tk_root)
    assert frame.winfo_children()
    assert f.state_pill.text == "Ready" and "disabled" not in f.run_btn.state()
    fsdev.files["/FLASH_DISK:/a"] = bytearray(b"hi")
    f.cmd_var.set("ls")
    f.run_line()
    assert f.tree.get_children() == ("0",)
    f.tree.selection_set("0")
    f.tree.update()
    f._pick_entry()
    assert f.path_var.get() == "/FLASH_DISK:/a"
    f.cmd_var.set("openr a")
    f.run_line()
    f.cmd_var.set("read")
    f.run_line()
    assert "68 69" in f.read_text.get("1.0", "end")
    # Listed, so the read had a size; done, the bar is full
    assert str(f.progress["mode"]) == "determinate" and float(f.progress["value"]) == 2
    assert f.progress_var.get().startswith("done: 2 B in ")
    for cmd in ("close", "openw b"):
        f.cmd_var.set(cmd)
        f.run_line()
    f.payload_var.set("w" * 600)
    f.write()
    assert f.progress_var.get().startswith("done: 600 B in ") and float(f.progress["value"]) == 600
    assert f.tile_xfer.value_var.get().endswith(" kbit/s")
    f.ctx.link.connected = False
    f._update()
    assert "disabled" in f.run_btn.state() and f.state_pill.text == "Not connected"
    assert struct.calcsize("<H") == 2
