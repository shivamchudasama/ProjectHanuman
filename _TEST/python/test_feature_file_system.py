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
    for name in ("cmd_var", "path_var", "payload_var", "count_var"):
        setattr(f, name, Var())
    f.hex_var = Var(False)
    for name in ffs.BUTTONS + ("stop_btn",):
        setattr(f, name, Button())
    f.state_pill, f.tile_dir, f.tile_file = Shown(), Shown(), Shown()
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
    page.stop_read()                                    # nothing to stop
    assert not page._stop_read
    real = fsdev.handle

    def handle(payload):
        if payload[1] == fsp.OPS["READ"] and len(read_args(fsdev)) == 1:
            page.stop_read()                            # during the second READ
        return real(payload)
    fsdev.handle = handle
    page.read()
    assert len(read_args(fsdev)) == 2, "it ended after the READ in flight"
    assert len(page.read_data) == 478 and "read stopped after 478 bytes" in logged(page)
    assert page.open_file is not None and not page.stop_btn.enabled and not page._stop_read
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
    page.stop_read()
    assert not page.stop_btn.enabled, "asked once"
    page.on_disconnected("gone")
    assert not page.busy and not page._reading and not page._stop_read and not page.stop_btn.enabled
    page.ctx.hold = False
    line(page, "ls")
    assert not page.stop_btn.enabled, "only a Read can be stopped"


def test_read_progress_only_while_reading(page):
    page._read_progress(1234)
    assert page.read_section.title is None
    page._reading = True
    page._read_progress(1234)
    assert page.read_section.title == "Read data (reading… 1,234 bytes)"


def test_a_cancelled_or_failed_read_ends_it(page):
    page._reading = True
    page._cancelled()
    assert not page._reading
    page._reading = page._stop_read = True
    page._failed(RuntimeError("link"))
    assert not page._reading and not page._stop_read


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
    f.ctx.link.connected = False
    f._update()
    assert "disabled" in f.run_btn.state() and f.state_pill.text == "Not connected"
    assert struct.calcsize("<H") == 2
