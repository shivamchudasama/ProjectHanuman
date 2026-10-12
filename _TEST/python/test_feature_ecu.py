# SPDX-License-Identifier: MIT
"""The ECU page (_TOOLS/BleHostGUI/blehost/features/ecu.py): the profile form,
target, diagnostic requests, unlock, the stored-file list and flash jobs, run
against FakeUdsDevice (UDS with the firmware's rules on the ECU simulator) and
FakeFsDevice (the file list) from conftest.py, through stand-in Tk variables and
widgets and a fake AppContext whose run() executes the coroutine at once on one
event loop (as the GUI's BLE loop). Also the SETU service's appType routes,
which keep a flash job's messages on the page whichever client another page
takes. One test builds the real page on conftest's shared Tk root."""

import asyncio
import json
import os
import struct

import pytest

import setu_client
from blehost.features import ecu
from blehost.protocols import setu as setu_proto
from blehost.protocols import uds
from conftest import REPO, FakeSETU, FakeUdsSETU

SIM_PROFILE = os.path.join(REPO, "_TOOLS", "EcuSim", "profiles", "sim.json")
SIM_FD_PROFILE = os.path.join(REPO, "_TOOLS", "EcuSim", "profiles", "sim_fd.json")


def status(state, step=0, rec=0, cnt=0, done=0, total=0, sid=0, nrc=0, st=0) -> bytes:
    return struct.pack("<BBBBIIBBB", state, step, rec, cnt, done, total, sid, nrc, st)


def flash_file(vectors) -> bytes:
    return bytes.fromhex(vectors["uds_flash"]["file_hex"])


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
    """Pill, StatTile: remembers what it was told to show."""

    def __init__(self):
        self.value, self.note = None, None

    def set(self, value, note=None):
        self.value, self.note = value, note


class Steps:
    def __init__(self):
        self.steps, self.current, self.state = [], 0, "idle"

    def set_steps(self, steps):
        self.steps = list(steps)

    def show(self, current, state):
        self.current, self.state = current, state


class Widget:
    """Progress bar, combobox: remembers what it was configured with."""

    def __init__(self):
        self.options = {}

    def configure(self, **kw):
        self.options.update(kw)


class Text:
    def __init__(self):
        self.lines = []

    def configure(self, **kw):
        pass

    def insert(self, at, text):
        self.lines.append(text.rstrip("\n"))

    def delete(self, a, b):
        if b == "end":
            self.lines = []
        else:
            del self.lines[:int(b.split(".")[0]) - 1]

    def see(self, at):
        pass


# ---- the context -------------------------------------------------------------------------
class Future:
    def __init__(self, on_cancel=None):
        self.on_cancel = on_cancel

    def cancel(self):
        if self.on_cancel:
            on_cancel, self.on_cancel = self.on_cancel, None
            on_cancel()


class Ctx:
    def __init__(self, udsdev, fsdev):
        self.link = type("Link", (), {"connected": True})()
        self.udsdev, self.fsdev = udsdev, fsdev
        self.routed, self.clients = [], []
        svc = type("Svc", (), {"available": True})()
        svc.new_client = self._new_client
        svc.routed_client = self._routed_client
        self.svc = svc
        self.services = {setu_proto.SETUService.NAME: svc}
        self.bus = type("Bus", (), {"call": staticmethod(lambda fn, *a: fn(*a))})()
        self.logs = []
        self.hold = False
        self.loop = asyncio.new_event_loop()

    def _new_client(self):
        cli = FakeSETU(self.fsdev)
        self.clients.append(cli)
        return cli

    def _routed_client(self, first, last):
        assert (first, last) == (uds.APP_FIRST, uds.APP_LAST)
        cli = FakeUdsSETU(self.udsdev)
        self.routed.append(cli)
        return cli

    def log(self, text, level="info"):
        self.logs.append((level, text))

    def run(self, coro, on_done=None, on_error=None, on_cancel=None):
        if self.hold:
            coro.close()
            return Future(on_cancel)
        try:
            result = self.loop.run_until_complete(coro)
        except Exception as e:                  # noqa: BLE001 - as AppContext.run
            if on_error:
                on_error(e)
        else:
            if on_done:
                on_done(result)
        return Future()


def make_page(ctx) -> ecu.EcuFeature:
    f = ecu.EcuFeature(ctx)
    f.v = {n: Var("") for n in ecu.TARGET_TEXT + ecu.SEQ_TEXT + ecu.OTHER_TEXT}
    f.v.update({n: Var(False) for n in ecu.TARGET_BOOL + ecu.OTHER_BOOL})
    f.flag_vars = {n: Var(False) for n in uds.FF}
    f.summary_var, f.profile_var = Var(), Var()
    for name in ecu.SEND_BUTTONS + ("abort_btn", "status_entry"):
        setattr(f, name, Button())
    f.quick_btns = [Button() for _ in ecu.QUICK]
    f.state_pill, f.job_pill = Shown(), Shown()
    f.tile_rec, f.tile_data, f.tile_rate, f.tile_nrc = Shown(), Shown(), Shown(), Shown()
    f.stepper, f.progress, f.file_box, f.rsp_text = Steps(), Widget(), Widget(), Text()
    f.fill_form(uds.Target(), uds.FlashParams())
    f._update()
    return f


@pytest.fixture
def fsdev():
    from conftest import FakeFsDevice
    return FakeFsDevice()


@pytest.fixture
def page(udsdev, fsdev, monkeypatch):
    monkeypatch.setattr(uds, "STATUS_SILENCE", 0.02)
    monkeypatch.setattr(uds, "TIMEOUT_TARGET", 0.05)
    ctx = Ctx(udsdev, fsdev)
    yield make_page(ctx)
    ctx.loop.close()


def logged(f) -> str:
    return "\n".join(t for _, t in f.ctx.logs)


def load(f, path=SIM_PROFILE):
    f.fill_form(*uds.load_profile(path))
    f._update()


def apply(f, path=SIM_PROFILE):
    load(f, path)
    f.apply_target()
    assert f.applied is not None, logged(f)


# ---- helpers -------------------------------------------------------------------------------
def test_parsers():
    assert ecu.parse_int("0x7E0", "ID", 0, 0x7FF) == 0x7E0 and ecu.parse_int(" 15 ", "x", 0, 20) == 15
    with pytest.raises(ValueError, match="TX ID: 'zz' is not a number"):
        ecu.parse_int("zz", "TX ID", 0, 1)
    with pytest.raises(ValueError, match=r"ID must be 0x0…0x7FF"):
        ecu.parse_int("0x800", "ID", 0, 0x7FF)
    with pytest.raises(ValueError, match="P2 must be 0…65535"):
        ecu.parse_int("70000", "P2", 0, 0xFFFF)
    assert [ecu.parse_bitrate(t, "b", 1, 10 ** 8) for t in ("500000", "500k", "2M", "2.5m", "1_000k")] == \
        [500000, 500000, 2000000, 2500000, 1000000]
    with pytest.raises(ValueError, match="not a bitrate"):
        ecu.parse_bitrate("fast", "Bitrate", 1, 2)
    with pytest.raises(ValueError, match="Bitrate must be 10,000…1,000,000 bit/s"):
        ecu.parse_bitrate("2M", "Bitrate", 10000, 1000000)
    assert ecu.parse_level("0x01") == 1
    for bad in ("2", "0", "0x7F"):
        with pytest.raises(ValueError, match="Security level"):
            ecu.parse_level(bad)
    assert ecu.parse_algo("bench_xor") == 1 and ecu.parse_algo("0x80") == 0x80
    assert ecu.algo_text(1) == "BENCH_XOR" and ecu.algo_text(0x81) == "0x81"
    assert ecu.parse_request("22 F1 90") == b"\x22\xf1\x90" and ecu.parse_request("0x22,0xF1") == b"\x22\xf1"
    for bad, msg in (("2", "not hex"), ("", "1…240 bytes"), ("00" * 241, "1…240 bytes")):
        with pytest.raises(ValueError, match=msg):
            ecu.parse_request(bad)
    with pytest.raises(ValueError, match="functional request is at most 7"):
        ecu.parse_request("22" * 8, functional=True)
    assert ecu.check_file_name(" APP1.BIN ") == "APP1.BIN"
    with pytest.raises(ValueError, match="1…32 characters"):
        ecu.check_file_name("FW/APP")
    assert [ecu.bitrate_text(v) for v in (500000, 2000000, 83333)] == ["500k", "2M", "83333"]


def test_summary_and_flash_steps():
    t, p = uds.load_profile(SIM_FD_PROFILE)
    assert ecu.target_summary(t) == "CAN FD 500k/2M BRS · tx 0x7E0 rx 0x7E8 func 0x7DF · DL 64"
    assert ecu.target_summary(uds.Target(dl=0)) == "CAN 500k · tx 0x7E0 rx 0x7E8 · DL 8"
    assert ecu.target_summary(uds.Target(tx_id=0x18DA10F1, rx_id=1, extended_ids=True)).startswith(
        "CAN 500k · tx 0x18DA10F1 rx 0x00000001")
    rows = ecu.flash_steps(p)
    assert [label for _, label in rows] == [
        "Extended session (10 03)", "DTC setting off (85 02)", "Communication off (28)",
        "Programming session (10 02)", "Security access (27)", "Fingerprint (2E)",
        "Erase and download per record", "Check (31 01)", "ECU reset (11)", "Done"]
    assert [ecu.step_row(rows, s) for s in (0, 1, 4, 7, 9, 10, 11, 13)] == [0, 0, 3, 6, 6, 6, 7, 9]
    bare = ecu.flash_steps(uds.FlashParams(flags=uds.FF["ERASE"]))
    assert [label for _, label in bare] == ["Programming session (10 02)", "Erase (31 01)",
                                             "Download (34 / 36 / 37)", "Done"]
    assert ecu.step_row(bare, 1) == 0, "a step that does not run: the next row"


# ---- the form ------------------------------------------------------------------------------
@pytest.mark.parametrize("path", [SIM_PROFILE, SIM_FD_PROFILE])
def test_form_holds_a_profile(page, path):
    target, params = uds.load_profile(path)
    page.fill_form(target, params)
    assert page.target_from_form() == target and page.params_from_form() == params
    assert page.v["tx_id"].get() == "0x7E0" and page.v["algo"].get() == "BENCH_XOR"
    assert page.v["unlock_level"].get() == "1" and page.v["unlock_algo"].get() == "BENCH_XOR"


def test_form_drops_sub_steps_and_ignores_fd_fields_without_fd(page):
    load(page)
    page.flag_vars["ERASE"].set(False)
    page.flag_vars["CHECK"].set(False)
    p = page.params_from_form()
    assert not p.flags & (uds.FF["ERASE_PER_RECORD"] | uds.FF["CHECK_CRC"] | uds.FF["ERASE"])
    page.v["fd"].set(False)
    page.v["brs"].set(True)
    page.v["data_bitrate"].set("rubbish")
    t = page.target_from_form()
    assert (t.fd, t.brs, t.data_bitrate) == (False, False, uds.Target.data_bitrate)


@pytest.mark.parametrize("field, value, message", [
    ("tx_id", "0x800", r"TX ID \(11-bit\) must be 0x0…0x7FF"),
    ("rx_id", "0x7E0", "TX and RX IDs must differ"),
    ("func_id", "x", "Functional ID"),
    ("bitrate", "5M", "Bitrate must be"),
    ("dl", "64", r"DL must be 0 or 8 \(12…64 needs CAN FD\)"),
    ("p2star", "-1", "P2\\* must be"),
])
def test_target_form_errors_show_in_the_summary(page, field, value, message):
    load(page)
    page.v[field].set(value)
    with pytest.raises(ValueError, match=message):
        page.target_from_form()
    page._update()
    assert page.summary_var.get().startswith("⚠")


def test_fd_target_form_rules(page):
    load(page, SIM_FD_PROFILE)
    page.v["dl"].set("24")
    assert page.target_from_form().dl == 24
    page.v["dl"].set("40")
    with pytest.raises(ValueError, match="DL must be 0 or 8, 12, 16"):
        page.target_from_form()
    page.v["dl"].set("64")
    page.v["data_bitrate"].set("20M")
    with pytest.raises(ValueError, match="Data bitrate"):
        page.target_from_form()
    page.v["data_bitrate"].set("2M")
    page.v["ext_ids"].set(True)
    page.v["tx_id"].set("0x18DA10F1")
    page.v["rx_id"].set("0x18DAF110")
    page.v["func_id"].set("")
    t = page.target_from_form()
    assert (t.extended_ids, t.tx_id, t.func_id) == (True, 0x18DA10F1, None)


@pytest.mark.parametrize("field, value, message", [
    ("level", "2", "Security level must be odd"),
    ("algo", "ROT13", "Key algorithm"),
    ("alfid", "0x54", "ALFID: size and address bytes"),
    ("fp_data", "zz", "Fingerprint data is not hex"),
    ("fp_data", "", r"Fingerprint data is 1…16 bytes"),
    ("fp_data", "00" * 17, r"Fingerprint data is 1…16 bytes"),
    ("erase_rid", "0x10000", "Erase RID"),
    ("max_block", "-2", "Max block"),
])
def test_sequence_form_errors(page, field, value, message):
    load(page)
    page.v[field].set(value)
    with pytest.raises(ValueError, match=message):
        page.params_from_form()


# ---- profiles ------------------------------------------------------------------------------
def test_profile_load_save_and_new(page, tmp_path, monkeypatch):
    errors = []
    monkeypatch.setattr(ecu.messagebox, "showerror", lambda t, m: errors.append(m))
    out = tmp_path / "mine.json"
    load(page, SIM_FD_PROFILE)
    page.v["tx_id"].set("0x7E1")
    monkeypatch.setattr(ecu.filedialog, "asksaveasfilename", lambda **kw: "")
    page.save_profile()
    assert not out.exists()
    monkeypatch.setattr(ecu.filedialog, "asksaveasfilename", lambda **kw: str(out))
    page.save_profile()
    assert json.loads(out.read_text(encoding="utf-8"))["addressing"]["tx_id"] == "0x7E1"
    assert page.profile_var.get() == "Profile: mine.json" and "profile saved" in logged(page)

    page.new_profile()
    assert page.target_from_form() == uds.Target() and page.profile_var.get().endswith("(not saved)")
    for chosen in ("", str(out)):
        monkeypatch.setattr(ecu.filedialog, "askopenfilename", lambda **kw: chosen)
        page.load_profile()
    assert page.target_from_form().tx_id == 0x7E1 and page.target_from_form().fd

    bad = tmp_path / "bad.json"
    bad.write_text('{"addressing": {}}', encoding="utf-8")
    monkeypatch.setattr(ecu.filedialog, "askopenfilename", lambda **kw: str(bad))
    page.load_profile()
    page.v["dl"].set("x")
    page.save_profile()
    monkeypatch.setattr(ecu.filedialog, "asksaveasfilename", lambda **kw: str(tmp_path / "no" / "dir.json"))
    page.v["dl"].set("8")
    page.save_profile()
    assert len(errors) == 3 and "bad.json" in errors[0] and "DL" in errors[1]


# ---- target, requests, unlock ------------------------------------------------------------
def test_buttons_need_a_link_and_a_target(page):
    assert page.state_pill.value == "No target" and page.apply_btn.enabled and page.refresh_btn.enabled
    assert not page.send_btn.enabled and not page.flash_btn.enabled and not page.quick_btns[0].enabled
    assert not page.abort_btn.enabled and page.status_entry.enabled
    page.ctx.svc.available = False
    page._update()
    assert page.state_pill.value == "No SETU service" and not page.apply_btn.enabled
    page.ctx.link.connected = False
    page._update()
    assert page.state_pill.value == "Not connected"
    page.apply_target()
    page.send_request()
    page.get_status()
    assert page.ctx.udsdev.received == [], "nothing runs without a link"


def test_apply_target(page, udsdev):
    load(page, SIM_FD_PROFILE)
    page.v["tx_id"].set("0x800")
    page.apply_target()
    assert "TX ID" in logged(page) and udsdev.received == []
    page.v["tx_id"].set("0x7E0")
    page.apply_target()
    assert page.applied == uds.load_profile(SIM_FD_PROFILE)[0] == udsdev.target
    assert page.state_pill.value == "Target set" and page.send_btn.enabled and page.flash_btn.enabled
    assert "target set: CAN FD 500k/2M BRS" in logged(page)
    page.v["p2"].set("100")
    page._update()
    assert page.state_pill.value == "Target changed: apply"
    udsdev.target_status = 1
    page.apply_target()
    assert page.applied is None and ("error", "ecu: TARGET: BUSY") in page.ctx.logs
    assert page.state_pill.value == "No target"
    assert len(page.ctx.routed) == 1, "one routed client for the connection"


def test_requests_and_responses(page, udsdev):
    apply(page)
    page.v["request"].set("22 F1 90")
    page.send_request()
    page.v["request"].set("22F1AA")
    page.send_request()
    page.quick("3E 00")
    page.v["request"].set("2")
    page.send_request()
    assert "ecu: the request is not hex" in logged(page)
    assert page.responses == [
        "→ 22 f1 90", "← OK  62 f1 90 " + b"WMI0HANUMAN000001".hex(" "),
        "→ 22 f1 aa", "← NRC  7f 22 31  NRC 0x31 requestOutOfRange",
        "→ 3e 00", "← OK  7e 00"]
    assert page.rsp_text.lines == page.responses
    page.v["functional"].set(True)
    page.v["request"].set("3E 80")
    page.send_request()
    assert page.responses[-2:] == ["→ func 3e 80", "← OK  (no response)"]
    assert udsdev.received[-1] == (uds.APP_DIAG_REQ, bytes([page._seq, 1, 0x3E, 0x80]))
    udsdev.silent = True
    page.v["request"].set("22F190")
    page.send_request()
    assert page.responses[-1] == "← TIMEOUT  (no response)"
    page.clear_responses()
    assert page.responses == [] and page.rsp_text.lines == []


def test_responses_keep_the_last_lines(page, monkeypatch):
    monkeypatch.setattr(ecu, "RESPONSE_LINES", 3)
    for i in range(5):
        page._respond(f"line {i}")
    assert page.responses == ["line 2", "line 3", "line 4"] == page.rsp_text.lines


def test_a_request_without_an_answer_is_an_error_line(page, udsdev, monkeypatch):
    apply(page)
    monkeypatch.setattr(uds, "TIMEOUT_DIAG", 0.05)
    cli = page._uds.setu_cli

    async def dead(app_type, payload):
        await asyncio.sleep(0)
    cli.send_short = dead
    page.v["request"].set("1001")
    page.send_request()
    assert page.responses[-1] == "← DIAG_REQ: no answer from the device" and not page.busy
    assert ("error", "ecu: DIAG_REQ: no answer from the device") in page.ctx.logs


def test_unlock(page, udsdev):
    apply(page)
    page.v["unlock_level"].set("2")
    page.unlock()
    assert "Security level must be odd" in logged(page)
    page.v["unlock_level"].set("1")
    page.unlock()
    assert page.responses[-1] == "← UNLOCK: NRC (NRC 0x7f) serviceNotSupportedInActiveSession"
    page.quick("10 03")
    page.unlock()
    assert page.responses[-1] == "← level 0x01 unlocked" and udsdev.ecu.unlocked
    page.v["unlock_algo"].set("0x80")
    page.unlock()
    assert "NOT_SUPPORTED" in page.responses[-1]


# ---- stored files and flashing ------------------------------------------------------------
def test_refresh_lists_the_stored_uploads(page, fsdev):
    fsdev.dirs.update({"/FLASH_DISK:/FW", "/FLASH_DISK:/LOG"})
    fsdev.files["/FLASH_DISK:/FW/APP2.BIN"] = bytearray(8)
    fsdev.files["/FLASH_DISK:/FW/APP1.BIN"] = bytearray(8)
    fsdev.files["/FLASH_DISK:/LOG/x"] = bytearray(1)
    page.refresh_files()
    assert page.files == ["APP1.BIN", "APP2.BIN"] == page.file_box.options["values"]
    assert page.v["file"].get() == "APP1.BIN" and "2 stored upload(s): APP1.BIN, APP2.BIN" in logged(page)
    page.v["file"].set("APP2.BIN")
    page.refresh_files()
    assert page.v["file"].get() == "APP2.BIN", "a listed choice stays"
    fsdev.files.clear()
    page.refresh_files()
    assert "0 stored upload(s) (store one with Hex Upload" in logged(page)
    fsdev.busy = True
    page.refresh_files()
    assert "LS: BUSY" in logged(page)


def test_flash_runs_and_shows_the_job(page, udsdev, vectors, monkeypatch):
    from ecu_sim import EcuSim
    udsdev.ecu = EcuSim(max_block=18)
    udsdev.files["APP1.BIN"] = flash_file(vectors)
    apply(page)
    asked = []
    monkeypatch.setattr(ecu.messagebox, "askyesno", lambda t, m: asked.append(m) or False)
    page.v["file"].set("APP1.BIN")
    page.flash()
    assert asked and "Flash APP1.BIN into the ECU (CAN 500k" in asked[0] and "EXT_SESSION" in asked[0]
    assert not any(t == uds.APP_FLASH for t, _ in udsdev.received), "not confirmed: not sent"

    shown = []
    real = page.show_status
    monkeypatch.setattr(page, "show_status", lambda st: shown.append(st) or real(st))
    page.flash(confirm=False)
    assert udsdev.ecu.image == flash_file(vectors)
    assert shown[0].step_name == "EXT_SESSION" and shown[-1].state_name == "DONE"
    assert page.stepper.steps[0] == "Extended session (10 03)" and page.stepper.state == "done"
    assert page.job_pill.value == "DONE" and page.tile_rec.value == "2 / 2"
    assert page.tile_data.value == "30 / 30" and page.tile_data.note == "bytes, 100 %"
    assert page.progress.options == {"maximum": 30, "value": 30}
    assert "flash APP1.BIN accepted, steps: EXT_SESSION" in logged(page)
    assert "flashed APP1.BIN: 30 bytes" in logged(page)
    assert not page.busy and page.state_pill.value == "Target set"


def test_flash_refusals_and_failures(page, udsdev, vectors):
    from ecu_sim import EcuSim
    apply(page)
    page.v["file"].set("FW/APP")
    page.flash(confirm=False)
    page.v["file"].set("APP1.BIN")
    page.v["level"].set("2")
    page.flash(confirm=False)
    assert "1…32 characters" in logged(page) and "must be odd" in logged(page)
    assert not any(t == uds.APP_FLASH for t, _ in udsdev.received)
    page.v["level"].set("1")

    page.flash(confirm=False)                       # no such file
    assert ("error", "ecu: flash APP1.BIN: FAILED NONE: FILE") in page.ctx.logs
    assert page.job_pill.value == "FAILED: FILE" and page.stepper.state == "failed"

    udsdev.files["APP1.BIN"] = flash_file(vectors)
    udsdev.ecu = EcuSim(nrc_at=(0x36, 0x72))
    page.flash(confirm=False)
    assert page.stepper.current == 6 and page.stepper.state == "failed", "on the download row"
    assert (page.tile_nrc.value, page.tile_nrc.note) == ("0x72", "SID 0x36: generalProgrammingFailure")
    assert "SID 0x36 NRC 0x72" in logged(page) and not page.busy

    udsdev.target = None                            # a reset device: no target
    page.flash(confirm=False)
    assert ("error", "ecu: FLASH: NOT_READY") in page.ctx.logs


def test_abort_and_a_lost_link_while_flashing(page, udsdev):
    apply(page)
    page.v["file"].set("APP1.BIN")
    page.ctx.hold = True
    page.flash(confirm=False)
    assert page.busy and page.state_pill.value == "Flashing"
    assert page.abort_btn.enabled and not page.send_btn.enabled and not page.apply_btn.enabled
    page.ctx.hold = False
    page.send_request()
    page.apply_target()
    assert udsdev.received[-1][0] == uds.APP_TARGET, "nothing else is sent while the job runs"
    page.abort()
    assert udsdev.received[-1][0] == uds.APP_ABORT and "abort requested" in logged(page)
    page.on_disconnected("link lost")
    assert not page.busy and page._uds is None
    assert "stopped following the flash job; it goes on on the device" in logged(page)
    assert page.state_pill.value == "No target"
    page.abort()                                    # no job followed: nothing sent
    assert udsdev.received[-1][0] == uds.APP_ABORT and len(
        [t for t, _ in udsdev.received if t == uds.APP_ABORT]) == 1


def test_an_aborted_job_ends_with_a_warning(page, udsdev):
    apply(page)
    udsdev.status = status(4, 9, 0, 2, 10, 30, st=10)
    page._follow()
    assert page.job_pill.value == "ABORTED" and page.stepper.state == "aborted"
    assert ("warn", "ecu: flash: ABORTED TRANSFER record 1/2 10/30 bytes (33 %): ABORTED") in page.ctx.logs


def test_connecting_picks_up_a_running_job(page, udsdev):
    replies = iter([status(1, 9, 0, 2, 10, 30), status(1, 9, 1, 2, 20, 30), status(2, 13, 2, 2, 30, 30)])
    real = udsdev.handle

    def handle(app_type, p):
        if app_type == uds.APP_STATUS_REQ:
            udsdev.status = next(replies, udsdev.status)
        return real(app_type, p)
    udsdev.handle = handle
    page.applied = uds.Target()
    page.on_connected({})
    text = logged(page)
    assert "a flash job runs on the device (RUNNING TRANSFER record 1/2 10/30 bytes (33 %)); following it" in text
    assert "flashed the file: 30 bytes" in text and page.job_pill.value == "DONE"
    assert page.applied is None, "which target the device has is not known"
    assert not page.busy


def test_connecting_to_an_idle_or_a_silent_device(page, udsdev):
    page.on_connected({})
    assert page.job_pill.value is None and not page.busy, "IDLE: nothing to show"
    page.ctx.routed.clear()
    udsdev.handle = lambda app_type, p: []
    page.on_connected({})
    assert "ecu: no UDS on this device? (STATUS_REQ: no answer from the device)" in logged(page)
    page.ctx.svc.available = False
    page.on_connected({})
    assert len(page.ctx.routed) == 1, "no SETU service: not asked"


def test_get_status(page, udsdev):
    udsdev.status = status(3, 9, 1, 2, 20, 30, 0x36, 0x72, uds.ST_NRC)
    page.get_status()
    assert "ecu: job FAILED TRANSFER record 2/2 20/30 bytes (66 %): NRC, SID 0x36 NRC 0x72" in logged(page)
    assert page.job_pill.value == "FAILED: NRC" and page.tile_nrc.value == "0x72"


def test_the_rate_follows_the_bytes(page, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(ecu.time, "perf_counter", lambda: now[0])
    page.show_status(uds.decode_status(status(1, 9, 0, 1, 0, 1000)))
    now[0] = 101.0
    page.show_status(uds.decode_status(status(1, 9, 0, 1, 500, 1000)))
    assert page.tile_rate.value == "4.0" and page.rate == 4.0
    page.show_status(uds.decode_status(status(1, 9, 0, 0, 0, 0)))
    assert page.tile_rec.value == "–" and page.tile_data.value == "–"


# ---- appType routes in the SETU service ------------------------------------------------------
def test_setu_service_routes_an_app_type_range(monkeypatch):
    from blehost.context import AppContext
    ctx = AppContext()
    svc = setu_proto.SETUService(ctx)
    with pytest.raises(RuntimeError, match="not connected"):
        svc.routed_client(0x50, 0x5F)
    ctx.link.gatt = type("Gatt", (), {"mtu_size": 247})()
    svc.available = True
    general = svc.new_client()
    routed = svc.routed_client(0x50, 0x5F)
    again = svc.routed_client(0x50, 0x5F)
    assert len(svc.routes) == 1 and svc.routes[0][2] is again, "a range has one client"
    other = svc.new_client()                        # another page takes the shared client
    svc._on_ctrl(None, bytearray([1, 0x56, 0]))
    svc._on_ctrl(None, bytearray([1, 0x41, 1]))
    svc._on_ctrl(None, bytearray([3, setu_client.T_ACK, 1, 2, 3]))
    assert again.short_q.qsize() == 1 and routed.short_q.empty() and general.short_q.empty()
    assert other.short_q.qsize() == 1 and other.ctrl_q.qsize() == 1
    svc._detach(ctx.link, "gone")
    assert svc.routes == [] and svc.client is None
    svc._on_ctrl(None, bytearray([1, 0x56, 0]))       # nobody to tell: dropped
    assert again.short_q.qsize() == 1


# ---- the real page ----------------------------------------------------------------------------
def test_build_real_page(udsdev, fsdev, vectors, tk_root, monkeypatch):
    from ecu_sim import EcuSim
    monkeypatch.setattr(uds, "TIMEOUT_TARGET", 0.05)
    udsdev.ecu = EcuSim(max_block=18)
    ctx = Ctx(udsdev, fsdev)
    f = ecu.EcuFeature(ctx)
    try:
        frame = f.build(tk_root)
        assert frame.winfo_children()
        assert f.state_pill.text == "No target" and "disabled" not in f.apply_btn.state()
        assert "disabled" in f.send_btn.state()
        assert udsdev.received[0][0] == uds.APP_STATUS_REQ, "the page asked for a running job"
        assert f.summary_var.get() == "CAN 500k · tx 0x7E0 rx 0x7E8 · DL 8"
        assert [k for k, w in f.views.items() if w.winfo_manager()] == ["profile"]
        f.view_var.set("diag")
        f._show_view()
        assert [k for k, w in f.views.items() if w.winfo_manager()] == ["diag"]

        f.fill_form(*uds.load_profile(SIM_FD_PROFILE))
        assert f.summary_var.get().startswith("CAN FD 500k/2M BRS"), "the traces follow the form"
        f.apply_target()
        assert f.state_pill.text == "Target set" and "disabled" not in f.send_btn.state()
        f.v["request"].set("22F190")
        f.send_request()
        assert "62 f1 90" in f.rsp_text.get("1.0", "end")
        f.v["dl"].set("40")
        assert f.summary_var.get().startswith("⚠ DL must be")

        f.view_var.set("flash")
        f._show_view()
        udsdev.files["APP1.BIN"] = flash_file(vectors)
        f.v["dl"].set("64")
        f.v["file"].set("APP1.BIN")
        f.flash(confirm=False)
        assert f.stepper.steps[-1] == "Done" and f.job_pill.text == "DONE"
        ctx.link.connected = False
        f._update()
        assert "disabled" in f.flash_btn.state() and f.state_pill.text == "Not connected"
    finally:
        ctx.loop.close()
