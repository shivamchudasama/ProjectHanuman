# SPDX-License-Identifier: MIT
"""The file commands over BLE (blehost/protocols/filesystem.py) and storing a hex
upload as a file (setu_client.py BEGIN / COMMIT), against the golden frames
of wire.json "file_system" and "hex_file" - the same bytes the C tests check on
the firmware - and against FakeFsDevice (conftest.py), a scripted device with
the firmware's rules."""

import asyncio
import struct
import zlib

import pytest

import setu_client
from blehost.protocols import setu as proto
from blehost.protocols import filesystem as fsp
from conftest import FakeSETU


def run(coro):
    return asyncio.run(coro)


def frame_of(vec) -> tuple:
    wire = bytes.fromhex(vec["hex"])
    assert wire[0] == len(wire) - 2
    return wire[1], wire[2:]


def vec(vectors, section, name):
    return next(s for s in vectors[section]["shorts"] if s["name"] == name)


# ---- constants -------------------------------------------------------------------------
def test_constants_match_firmware(vectors):
    fs = vectors["file_system"]
    assert (fsp.APP_CMD, fsp.APP_REPLY, fsp.APP_ENTRY) == tuple(fs["app_types"][k] for k in ("CMD", "REPLY", "ENTRY"))
    assert [fsp.APP_FIRST, fsp.APP_LAST] == fs["app_type_range"]
    assert fsp.OPS == fs["ops"]
    assert fsp.STATUS == {v: k for k, v in fs["status"].items()}
    assert (fsp.ENTRY_FILE, fsp.ENTRY_DIR) == (fs["entry_types"]["FILE"], fs["entry_types"]["DIR"])
    assert (fsp.ARG_MAX, fsp.READ_MAX, fsp.ENTRY_PATH_MAX) == (
        fs["limits"]["arg_max"], fs["limits"]["read_max"], fs["limits"]["entry_path_max"])
    assert (fsp.ST_OK, fsp.ST_BAD_ARG, fsp.ST_BAD_STATE, fsp.ST_BUSY) == tuple(
        fs["status"][k] for k in ("OK", "BAD_ARG", "BAD_STATE", "BUSY"))


def test_hex_file_constants_match_firmware(vectors):
    hf = vectors["hex_file"]
    assert (setu_client.APP_TYPE_BEGIN, setu_client.APP_TYPE_COMMIT, setu_client.APP_TYPE_FILE) == tuple(
        hf["app_types"][k] for k in ("BEGIN", "COMMIT", "FILE"))
    assert setu_client.FILE_DIR == hf["dir"]
    assert setu_client.FILE_NAME_MAX == hf["name_max"]
    assert not setu_client.valid_file_name(hf["temp_name"]) and not setu_client.valid_file_name(hf["temp_name"].lower())


# ---- codecs ------------------------------------------------------------------------------
def test_every_cmd_vector_encodes_byte_identical(vectors):
    cmds = [s for s in vectors["file_system"]["shorts"] if s["name"].startswith("cmd_")]
    assert len(cmds) >= 10
    for v in cmds:
        t, payload = frame_of(v)
        assert t == fsp.APP_CMD
        assert fsp.encode_cmd(v["seq"], v["op"], bytes.fromhex(v["arg_hex"])) == payload, v["name"]
        assert setu_client.frame(t, payload) == bytes.fromhex(v["hex"])


def test_every_reply_vector_decodes(vectors):
    for v in (s for s in vectors["file_system"]["shorts"] if s["name"].startswith("reply_")):
        t, payload = frame_of(v)
        r = fsp.decode_reply(payload)
        assert t == fsp.APP_REPLY
        assert (r.seq, r.op, r.status, r.data) == (v["seq"], v["op"], v["status"],
                                                   bytes.fromhex(v["data_hex"])), v["name"]


def test_reply_accessors(vectors):
    assert fsp.decode_reply(frame_of(vec(vectors, "file_system", "reply_mkdir_ok"))[1]).text == "/FLASH_DISK:/FW"
    assert fsp.decode_reply(frame_of(vec(vectors, "file_system", "reply_write_ok"))[1]).total == 5
    assert fsp.decode_reply(frame_of(vec(vectors, "file_system", "reply_ls_ok"))[1]).count == 2
    r = fsp.decode_reply(frame_of(vec(vectors, "file_system", "reply_busy"))[1])
    assert (r.ok, r.status_name, r.op_name) == (False, "BUSY", "OPENW")
    assert fsp.Reply(1, 99, 0).op_name == "op 99" and fsp.Reply(1, 1, 200).status_name == "0xc8"
    assert fsp.Reply(1, 5, 0, b"\x01").total == 0 and fsp.Reply(1, 7, 0).count == 0
    with pytest.raises(ValueError):
        fsp.decode_reply(b"\x01\x02")


def test_every_entry_vector_decodes(vectors):
    for v in (s for s in vectors["file_system"]["shorts"] if s["name"].startswith("entry_")):
        t, payload = frame_of(v)
        seq, e = fsp.decode_entry(payload)
        assert t == fsp.APP_ENTRY
        assert (seq, e.is_dir, e.size, e.path) == (v["seq"], v["type"] == 1, v["size"], v["path"])
    assert fsp.Entry(False, 1, "/FLASH_DISK:/FW/FW1").name == "FW1"
    with pytest.raises(ValueError):
        fsp.decode_entry(b"\x01\x00\x00")


@pytest.mark.parametrize("status, op, closes", [
    (9, "WRITE", True), (4, "WRITE", True), (9, "READ", True), (9, "CLOSE", True),
    (6, "WRITE", False), (7, "WRITE", False), (5, "WRITE", False), (9, "MKDIR", False), (0, "WRITE", False),
])
def test_which_failures_close_the_file(status, op, closes):
    assert fsp.Reply(1, fsp.OPS[op], status).closes_file is closes


def test_argument_limits():
    assert len(fsp.encode_cmd(1, 5, bytes(fsp.ARG_MAX))) == fsp.SHORT_MAX
    with pytest.raises(ValueError):
        fsp.encode_cmd(1, 5, bytes(fsp.ARG_MAX + 1))
    assert fsp.encode_read() == b"" and fsp.encode_read(16) == b"\x10\x00"
    with pytest.raises(ValueError):
        fsp.encode_read(70000)


# ---- the UART harness's command lines --------------------------------------------------
@pytest.mark.parametrize("line, op, arg", [
    ("mkdir FW", "MKDIR", b"FW"), ("cd /FLASH_DISK:/FW", "CD", b"/FLASH_DISK:/FW"),
    ("openr a.txt", "OPENR", b"a.txt"), ("openw  a.txt ", "OPENW", b"a.txt"),
    ("write hello world", "WRITE", b"hello world"), ("read", "READ", None), ("read 16", "READ", 16),
    ("read 999999", "READ", 999999), ("ls", "LS", b""), ("delfile /FW/a", "DELFILE", b"/FW/a"),
    ("deldir FW", "DELDIR", b"FW"), ("close", "CLOSE", b""), ("abort", "ABORT", b""), ("help", "help", b""),
])
def test_parse_line(line, op, arg):
    assert fsp.parse_line(line) == (op, arg)


@pytest.mark.parametrize("line, match", [
    ("", "empty"), ("format", "Unknown command: format"), ("mkdir", "requires a path"),
    ("write", "requires a payload"), ("read 0", "positive"), ("read x", "positive"),
    ("write " + "x" * 241, "at most 240"),
])
def test_parse_line_errors(line, match):
    with pytest.raises(ValueError, match=match):
        fsp.parse_line(line)


def test_help_lists_every_harness_command():
    text = "\n".join(fsp.HELP)
    for name in ("mkdir", "cd", "openr", "openw", "write", "read", "ls", "delfile", "deldir", "close", "abort"):
        assert f"  {name}" in text


def test_hexdump():
    assert fsp.hexdump(b"AB\x00") == ["0000: 41 42 00" + " " * 39 + "  AB."]
    assert len(fsp.hexdump(bytes(40))) == 3


# ---- traffic monitor ---------------------------------------------------------------------
def test_monitor_names_the_file_frames(vectors):
    cases = {"cmd_mkdir": "FS_CMD seq=1 MKDIR FW", "cmd_read_16": "FS_CMD seq=8 READ 16",
             "cmd_write": "FS_CMD seq=4 WRITE 5 B", "cmd_ls": "FS_CMD seq=10 LS",
             "reply_read_data": "FS_REPLY seq=8 READ OK 5 B", "reply_busy": "FS_REPLY seq=15 OPENW BUSY",
             "entry_file_fw1": "FS_ENTRY seq=10 FILE /FLASH_DISK:/FW/FW1 6568 B",
             "entry_dir_fw": "FS_ENTRY seq=10 DIR  /FLASH_DISK:/FW"}
    for name, shown in cases.items():
        assert proto.decode_frame(bytes.fromhex(vec(vectors, "file_system", name)["hex"])) == ("SHORT", shown)
    assert proto.decode_frame(setu_client.frame(0x41, b"\x01"))[1] == "FS_REPLY 01"
    assert proto.decode_frame(setu_client.frame(0x42, b"\x01"))[1] == "FS_ENTRY 01"
    assert proto.decode_frame(setu_client.frame(0x40, b"\x01"))[1] == "FS_CMD 01"


# ---- the session on the scripted device ---------------------------------------------------
@pytest.fixture
def session(fsdev):
    return fsp.FileSystemSession(FakeSETU(fsdev), log=lambda *_: None, timeout=0.2)


def test_session_write_then_read_back(session, fsdev):
    assert run(session.mkdir("FW")) == "/FLASH_DISK:/FW"
    assert run(session.openw("a.bin")) == "/FLASH_DISK:/FW/a.bin"
    data = bytes(range(256)) * 3                          # 768 B: 4 WRITE commands
    assert run(session.write(data)) == 768
    assert [len(a) for s, o, a in fsdev.commands if o == fsp.OPS["WRITE"]] == [240, 240, 240, 48]
    assert run(session.close()) == 768
    assert run(session.openr("/FW/a.bin")) == "/FLASH_DISK:/FW/a.bin"
    assert run(session.read(16)) == data[:16]
    assert run(session.read()) == data[16:16 + 239]
    run(session.close())
    assert run(session.get("/FW/a.bin")) == data


def reads(fsdev) -> list:
    """The arguments of the READs the device received."""
    return [a for _, o, a in fsdev.commands if o == fsp.OPS["READ"]]


def writes(fsdev) -> list:
    """The arguments of the WRITEs the device received."""
    return [a for _, o, a in fsdev.commands if o == fsp.OPS["WRITE"]]


def test_write_to_in_pieces_with_progress(session, fsdev):
    data = bytes(range(200)) * 3                          # 600 B: 240, 240, 120
    run(session.openw("/w"))
    progress = []
    r = run(session.write_to(data, progress=progress.append))
    assert r.ok and r.op == fsp.OPS["WRITE"] and r.written == 600 and r.total == 600
    assert [len(a) for a in writes(fsdev)] == [240, 240, 120] and progress == [240, 480, 600]
    r = run(session.write_to(b"x"))
    assert r.written == 1 and r.total == 601, "total is the file's count, written this write's"
    run(session.close())
    assert fsdev.files["/FLASH_DISK:/w"] == data + b"x"
    with pytest.raises(ValueError):
        run(session.write_to(b""))


def test_write_to_stops_when_asked(session, fsdev):
    run(session.openw("/w"))
    progress = []
    r = run(session.write_to(bytes(1000), progress=progress.append, stop=lambda: len(progress) == 2))
    assert r.ok and r.written == 480 and len(writes(fsdev)) == 2
    assert run(session.write_to(bytes(520))).total == 1000, "the next write carries on"


def test_write_to_keeps_the_count_before_a_failure(session, fsdev):
    real = fsdev.handle

    def handle(payload):
        if payload[1] == fsp.OPS["WRITE"] and len(writes(fsdev)) == 2:
            fsdev.fail["WRITE"] = 4
        return real(payload)
    fsdev.handle = handle
    run(session.openw("/w"))
    r = run(session.write_to(bytes(1000)))
    assert not r.ok and r.status_name == "NO_SPACE" and r.written == 480
    assert r.closes_file and fsdev.open is None
    # Without an open file the first WRITE is refused, nothing written
    del fsdev.fail["WRITE"]
    r = run(session.write_to(b"abc"))
    assert r.status_name == "BAD_STATE" and r.written == 0


def test_read_to_the_end_from_the_position(session, fsdev):
    data = bytes(range(256)) * 3
    fsdev.files["/FLASH_DISK:/f"] = bytearray(data)
    run(session.openr("/f"))
    run(session.read(16))
    progress = []
    r = run(session.read_to(progress=progress.append))
    assert r.ok and r.eof and r.op == fsp.OPS["READ"] and r.data == data[16:]
    # 752 bytes: four READs with data, then one that finds the end
    assert reads(fsdev)[1:] == [b""] * 5 and progress == [239, 478, 717, 752]
    assert run(session.read_to()).data == b"" and run(session.read_to()).eof


def test_read_to_a_count(session, fsdev):
    fsdev.files["/FLASH_DISK:/f"] = bytearray(range(256)) * 4
    run(session.openr("/f"))
    r = run(session.read_to(300))
    assert r.data == bytes(range(256)) + bytes(range(44)) and not r.eof
    assert reads(fsdev) == [b"\xef\x00", b"\x3d\x00"], "239 then 61"
    r = run(session.read_to(5))
    assert r.data == bytes(range(44, 49)) and len(reads(fsdev)) == 3
    # More than is left: everything up to the end, and the end
    r = run(session.read_to(100000))
    assert len(r.data) == 1024 - 305 and r.eof
    with pytest.raises(ValueError):
        run(session.read_to(0))


def test_read_to_stops_when_asked(session, fsdev):
    fsdev.files["/FLASH_DISK:/f"] = bytearray(1000)
    run(session.openr("/f"))
    progress = []
    r = run(session.read_to(progress=progress.append, stop=lambda: len(progress) == 2))
    assert r.ok and not r.eof and len(r.data) == 478 and len(reads(fsdev)) == 2
    assert len(run(session.read_to()).data) == 1000 - 478, "the next read carries on"


def test_read_to_keeps_the_data_before_a_failure(session, fsdev):
    fsdev.files["/FLASH_DISK:/f"] = bytearray(b"x" * 600)
    real = fsdev.handle

    def handle(payload):
        if payload[1] == fsp.OPS["READ"] and len(reads(fsdev)) == 2:
            fsdev.fail["READ"] = 9
        return real(payload)
    fsdev.handle = handle
    run(session.openr("/f"))
    r = run(session.read_to())
    assert not r.ok and r.status_name == "IO" and r.data == b"x" * 478 and not r.eof
    assert r.closes_file and fsdev.open is None
    # Without an open file the first READ is refused, nothing read
    del fsdev.fail["READ"]
    r = run(session.read_to(10))
    assert r.status_name == "BAD_STATE" and r.data == b""


def test_session_sequence_numbers_increase_and_wrap(session, fsdev):
    session.seq = 254
    run(session.ls())
    run(session.ls())
    assert [c[0] for c in fsdev.commands] == [255, 0]
    # An empty name is refused, as by the firmware's path rules
    assert run(session.command("CD", b"/")).status_name == "BAD_ARG"
    assert run(session.command("OPENW", b"")).status_name == "BAD_ARG"


def test_session_ls(session, fsdev):
    fsdev.dirs.add("/FLASH_DISK:/FW")
    fsdev.files["/FLASH_DISK:/FW/FW1"] = bytearray(10)
    fsdev.files["/FLASH_DISK:/top"] = bytearray(3)
    entries = run(session.ls())
    assert [(e.path, e.is_dir, e.size) for e in entries] == [
        ("/FLASH_DISK:/FW", True, 0), ("/FLASH_DISK:/FW/FW1", False, 10), ("/FLASH_DISK:/top", False, 3)]


def test_session_errors_carry_the_status(session, fsdev):
    with pytest.raises(fsp.FsError, match="CD: NOT_FOUND") as e:
        run(session.cd("NONE"))
    assert (e.value.status, e.value.op) == (1, fsp.OPS["CD"])
    with pytest.raises(fsp.FsError, match="WRITE: BAD_STATE"):
        run(session.write(b"x"))
    with pytest.raises(ValueError):
        run(session.write(b""))
    r = run(session.command("DELFILE", b"nothing"))
    assert not r.ok and r.status_name == "NOT_FOUND"


def test_session_times_out_without_a_reply(session, fsdev):
    fsdev.silent = True
    with pytest.raises(fsp.FsError, match="LS: no reply"):
        run(session.ls())


def test_session_ignores_other_replies_and_stale_ones(session, fsdev):
    setu_cli = session.setu_cli
    setu_cli.short_q.put_nowait((fsp.APP_REPLY, bytes([99, 7, 0])))            # stale: dropped first

    real = setu_cli.send_short

    async def send_short(app_type, payload):
        # an unrelated message, a reply with another seq and broken frames come first
        setu_cli.short_q.put_nowait((0x11, b"\x00" * 9))
        setu_cli.short_q.put_nowait((fsp.APP_REPLY, bytes([payload[0] ^ 0xFF, payload[1], 0])))
        setu_cli.short_q.put_nowait((fsp.APP_REPLY, b"\x00"))
        setu_cli.short_q.put_nowait((fsp.APP_ENTRY, b"\x00"))
        setu_cli.short_q.put_nowait((fsp.APP_ENTRY, struct.pack("<BBI", payload[0] ^ 0xFF, 0, 1) + b"/x"))
        await real(app_type, payload)
    setu_cli.send_short = send_short
    assert run(session.ls()) == []


def test_get_and_put_abort_on_failure(session, fsdev):
    fsdev.files["/FLASH_DISK:/f"] = bytearray(b"abc")
    fsdev.fail["READ"] = 9
    with pytest.raises(fsp.FsError, match="READ: IO"):
        run(session.get("/f"))
    assert fsdev.commands[-1][1] == fsp.OPS["ABORT"]
    del fsdev.fail["READ"]
    fsdev.fail["WRITE"] = 4
    with pytest.raises(fsp.FsError, match="NO_SPACE"):
        run(session.put("/g", b"data"))
    assert fsdev.commands[-1][1] == fsp.OPS["ABORT"]
    del fsdev.fail["WRITE"]
    assert run(session.put("/g", b"data")) == 4 and fsdev.files["/FLASH_DISK:/g"] == b"data"
    progress = []
    assert run(session.get("/g", progress=progress.append)) == b"data" and progress == [4]


def test_put_failure_with_a_silent_abort(session, fsdev):
    fsdev.fail["WRITE"] = 9
    real = fsdev.handle

    def handle(payload):
        if payload[1] == fsp.OPS["ABORT"]:
            fsdev.silent = True
        return real(payload)
    fsdev.handle = handle
    with pytest.raises(fsp.FsError, match="WRITE: IO"):
        run(session.put("/h", b"x"))


# ---- what the CLI prints ------------------------------------------------------------------
def test_describe():
    assert fsp.describe(fsp.Reply(1, 2, 0, b"/FLASH_DISK:/FW")) == ["Directory active: /FLASH_DISK:/FW"]
    assert fsp.describe(fsp.Reply(1, 3, 0, b"/p")) == ["File opened: /p"]
    assert fsp.describe(fsp.Reply(1, 5, 0, struct.pack("<I", 9))) == ["Written, total 9 bytes"]
    assert fsp.describe(fsp.Reply(1, 6, 0)) == ["End of file reached"]
    assert fsp.describe(fsp.Reply(1, 6, 0, b"hi"))[0] == "Read 2 bytes:"
    assert fsp.describe(fsp.Reply(1, 6, 0, b"hi", eof=True))[0] == "Read 2 bytes, end of file:"
    assert fsp.describe(fsp.Reply(1, 6, 0, eof=True)) == ["End of file reached"]
    assert fsp.describe(fsp.Reply(1, 10, 0, struct.pack("<I", 9))) == ["File closed, 9 bytes written"]
    assert fsp.describe(fsp.Reply(1, 11, 0)) == ["ABORT: OK"]
    assert fsp.describe(fsp.Reply(1, 8, 1)) == ["DELFILE: NOT_FOUND"]
    ls = fsp.Reply(1, 7, 0, struct.pack("<H", 2),
                   [fsp.Entry(True, 0, "/FLASH_DISK:/FW"), fsp.Entry(False, 5, "/FLASH_DISK:/FW/a")])
    assert fsp.describe(ls) == ["[DIR]  /FLASH_DISK:/FW", "[FILE] /FLASH_DISK:/FW/a (5 bytes)", "2 entries"]


def test_run_cli(session, fsdev, tmp_path):
    out = []
    session.log = out.append
    run(fsp.run_cli(session, "mkdir", ["FW"]))
    run(fsp.run_cli(session, "openw", ["a.txt"]))
    run(fsp.run_cli(session, "write", ["hello", "world"]))
    run(fsp.run_cli(session, "write", [], hex_data="0d0a"))
    src = tmp_path / "src.bin"
    src.write_bytes(b"!")
    run(fsp.run_cli(session, "write", [], from_file=str(src)))
    run(fsp.run_cli(session, "close", []))
    assert fsdev.files["/FLASH_DISK:/FW/a.txt"] == b"hello world\r\n!"
    dst = tmp_path / "dst.bin"
    run(fsp.run_cli(session, "get", ["/FW/a.txt", str(dst)]))
    assert dst.read_bytes() == b"hello world\r\n!"
    run(fsp.run_cli(session, "put", [str(src), "/FW/b.bin"]))
    assert fsdev.files["/FLASH_DISK:/FW/b.bin"] == b"!"
    # read N, then read to the end of the file, over several READs
    fsdev.files["/FLASH_DISK:/FW/c.bin"] = bytearray(b"c" * 500)
    run(fsp.run_cli(session, "openr", ["c.bin"]))
    run(fsp.run_cli(session, "read", ["250"]))
    run(fsp.run_cli(session, "read", []))
    assert "Read 250 bytes:" in out and "Read 250 bytes, end of file:" in out
    run(fsp.run_cli(session, "close", []))
    with pytest.raises(fsp.FsError, match="READ: BAD_STATE"):
        run(fsp.run_cli(session, "read", []))
    assert "Directory active: /FLASH_DISK:/FW" in out and "Written, total 14 bytes" in out
    with pytest.raises(ValueError, match="get REMOTE LOCAL"):
        run(fsp.run_cli(session, "get", ["x"]))
    with pytest.raises(ValueError, match="put LOCAL REMOTE"):
        run(fsp.run_cli(session, "put", []))
    with pytest.raises(fsp.FsError):
        run(fsp.run_cli(session, "cd", ["NONE"]))


def test_shell_runs_harness_lines(session, fsdev):
    out = []
    session.log = out.append
    lines = iter(["help", "", "mkdir FW", "bogus", "openw x", "write abc", "close", "ls",
                  "openr x", "read 2", "read", "close", "quit", "ls"])

    async def read_line():
        return next(lines)
    run(fsp.shell(session, read_line))
    text = "\n".join(out)
    assert "  openw <path>" in text and "Unknown command: bogus" in text
    assert "Directory active: /FLASH_DISK:/FW" in text and "File closed, 3 bytes written" in text
    assert "[FILE] /FLASH_DISK:/FW/x (3 bytes)" in text
    assert "Read 2 bytes:" in text and "Read 1 bytes, end of file:" in text
    assert next(lines) == "ls", "quit ends the shell"


def test_shell_ends_at_eof(session):
    async def eof():
        raise EOFError
    run(fsp.shell(session, eof))

    async def none():
        return None
    run(fsp.shell(session, none))


# ---- a hex upload stored as a file ---------------------------------------------------------
def test_file_image_matches_the_device_file(vectors, repo):
    hf = vectors["hex_file"]
    segs = setu_client.parse_ihex(f"{repo}/AA00000100.hex")
    first = [s for s in segs if s[0] == hf["record"]["address"]][:1]
    a, d = first[0]
    image = setu_client.file_image([(a, d[:hf["record"]["length"]])])
    assert image[:8].hex() == hf["record"]["header_hex"]
    assert (len(image), zlib.crc32(image)) == (hf["record"]["file_size"], hf["record"]["file_crc32"])


@pytest.mark.parametrize("name, ok", [
    ("FW1", True), ("ECU_App-v1.2.3.bin", True), ("x" * 32, True), ("x" * 33, False), ("", False),
    (".", False), ("..", False), ("a/b", False), ("a b", False), ("UPLOAD.TMP", False), ("upload.tmp", False),
])
def test_valid_file_name(name, ok):
    assert setu_client.valid_file_name(name) is ok


class ShortClient(setu_client.SETUClient):
    """A SETUClient whose short messages reach a scripted FILE answer."""

    def __init__(self, answers):
        self.short_q = asyncio.Queue()
        self.sent = []
        self.answers = answers

    async def send_short(self, app_type, payload):
        self.sent.append(setu_client.frame(app_type, payload))
        for t, p in self.answers.get(app_type, []):
            self.short_q.put_nowait((t, p))


def test_begin_and_commit_use_the_golden_frames(vectors):
    hf = lambda n: frame_of(vec(vectors, "hex_file", n))      # noqa: E731
    c = ShortClient({setu_client.APP_TYPE_BEGIN: [(0x11, bytes(9)), hf("file_begin_ok")],
                     setu_client.APP_TYPE_COMMIT: [hf("file_begin_ok"), hf("file_commit_ok")]})
    c.short_q.put_nowait((setu_client.APP_TYPE_FILE, bytes(10)))         # stale: dropped
    rep = run(c.begin_file("FW1"))
    assert c.sent[0] == bytes.fromhex(vec(vectors, "hex_file", "begin_fw1")["hex"])
    assert rep.ok and (rep.op, rep.size, rep.crc) == (setu_client.APP_TYPE_BEGIN, 0, 0)
    rep = run(c.commit_file())
    assert c.sent[1] == bytes.fromhex(vec(vectors, "hex_file", "commit")["hex"])
    v = vec(vectors, "hex_file", "file_commit_ok")
    assert (rep.op, rep.status, rep.size, rep.crc) == (v["op"], v["status"], v["size"], v["crc32"])


@pytest.mark.parametrize("name, status", [("file_begin_busy", "BUSY"), ("file_begin_bad_name", "BAD_ARG"),
                                          ("file_commit_no_begin", "BAD_STATE"), ("file_commit_io", "IO")])
def test_file_reply_failures(vectors, name, status):
    v = vec(vectors, "hex_file", name)
    c = ShortClient({v["op"]: [frame_of(v)]})
    rep = run(c._file_request(v["op"], b""))
    assert not rep.ok and rep.status_name == status
    assert setu_client.FileReply(0x12, 99, 0, 0).status_name == "0x63"


def test_file_reply_timeout(monkeypatch):
    monkeypatch.setattr(setu_client, "FILE_TIMEOUT", 0.05)
    with pytest.raises(TimeoutError, match="no FILE reply to 0x13"):
        run(ShortClient({}).commit_file())
