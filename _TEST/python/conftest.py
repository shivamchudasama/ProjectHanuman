# SPDX-License-Identifier: MIT
"""Shared fixtures for the PC-tool tests.

Puts _TOOLS/BleHostGUI on sys.path (setu_client.py and the blehost
package live there) and provides the golden wire vectors shared with the C
tests, plus a fake GATT transport and a scripted SETU server so that
SETUClient can be tested without a BLE adapter, and one shared Tk root
for the tests that build widgets.
"""

import asyncio
import json
import os
import struct
import sys
import zlib

import pytest

REPO = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
GUI_DIR = os.path.join(REPO, "_TOOLS", "BleHostGUI")
if GUI_DIR not in sys.path:
    sys.path.insert(0, GUI_DIR)

import setu_client  # noqa: E402


@pytest.fixture(scope="session")
def repo():
    return REPO


@pytest.fixture(scope="session")
def vectors():
    with open(os.path.join(REPO, "_TEST", "vectors", "wire.json")) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def _tk_session():
    """One Tk interpreter for the whole run: on Windows, creating several in
    one process now and then fails to find tk.tcl. None without a display."""
    try:
        import tkinter as tk
        root = tk.Tk()
    except Exception as e:                       # ImportError, TclError
        yield e
        return
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def tk_root(_tk_session):
    """The shared Tk root (skips without a display); widgets a test creates
    on it are destroyed after the test."""
    if isinstance(_tk_session, Exception):
        pytest.skip(f"no display for Tk ({_tk_session})")
    yield _tk_session
    for w in _tk_session.winfo_children():
        w.destroy()


class FakeServer:
    """Scripted SETU Server on the far side of a fake GATT link.

    Implements the receiver half of the protocol (ACK every window/2 frames,
    NACK on a gap, END with a CRC check) closely enough to exercise the client,
    plus knobs to misbehave. `writes` records every frame the client wrote.
    """

    def __init__(self, mtu=247, window=16):
        self.mtu_size = mtu
        self.window = window
        self.writes = []
        self.client = None                      # SETUClient, set by the test
        self.caps = bytes([2, 244, 16, 0])
        # knobs
        self.silent = False                     # never answer
        self.reject = None                      # status: answer START with ABORT(by receiver)
        self.drop_once = None                   # absolute frame index to lose once
        self.after_end = []                     # short frames (type, payload) to notify after END OK
        self.corrupt = False                    # END with CRC_ERROR
        # receiver state
        self.xid = None
        self.buf = bytearray()
        self.total = 0
        self.chunk = 0
        self.nxt = 0
        self.since_ack = 0
        self.nack_sent = False
        self.objects = []                       # (app_type, bytes) received OK
        self.aborted = None                     # (xid, reason, dir) of the client's ABORT

    # --- the three things SETUClient needs from bleak's BleakClient ----
    async def write_gatt_char(self, uuid, data, response=False):
        assert uuid == self.client.data_uuid, "client must write DATA"
        assert response is False, "client must use Write Without Response"
        data = bytes(data)
        assert len(data) <= self.mtu_size - 3
        self.writes.append(data)
        self._on_frame(data)
        await asyncio.sleep(0)

    async def read_gatt_char(self, uuid):
        assert uuid == self.client.caps_uuid
        return bytearray(self.caps)

    # --- receiver --------------------------------------------------------------
    def _notify(self, payload: bytes):
        self.client.on_notify(0, bytearray(payload))

    def _on_frame(self, f: bytes):
        if self.silent:
            return
        ftype, p = f[1], f[2:]
        if ftype == setu_client.T_START:
            xid, app, total, chunk, win, crc = struct.unpack("<BBIBBI", p)
            self.xid, self.app, self.total, self.chunk, self.crc = xid, app, total, chunk, crc
            self.buf, self.nxt, self.since_ack, self.nack_sent = bytearray(), 0, 0, False
            if self.reject is not None:
                self._notify(setu_client.frame(setu_client.T_ABORT, bytes([xid, self.reject, setu_client.ABORT_BY_RECEIVER])))
                return
            if total == 0:
                self._end()
                return
            self._notify(setu_client.frame(setu_client.T_ACK, bytes([xid, 0, min(win, self.window)])))
        elif ftype == setu_client.T_DATA and p[0] == self.xid:
            seq, data = p[1], p[2:]
            if seq == (self.nxt & 0xFF):
                if self.drop_once == self.nxt:
                    self.drop_once = None
                    return
                self.buf += data
                self.nxt += 1
                self.since_ack += 1
                self.nack_sent = False
                if len(self.buf) >= self.total:
                    self._end()
                elif self.since_ack >= self.window // 2:
                    self.since_ack = 0
                    self._notify(setu_client.frame(setu_client.T_ACK, bytes([self.xid, self.nxt & 0xFF, self.window])))
            elif not self.nack_sent:
                self.nack_sent = True
                self._notify(setu_client.frame(setu_client.T_NACK, bytes([self.xid, self.nxt & 0xFF, 11])))
        elif ftype == setu_client.T_ABORT:
            self.aborted = (p[0], p[1], p[2])

    def _end(self):
        ok = zlib.crc32(bytes(self.buf)) == self.crc and not self.corrupt
        self._notify(setu_client.frame(setu_client.T_END, bytes([self.xid, 0 if ok else 1])))
        if ok:
            self.objects.append((self.app, bytes(self.buf)))
            for t, payload in self.after_end:
                self._notify(setu_client.frame(t, payload))


@pytest.fixture
def server():
    return FakeServer()


@pytest.fixture
def client(server):
    c = setu_client.SETUClient(server, log=lambda *_: None)
    server.client = c
    return c


@pytest.fixture
def fast_timeouts(monkeypatch):
    """Shrink the client's 1 s ACK timeout so timeout paths run quickly."""
    monkeypatch.setattr(setu_client, "ACK_TIMEOUT", 0.02)


class FakeFsDevice:
    """The device's file commands (_DOC/FileSysManager/PROTOCOL.md) and the
    hex upload's BEGIN / COMMIT, scripted in Python with the firmware's rules:
    paths ("/FLASH_DISK:/x" as is, "/x" from the root, a relative directory
    from the root and a relative file from the current directory), one open
    file, opening for writing does not truncate, LS lists the root and one
    level, DELDIR deletes files but refuses subdirectories, an ABORT without an
    open file resets the current directory. handle() returns the notifications
    as (appType, payload). Knobs: busy, silent, fail (op name -> status)."""

    ROOT = "/FLASH_DISK:"
    OPS = {"MKDIR": 1, "CD": 2, "OPENR": 3, "OPENW": 4, "WRITE": 5, "READ": 6, "LS": 7,
           "DELFILE": 8, "DELDIR": 9, "CLOSE": 10, "ABORT": 11}
    OK, NOT_FOUND, BAD_ARG, BAD_STATE, BUSY, NOT_SUPPORTED, WRONG_TYPE = 0, 1, 5, 6, 7, 10, 11

    def __init__(self):
        self.files = {}                       # path -> bytearray
        self.dirs = set()
        self.cwd = self.ROOT
        self.open = None                      # [path, mode, position, written]
        self.busy = False
        self.silent = False
        self.fail = {}
        self.commands = []                    # (seq, op, arg) received
        self.upload = None                    # bytearray between BEGIN and COMMIT
        self.upload_name = None

    def _path(self, arg: bytes, is_dir: bool) -> str:
        name = arg.decode()
        if name.startswith("/") and ":" in name:
            return name
        if name.startswith("/"):
            return f"{self.ROOT}/{name[1:]}"
        return f"{self.ROOT if is_dir else self.cwd}/{name}"

    def _parent_ok(self, path: str) -> bool:
        parent = path.rsplit("/", 1)[0]
        return parent == self.ROOT or parent in self.dirs

    def _children(self, d: str):
        for p in sorted(self.dirs | set(self.files)):
            if p.rsplit("/", 1)[0] == d:
                yield p

    def handle(self, payload: bytes) -> list:
        seq, op, arg = payload[0], payload[1], bytes(payload[2:])
        self.commands.append((seq, op, arg))

        def reply(st, data=b""):
            return [(0x41, bytes([seq, op, st]) + data)]

        if self.silent:
            return []
        if self.busy:
            return reply(self.BUSY)
        name = next((k for k, v in self.OPS.items() if v == op), None)
        if name is None:
            return reply(self.BAD_ARG)
        if name in self.fail:
            if name in ("WRITE", "READ", "CLOSE"):
                self.open = None
            return reply(self.fail[name])
        o = self.open
        if name in ("WRITE", "READ") and o is None:
            return reply(self.BAD_STATE)
        if o is not None and name not in ("WRITE", "READ", "CLOSE", "ABORT"):
            return reply(self.BAD_STATE)
        if name in ("MKDIR", "CD", "OPENR", "OPENW", "DELFILE", "DELDIR") and arg.lstrip(b"/") == b"":
            return reply(self.BAD_ARG)
        if name in ("MKDIR", "CD"):
            p = self._path(arg, True)
            if name == "MKDIR":
                if not self._parent_ok(p):
                    return reply(self.NOT_FOUND)
                self.dirs.add(p)
            elif p not in self.dirs and p != self.ROOT:
                return reply(self.NOT_FOUND if p not in self.files else self.WRONG_TYPE)
            self.cwd = p
            return reply(self.OK, p.encode())
        if name in ("OPENR", "OPENW"):
            p = self._path(arg, False)
            if name == "OPENR" and p not in self.files:
                return reply(self.NOT_FOUND)
            if name == "OPENW":
                if not self._parent_ok(p):
                    return reply(self.NOT_FOUND)
                self.files.setdefault(p, bytearray())
            self.open = [p, name, 0, 0]
            return reply(self.OK, p.encode())
        if name == "WRITE":
            if o[1] != "OPENW":
                return reply(self.BAD_STATE)
            if not arg:
                return reply(self.BAD_ARG)
            f = self.files[o[0]]
            f[o[2]:o[2] + len(arg)] = arg
            o[2] += len(arg)
            o[3] += len(arg)
            return reply(self.OK, struct.pack("<I", o[3]))
        if name == "READ":
            if o[1] != "OPENR":
                return reply(self.BAD_STATE)
            n = struct.unpack("<H", arg)[0] if len(arg) == 2 else 239
            n = 239 if n == 0 or n > 239 else n
            data = bytes(self.files[o[0]][o[2]:o[2] + n])
            o[2] += len(data)
            return reply(self.OK, data)
        if name == "LS":
            out, n = [], 0
            for p in self._children(self.ROOT):
                for q in [p] + (list(self._children(p)) if p in self.dirs else []):
                    is_dir = q in self.dirs
                    size = 0 if is_dir else len(self.files[q])
                    out.append((0x42, struct.pack("<BBI", seq, 1 if is_dir else 0, size) + q.encode()))
                    n += 1
            return out + reply(self.OK, struct.pack("<H", n))
        if name in ("DELFILE", "DELDIR"):
            p = self._path(arg, name == "DELDIR")
            if name == "DELFILE":
                if p in self.dirs:
                    return reply(self.WRONG_TYPE)
                if p not in self.files:
                    return reply(self.NOT_FOUND)
                del self.files[p]
                return reply(self.OK)
            if p not in self.dirs:
                return reply(self.NOT_FOUND if p not in self.files else self.WRONG_TYPE)
            kids = list(self._children(p))
            if any(k in self.dirs for k in kids):
                return reply(self.NOT_SUPPORTED)
            for k in kids:
                del self.files[k]
            self.dirs.discard(p)
            return reply(self.OK)
        if name == "CLOSE":
            total = o[3] if o is not None else 0
            self.open = None
            return reply(self.OK, struct.pack("<I", total))
        # ABORT
        if o is None:
            self.cwd = self.ROOT
        self.open = None
        return reply(self.OK)

    # ---- hex upload stored as a file ------------------------------------------------
    def begin(self, name: bytes) -> tuple:
        if self.busy:
            return (0x14, struct.pack("<BBII", 0x12, self.BUSY, 0, 0))
        self.upload, self.upload_name = bytearray(), name.decode()
        return (0x14, struct.pack("<BBII", 0x12, self.OK, 0, 0))

    def segment(self, obj: bytes):
        if self.upload is not None:
            self.upload += struct.pack("<II", struct.unpack("<I", obj[:4])[0], len(obj) - 4) + obj[4:]

    def commit(self) -> tuple:
        if self.upload is None:
            return (0x14, struct.pack("<BBII", 0x13, self.BAD_STATE, 0, 0))
        data, self.upload = bytes(self.upload), None
        self.files[f"{self.ROOT}/FW/{self.upload_name}"] = bytearray(data)
        return (0x14, struct.pack("<BBII", 0x13, self.OK, len(data), zlib.crc32(data)))


class FakeSETU:
    """What FileSystemSession needs from a SETUClient: send_short and
    short_q, wired to a FakeFsDevice."""

    def __init__(self, device: FakeFsDevice):
        self.device = device
        self.short_q = asyncio.Queue()
        self.sent = []

    async def send_short(self, app_type: int, payload: bytes):
        self.sent.append((app_type, bytes(payload)))
        if app_type == 0x40:
            for t, p in self.device.handle(bytes(payload)):
                self.short_q.put_nowait((t, p))
        await asyncio.sleep(0)


@pytest.fixture
def fsdev():
    return FakeFsDevice()


# ---- UDS -----------------------------------------------------------------------------
ECUSIM_DIR = os.path.join(REPO, "_TOOLS", "EcuSim")
if ECUSIM_DIR not in sys.path:
    sys.path.insert(0, ECUSIM_DIR)


class FakeUdsDevice:
    """UDS over BLE (_DOC/UDS/PROTOCOL.md) with the firmware's rules, in Python:
    TARGET is stored, DIAG_REQ and UNLOCK go to an EcuSim (the ECU on the bus;
    _TOOLS/EcuSim) with the device's own BENCH_XOR key, and FLASH runs the
    parameterised programming sequence against it on a stored file, reporting
    STATUS at each step. handle() returns the notifications as (appType,
    payload). Knobs: target_status, silent (no DIAG answer: TIMEOUT)."""

    PART = 236

    def __init__(self, ecu=None):
        from ecu_sim import EcuSim
        self.ecu = ecu or EcuSim()
        self.files = {}                       # name -> the stored file (records)
        self.target = None
        self.target_status = 0
        self.silent = False
        self.status = bytes(15)               # STATUS payload of the last job
        self.received = []                    # (appType, payload)

    # ---- UDS on the bus --------------------------------------------------------------
    def _uds(self, req: bytes):
        """The ECU's final response, or None."""
        rsps = [r for _, r in self.ecu.handle(bytes(req))]
        rsps = [r for r in rsps if not (len(r) == 3 and r[0] == 0x7F and r[2] == 0x78)]
        return rsps[-1] if rsps else None

    def _diag_rsp(self, seq, req, functional=False):
        if self.target is None:
            return [(0x53, struct.pack("<BBHH", seq, 4, 0, 0))]
        from ecu_sim import SUB_FUNCTION_SIDS
        rsp = None if self.silent else self._uds(req)
        if rsp is None:
            suppressed = req[0] in SUB_FUNCTION_SIDS and len(req) >= 2 and bool(req[1] & 0x80)
            st = 0 if (functional or suppressed) and not self.silent else 6
            return [(0x53, struct.pack("<BBHH", seq, st, 0, 0))]
        st = 5 if rsp[0] == 0x7F else 0
        return [(0x53, struct.pack("<BBHH", seq, st, len(rsp), off) + rsp[off:off + self.PART])
                for off in range(0, len(rsp), self.PART)]

    def _unlock(self, level, algo):
        from ecu_sim import bench_xor
        if algo != 0x01:
            return 11, b""
        seed = self._uds(bytes([0x27, level]))
        if seed is None or seed[0] == 0x7F:
            return (5, seed[2:3]) if seed else (6, b"")
        if not any(seed[2:]):
            return 0, b""
        rsp = self._uds(bytes([0x27, level + 1]) + bench_xor(level, seed[2:]))
        return (5, rsp[2:3]) if rsp is None or rsp[0] == 0x7F else (0, b"")

    def _flash(self, params, name):
        """The device's flash job; returns the STATUS payloads."""
        from blehost.protocols import uds
        out = []
        state = {"step": 0, "rec": 0, "cnt": 0, "done": 0, "total": 0, "sid": 0, "nrc": 0}

        def status(st, result=0):
            p = struct.pack("<BBBBIIBBB", st, state["step"], state["rec"], state["cnt"], state["done"],
                            state["total"], state["sid"], state["nrc"], result)
            out.append((0x56, p))
            self.status = p

        def step(n, req):
            state["step"], state["sid"] = n, req[0]
            status(1)
            rsp = self._uds(req)
            if rsp is None:
                status(3, 6)
                return False
            if rsp[0] == 0x7F:
                state["nrc"] = rsp[2]
                status(3, 5)
                return False
            return rsp

        data = self.files.get(name)
        if data is None:
            status(3, 9)
            return out
        recs, i = [], 0
        while i < len(data):
            addr, n = struct.unpack("<II", data[i:i + 8])
            recs.append((addr, data[i + 8:i + 8 + n]))
            i += 8 + n
        state["cnt"], state["total"] = len(recs), sum(len(d) for _, d in recs)
        f, ff = params.flags, uds.FF
        al = params.alfid
        crc = 0
        for _, d in recs:
            crc = zlib.crc32(d, crc)
        seq = []
        if f & ff["EXT_SESSION"]:
            seq.append((1, b"\x10\x03"))
        if f & ff["DTC_OFF"]:
            seq.append((2, b"\x85\x02"))
        if f & ff["COMM_OFF"]:
            seq.append((3, bytes([0x28, params.comm_control, params.comm_type])))
        seq.append((4, b"\x10\x02"))
        for n, req in seq:
            if step(n, req) is False:
                return out
        if f & ff["SECURITY"]:
            state["step"], state["sid"] = 5, 0x27
            st, nrc = self._unlock(params.security_level, params.key_algo)
            if st:
                state["nrc"] = nrc[0] if nrc else 0
                status(3, st)
                return out
        if f & ff["FINGERPRINT"]:
            if step(6, b"\x2e" + struct.pack(">H", params.fingerprint_did) + params.fingerprint) is False:
                return out
        if f & ff["ERASE"] and not f & ff["ERASE_PER_RECORD"]:
            if step(7, b"\x31\x01" + struct.pack(">H", params.erase_rid)) is False:
                return out
        for idx, (addr, d) in enumerate(recs):
            state["rec"] = idx
            al_bytes = (addr.to_bytes(al & 0xF, "big") + len(d).to_bytes(al >> 4, "big"))
            if f & ff["ERASE_PER_RECORD"]:
                if step(7, b"\x31\x01" + struct.pack(">H", params.erase_rid) + bytes([al]) + al_bytes) is False:
                    return out
            rsp = step(8, bytes([0x34, params.dfi, al]) + al_bytes)
            if rsp is False:
                return out
            block = int.from_bytes(rsp[2:2 + (rsp[1] >> 4)], "big") - 2
            bsc = 1
            for off in range(0, len(d), block):
                if step(9, bytes([0x36, bsc]) + d[off:off + block]) is False:
                    return out
                state["done"] += len(d[off:off + block])
                bsc = (bsc + 1) & 0xFF
            if step(10, b"\x37") is False:
                return out
        state["rec"] = len(recs)
        if f & ff["CHECK"]:
            args = struct.pack(">I", crc & 0xFFFFFFFF) if f & ff["CHECK_CRC"] else b""
            if step(11, b"\x31\x01" + struct.pack(">H", params.check_rid) + args) is False:
                return out
        if f & ff["RESET"]:
            if step(12, bytes([0x11, params.reset_type])) is False:
                return out
        state["step"] = 13
        status(2)
        return out

    def handle(self, app_type: int, p: bytes) -> list:
        from blehost.protocols import uds
        self.received.append((app_type, bytes(p)))
        seq = p[0]
        if app_type == 0x50:
            _, self.target = uds.Target.decode(bytes(p))
            return [(0x51, bytes([seq, 0x50, self.target_status]))]
        if app_type == 0x52:
            return self._diag_rsp(seq, bytes(p[2:]), bool(p[1] & 1))
        if app_type == 0x54:
            if self.target is None:
                return [(0x51, bytes([seq, 0x54, 4]))]
            st, data = self._unlock(p[1], p[2])
            return [(0x51, bytes([seq, 0x54, st]) + data)]
        if app_type == 0x55:
            if self.target is None:
                return [(0x51, bytes([seq, 0x55, 4]))]
            params = uds.FlashParams.decode(bytes(p[1:35]))
            name = bytes(p[36:36 + p[35]]).decode()
            return [(0x51, bytes([seq, 0x55, 0]))] + self._flash(params, name)
        if app_type == 0x57:
            return [(0x51, bytes([seq, 0x57, 3]))]
        if app_type == 0x58:
            return [(0x56, self.status)]
        return []


class FakeUdsSETU:
    """What UdsSession needs from a SETUClient, wired to a FakeUdsDevice."""

    def __init__(self, device: FakeUdsDevice):
        self.device = device
        self.short_q = asyncio.Queue()
        self.sent = []

    async def send_short(self, app_type: int, payload: bytes):
        self.sent.append((app_type, bytes(payload)))
        for t, p in self.device.handle(app_type, bytes(payload)):
            self.short_q.put_nowait((t, p))
        await asyncio.sleep(0)


@pytest.fixture
def udsdev():
    return FakeUdsDevice()
