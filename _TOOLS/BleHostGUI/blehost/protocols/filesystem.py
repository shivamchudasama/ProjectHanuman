"""The device's file commands over BLE (_DOC/FileSysManager/PROTOCOL.md).

The FileSystemPoC drove its File System Manager from a UART test harness;
here the same commands travel as SETU short messages on the host link:

    CMD   0x40  host -> device  [u8 seq][u8 op][arg]
    REPLY 0x41  device -> host  [u8 seq][u8 op][u8 status][data]
    ENTRY 0x42  device -> host  [u8 seq][u8 type][u32 LE size][path]  (LS only, before REPLY)

FileSystemSession runs them one at a time on a SETUClient (anything with
send_short and short_q). parse_line() reads the UART harness's command lines,
for the GUI's Files page and `setu_client.py fs shell`. A READ carries at most
READ_MAX bytes; read_to() (and `read [N]` on a command line) sends as many as it
takes to read N bytes or to the end of the file.
"""

import asyncio
import struct
import time
from dataclasses import dataclass, field

from .setu import setu_client, register_app_type

APP_CMD, APP_REPLY, APP_ENTRY = 0x40, 0x41, 0x42
APP_FIRST, APP_LAST = 0x40, 0x4F
OPS = {"MKDIR": 1, "CD": 2, "OPENR": 3, "OPENW": 4, "WRITE": 5, "READ": 6, "LS": 7,
       "DELFILE": 8, "DELDIR": 9, "CLOSE": 10, "ABORT": 11}
OP_NAMES = {v: k for k, v in OPS.items()}
STATUS = setu_client.FS_STATUS
ST_OK, ST_BAD_ARG, ST_BAD_STATE, ST_BUSY = 0, 5, 6, 7
ENTRY_FILE, ENTRY_DIR = 0, 1
SHORT_MAX = 242                                      # SETU short payload
ARG_MAX, READ_MAX, ENTRY_PATH_MAX = SHORT_MAX - 2, SHORT_MAX - 3, SHORT_MAX - 6
TIMEOUT = 15.0                                       # one command (flash work: erase, sync)

# Ops whose failure (other than the refusals below) closes the device's open file
_CLOSING_OPS = (OPS["WRITE"], OPS["READ"], OPS["CLOSE"])
_REFUSALS = (ST_BAD_ARG, ST_BAD_STATE, ST_BUSY)

# The UART harness's commands, in its help order: name -> (op, operand)
HARNESS = {
    "mkdir": ("MKDIR", "<path>"), "cd": ("CD", "<path>"), "openr": ("OPENR", "<path>"),
    "openw": ("OPENW", "<path>"), "write": ("WRITE", "<text payload>"), "read": ("READ", "[bytes]"),
    "ls": ("LS", ""), "delfile": ("DELFILE", "<path>"), "deldir": ("DELDIR", "<path>"),
    "close": ("CLOSE", ""), "abort": ("ABORT", ""),
}
HELP = ["FileSys commands:", "  help"] + [f"  {n} {a}".rstrip() for n, (_, a) in HARNESS.items()]
CLI_COMMANDS = list(HARNESS) + ["get", "put", "shell"]


def status_name(st: int) -> str:
    return STATUS.get(st, f"0x{st:02x}")


class FsError(Exception):
    """A command the device answered with a non-OK status (or not at all)."""

    def __init__(self, message: str, status: int = None, op: int = None):
        super().__init__(message)
        self.status, self.op = status, op


@dataclass
class Entry:
    """One listed entry."""
    is_dir: bool
    size: int
    path: str

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class Reply:
    """The REPLY that ends a command, with the ENTRYs of a listing."""
    seq: int
    op: int
    status: int
    data: bytes = b""
    entries: list = field(default_factory=list)
    eof: bool = False                     # read_to(): reading stopped at the end of the file

    @property
    def ok(self) -> bool:
        return self.status == ST_OK

    @property
    def status_name(self) -> str:
        return status_name(self.status)

    @property
    def op_name(self) -> str:
        return OP_NAMES.get(self.op, f"op {self.op}")

    @property
    def text(self) -> str:
        """A path in the data (MKDIR, CD, OPENR, OPENW)."""
        return self.data.decode("utf-8", "replace")

    @property
    def total(self) -> int:
        """Bytes written so far (WRITE, CLOSE)."""
        return struct.unpack("<I", self.data[:4])[0] if len(self.data) >= 4 else 0

    @property
    def count(self) -> int:
        """Entries listed (LS)."""
        return struct.unpack("<H", self.data[:2])[0] if len(self.data) >= 2 else 0

    @property
    def closes_file(self) -> bool:
        """Whether this failure also closed the device's open file."""
        return (not self.ok and self.op in _CLOSING_OPS and self.status not in _REFUSALS)


# ---- codecs ------------------------------------------------------------------------
def encode_cmd(seq: int, op: int, arg: bytes = b"") -> bytes:
    """CMD payload; the argument must fit (ARG_MAX)."""
    if len(arg) > ARG_MAX:
        raise ValueError(f"argument of {len(arg)} bytes, at most {ARG_MAX}")
    return bytes([seq & 0xFF, op]) + bytes(arg)


def encode_read(count: int = None) -> bytes:
    """READ's argument: none (as much as fits) or u16 LE count."""
    if count is None:
        return b""
    if not 0 <= count <= 0xFFFF:
        raise ValueError("read count must be 0..65535")
    return struct.pack("<H", count)


def decode_reply(payload: bytes) -> Reply:
    if len(payload) < 3:
        raise ValueError(f"REPLY of {len(payload)} bytes")
    return Reply(payload[0], payload[1], payload[2], bytes(payload[3:]))


def decode_entry(payload: bytes) -> tuple:
    """-> (seq, Entry)"""
    if len(payload) < 6:
        raise ValueError(f"ENTRY of {len(payload)} bytes")
    seq, etype, size = struct.unpack("<BBI", payload[:6])
    return seq, Entry(etype == ENTRY_DIR, size, payload[6:].decode("utf-8", "replace"))


def parse_line(line: str) -> tuple:
    """A UART harness command line -> (op, arg bytes), or ("help", b"").

    `read` is the exception: ("READ", count), count None (to the end of the
    file) or the positive number of bytes to read in all, for
    FileSystemSession.read_to(), which sends as many READs as that takes.
    Raises ValueError like the harness's own errors (unknown command, missing
    path or payload, bad read count).
    """
    line = line.strip()
    if not line:
        raise ValueError("empty command")
    name, _, rest = line.partition(" ")
    rest = rest.strip()
    if name == "help":
        return "help", b""
    if name not in HARNESS:
        raise ValueError(f"Unknown command: {name}")
    op, operand = HARNESS[name]
    if name == "read":
        if not rest:
            return op, None
        try:
            n = int(rest, 10)
        except ValueError:
            n = 0
        if n <= 0:
            raise ValueError("read expects optional positive byte count")
        return op, n
    if operand.startswith("<"):
        if not rest:
            raise ValueError(f"{name} requires a {'payload' if name == 'write' else 'path'}")
        arg = rest.encode("utf-8")
        if len(arg) > ARG_MAX:
            raise ValueError(f"{name}: at most {ARG_MAX} bytes")
        return op, arg
    return op, b""


def hexdump(data: bytes, width: int = 16) -> list:
    """Lines "0000: 41 42 ...  AB..", for showing read data."""
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:04x}: {chunk.hex(' '):<{width * 3 - 1}}  {text}")
    return out


# ---- traffic monitor ---------------------------------------------------------------
def _cmd(p: bytes) -> str:
    if len(p) < 2:
        return p.hex(" ")
    arg = p[2:]
    if p[1] == OPS["READ"]:
        shown = f" {struct.unpack('<H', arg)[0]}" if len(arg) == 2 else ""
    elif p[1] == OPS["WRITE"]:
        shown = f" {len(arg)} B"
    else:
        shown = f" {arg.decode('utf-8', 'replace')}" if arg else ""
    return f"seq={p[0]} {OP_NAMES.get(p[1], p[1])}{shown}"


def _reply(p: bytes) -> str:
    try:
        r = decode_reply(p)
    except ValueError:
        return p.hex(" ")
    return f"seq={r.seq} {r.op_name} {r.status_name}" + (f" {len(r.data)} B" if r.data else "")


def _entry(p: bytes) -> str:
    try:
        seq, e = decode_entry(p)
    except ValueError:
        return p.hex(" ")
    return f"seq={seq} {'DIR ' if e.is_dir else 'FILE'} {e.path}" + ("" if e.is_dir else f" {e.size} B")


register_app_type(APP_CMD, "FS_CMD", _cmd)
register_app_type(APP_REPLY, "FS_REPLY", _reply)
register_app_type(APP_ENTRY, "FS_ENTRY", _entry)


# ---- session -----------------------------------------------------------------------
class FileSystemSession:
    """Runs file commands one at a time. `setu_cli` needs send_short(app_type, payload)
    and short_q (an asyncio.Queue of (app_type, payload)), as SETUClient has."""

    def __init__(self, setu_cli, log=print, timeout: float = None):
        self.setu_cli = setu_cli
        self.log = log
        self.timeout = timeout                        # None: TIMEOUT, read at each command
        self.seq = 0

    async def command(self, op, arg: bytes = b"") -> Reply:
        """Send one CMD and return its REPLY (whatever the status) with its ENTRYs."""
        op = OPS[op] if isinstance(op, str) else op
        while not self.setu_cli.short_q.empty():               # replies of an earlier command
            self.setu_cli.short_q.get_nowait()
        self.seq = (self.seq + 1) & 0xFF
        seq = self.seq
        await self.setu_cli.send_short(APP_CMD, encode_cmd(seq, op, arg))
        entries = []
        deadline = time.perf_counter() + (TIMEOUT if self.timeout is None else self.timeout)
        while True:
            try:
                t, p = await asyncio.wait_for(self.setu_cli.short_q.get(),
                                              max(0.05, deadline - time.perf_counter()))
            except asyncio.TimeoutError:
                raise FsError(f"{OP_NAMES.get(op, op)}: no reply from the device", op=op) from None
            if t == APP_ENTRY:
                try:
                    eseq, e = decode_entry(bytes(p))
                except ValueError:
                    continue
                if eseq == seq:
                    entries.append(e)
            elif t == APP_REPLY:
                try:
                    r = decode_reply(bytes(p))
                except ValueError:
                    continue
                if r.seq == seq:
                    r.entries = entries
                    return r

    async def run(self, op, arg: bytes = b"") -> Reply:
        """command(), raising FsError unless the status is OK."""
        r = await self.command(op, arg)
        if not r.ok:
            raise FsError(f"{r.op_name}: {r.status_name}", r.status, r.op)
        return r

    # ---- the harness's commands ----------------------------------------------------
    async def mkdir(self, path: str) -> str:
        return (await self.run("MKDIR", path.encode())).text

    async def cd(self, path: str) -> str:
        return (await self.run("CD", path.encode())).text

    async def openr(self, path: str) -> str:
        return (await self.run("OPENR", path.encode())).text

    async def openw(self, path: str) -> str:
        return (await self.run("OPENW", path.encode())).text

    async def write(self, data: bytes) -> int:
        """Write any length, ARG_MAX bytes per command; returns the file's byte count."""
        if not data:
            raise ValueError("nothing to write")
        total = 0
        for i in range(0, len(data), ARG_MAX):
            total = (await self.run("WRITE", data[i:i + ARG_MAX])).total
        return total

    async def read(self, count: int = None) -> bytes:
        """Up to READ_MAX bytes; b"" at the end of the file."""
        return (await self.run("READ", encode_read(count))).data

    async def read_to(self, count: int = None, progress=None, stop=None) -> Reply:
        """Read the open file from its position: `count` bytes, or to its end (None),
        READ_MAX bytes per READ. Ends early at the end of the file (eof), at a failed
        READ (its status, with the data read before it) or when stop() is true
        (checked between READs). Returns the last READ's Reply, its data everything
        read; progress(bytes so far) follows each READ that brought data."""
        if count is not None and count <= 0:
            raise ValueError("read count must be positive")
        data = bytearray()
        while True:
            left = None if count is None else count - len(data)
            r = await self.command("READ", encode_read(None if left is None else min(left, READ_MAX)))
            if not r.ok:
                break
            if not r.data:
                r.eof = True
                break
            data += r.data
            if progress:
                progress(len(data))
            if (count is not None and len(data) >= count) or (stop and stop()):
                break
        r.data = bytes(data)
        return r

    async def ls(self) -> list:
        return (await self.run("LS")).entries

    async def delfile(self, path: str):
        await self.run("DELFILE", path.encode())

    async def deldir(self, path: str):
        await self.run("DELDIR", path.encode())

    async def close(self) -> int:
        return (await self.run("CLOSE")).total

    async def abort(self):
        await self.run("ABORT")

    # ---- whole files -----------------------------------------------------------------
    async def get(self, path: str, progress=None) -> bytes:
        """Read a whole file (openr, read to the end, close)."""
        await self.openr(path)
        try:
            r = await self.read_to(progress=progress)
            if not r.ok:
                raise FsError(f"{r.op_name}: {r.status_name}", r.status, r.op)
        except BaseException:
            await self._abort_quietly()
            raise
        await self.close()
        return r.data

    async def put(self, path: str, data: bytes) -> int:
        """Write a whole file (openw, write, close). The device does not truncate:
        delete the file first to replace a longer one."""
        await self.openw(path)
        try:
            await self.write(data)
        except BaseException:
            await self._abort_quietly()
            raise
        return await self.close()

    async def _abort_quietly(self):
        try:
            await self.command("ABORT")
        except Exception:                                # noqa: BLE001 - best effort
            pass


# ---- command line ------------------------------------------------------------------
def describe(r: Reply) -> list:
    """Lines for a REPLY, as the harness would have logged them."""
    if not r.ok:
        return [f"{r.op_name}: {r.status_name}"]
    if r.op in (OPS["MKDIR"], OPS["CD"]):
        return [f"Directory active: {r.text}"]
    if r.op in (OPS["OPENR"], OPS["OPENW"]):
        return [f"File opened: {r.text}"]
    if r.op == OPS["WRITE"]:
        return [f"Written, total {r.total} bytes"]
    if r.op == OPS["READ"]:
        if not r.data:
            return ["End of file reached"]
        return [f"Read {len(r.data)} bytes{', end of file' if r.eof else ''}:"] + hexdump(r.data)
    if r.op == OPS["LS"]:
        lines = [f"{'[DIR] ' if e.is_dir else '[FILE]'} {e.path}" + ("" if e.is_dir else f" ({e.size} bytes)")
                 for e in r.entries]
        return lines + [f"{r.count} entries"]
    if r.op == OPS["CLOSE"]:
        return [f"File closed, {r.total} bytes written"]
    return [f"{r.op_name}: OK"]


async def run_cli(session: FileSystemSession, sub: str, rest: list, hex_data=None, from_file=None):
    """`setu_client.py fs SUB ...` (not shell)."""
    log = session.log
    if sub == "get":
        if len(rest) != 2:
            raise ValueError("get REMOTE LOCAL")
        data = await session.get(rest[0])
        with open(rest[1], "wb") as f:
            f.write(data)
        log(f"{rest[0]}: {len(data)} bytes -> {rest[1]}")
        return
    if sub == "put":
        if len(rest) != 2:
            raise ValueError("put LOCAL REMOTE")
        with open(rest[0], "rb") as f:
            data = f.read()
        n = await session.put(rest[1], data)
        log(f"{rest[0]} -> {rest[1]}: {n} bytes")
        return
    if sub == "write":
        if hex_data is not None:
            data = bytes.fromhex(hex_data)
        elif from_file is not None:
            with open(from_file, "rb") as f:
                data = f.read()
        else:
            data = " ".join(rest).encode("utf-8")
        log(f"Written, total {await session.write(data)} bytes")
        return
    op, arg = parse_line(" ".join([sub] + list(rest)))
    if op == "READ":
        r = await session.read_to(arg)
        if not r.ok:
            raise FsError(f"{r.op_name}: {r.status_name}", r.status, r.op)
    else:
        r = await session.run(op, arg)
    for line in describe(r):
        log(line)


async def shell(session: FileSystemSession, read_line=None):
    """The UART harness, over BLE: one command line at a time until EOF or quit."""
    log = session.log
    if read_line is None:
        loop = asyncio.get_running_loop()

        async def read_line():
            return await loop.run_in_executor(None, input, "fs> ")
    log("FileSysManager over BLE. Type 'help'; 'quit' or end of input leaves.")
    while True:
        try:
            line = await read_line()
        except EOFError:
            return
        if line is None or line.strip() in ("quit", "exit"):
            return
        if not line.strip():
            continue
        try:
            op, arg = parse_line(line)
        except ValueError as e:
            log(str(e))
            continue
        if op == "help":
            for h in HELP:
                log(h)
            continue
        r = await (session.read_to(arg) if op == "READ" else session.command(op, arg))
        for out in describe(r):
            log(out)
