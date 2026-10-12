"""UDS on the device over BLE (_DOC/UDS/PROTOCOL.md).

The device runs UDS (ISO 14229) over ISO-TP on its CAN bus; the host only tells it
what to do, with SETU short messages on the host link:

    TARGET     0x50  host -> device  [seq][flags][u32 bitrate][u32 data bitrate][u32 tx id]
                                     [u32 rx id][u32 func id][ext addr][tx dl][pad][u16 P2][u16 P2*]
    RESULT     0x51  device -> host  [seq][ref appType][status][data]
    DIAG_REQ   0x52  host -> device  [seq][flags][UDS request]
    DIAG_RSP   0x53  device -> host  [seq][status][u16 total][u16 offset][part]
    UNLOCK     0x54  host -> device  [seq][level][algo]
    FLASH      0x55  host -> device  [seq][params (34 bytes)][u8 name length][name]
    STATUS     0x56  device -> host  [state][step][rec idx][rec cnt][u32 done][u32 total][SID][NRC][status]
    ABORT      0x57  host -> device  [seq]
    STATUS_REQ 0x58  host -> device  [seq]

Numbers are little-endian. UdsSession runs them on a SETUClient (anything with
send_short and short_q). load_profile() reads a JSON profile (target + flash
parameters), save_profile() writes one, see _TOOLS/EcuSim/profiles/sim.json and
_DOC/UDS/README.md. NRC_NAMES / describe_response() name the ECU's negative
responses.
"""

import asyncio
import json
import re
import struct
import time
from dataclasses import dataclass

from .setu import register_app_type

APP_TARGET, APP_RESULT, APP_DIAG_REQ, APP_DIAG_RSP = 0x50, 0x51, 0x52, 0x53
APP_UNLOCK, APP_FLASH, APP_STATUS, APP_ABORT, APP_STATUS_REQ = 0x54, 0x55, 0x56, 0x57, 0x58
APP_FIRST, APP_LAST = 0x50, 0x5F
APP_NAMES = {APP_TARGET: "TARGET", APP_RESULT: "RESULT", APP_DIAG_REQ: "DIAG_REQ", APP_DIAG_RSP: "DIAG_RSP",
             APP_UNLOCK: "UNLOCK", APP_FLASH: "FLASH", APP_STATUS: "STATUS", APP_ABORT: "ABORT",
             APP_STATUS_REQ: "STATUS_REQ"}

STATUS = {0: "OK", 1: "BUSY", 2: "BAD_ARG", 3: "BAD_STATE", 4: "NOT_READY", 5: "NRC", 6: "TIMEOUT",
          7: "TRANSPORT", 8: "BUS_OFF", 9: "FILE", 10: "ABORTED", 11: "NOT_SUPPORTED"}
ST_OK, ST_NRC = 0, 5
STATES = {0: "IDLE", 1: "RUNNING", 2: "DONE", 3: "FAILED", 4: "ABORTED"}
STATE_RUNNING = 1
STEPS = {0: "NONE", 1: "EXT_SESSION", 2: "DTC_OFF", 3: "COMM_OFF", 4: "PROG_SESSION", 5: "SECURITY",
         6: "FINGERPRINT", 7: "ERASE", 8: "DOWNLOAD", 9: "TRANSFER", 10: "EXIT", 11: "CHECK", 12: "RESET",
         13: "DONE"}

TF_EXT_ID, TF_FD, TF_BRS, TF_PAD, TF_EXT_ADDR, TF_FUNC = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
DF_FUNCTIONAL = 0x01
FF = {"EXT_SESSION": 0x0001, "DTC_OFF": 0x0002, "COMM_OFF": 0x0004, "SECURITY": 0x0008, "FINGERPRINT": 0x0010,
      "ERASE": 0x0020, "ERASE_PER_RECORD": 0x0040, "CHECK": 0x0080, "CHECK_CRC": 0x0100, "RESET": 0x0200}
ALGOS = {"NONE": 0x00, "BENCH_XOR": 0x01}

TARGET_LEN, PARAMS_LEN, STATUS_LEN = 29, 34, 15
FP_MAX, NAME_MAX = 16, 32
SHORT_MAX = 242
DIAG_REQ_MAX = SHORT_MAX - 2
DIAG_PART_MAX = SHORT_MAX - 6
PAD_BYTE = 0xCC

TIMEOUT_TARGET = 5.0
TIMEOUT_DIAG = 30.0                                   # P2* after NRC 0x78, several times
TIMEOUT_UNLOCK = 30.0
STATUS_SILENCE = 10.0                                 # flash: ask for the status after this

FILE_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,32}")    # a FLASH file name (PROTOCOL.md, FLASH)

# ISO 14229-1 negative response codes
NRC_NAMES = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat", 0x14: "responseTooLong", 0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect", 0x24: "requestSequenceError", 0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction", 0x31: "requestOutOfRange", 0x33: "securityAccessDenied",
    0x35: "invalidKey", 0x36: "exceededNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted", 0x71: "transferDataSuspended", 0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter", 0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession", 0x7F: "serviceNotSupportedInActiveSession",
    0x81: "rpmTooHigh", 0x82: "rpmTooLow", 0x83: "engineIsRunning", 0x84: "engineIsNotRunning",
    0x85: "engineRunTimeTooLow", 0x86: "temperatureTooHigh", 0x87: "temperatureTooLow",
    0x88: "vehicleSpeedTooHigh", 0x89: "vehicleSpeedTooLow", 0x8A: "throttleTooHigh", 0x8B: "throttleTooLow",
    0x8C: "transmissionRangeNotInNeutral", 0x8D: "transmissionRangeNotInGear", 0x8F: "brakeSwitchNotClosed",
    0x90: "shifterLeverNotInPark", 0x91: "torqueConverterClutchLocked", 0x92: "voltageTooHigh",
    0x93: "voltageTooLow",
}


def status_name(st: int) -> str:
    return STATUS.get(st, f"0x{st:02x}")


def nrc_name(nrc: int) -> str:
    return NRC_NAMES.get(nrc, "ISOSAEReserved" if nrc < 0xF0 else "vehicleManufacturerSpecific")


def describe_response(rsp: bytes) -> str:
    """An ECU response as hex, a negative one with its NRC named."""
    if not rsp:
        return "(no response)"
    text = bytes(rsp).hex(" ")
    if len(rsp) >= 3 and rsp[0] == 0x7F:
        text += f"  NRC 0x{rsp[2]:02x} {nrc_name(rsp[2])}"
    return text


class UdsError(Exception):
    """A request the device refused or could not complete."""

    def __init__(self, message: str, status: int = None, nrc: int = None):
        super().__init__(message)
        self.status, self.nrc = status, nrc


def _num(v) -> int:
    """An int, or a string such as "0x7E0"."""
    return int(v, 0) if isinstance(v, str) else int(v)


# ---- target ------------------------------------------------------------------------
@dataclass
class Target:
    """The ECU: CAN configuration and UDS addressing (TARGET)."""
    tx_id: int = 0x7E0
    rx_id: int = 0x7E8
    func_id: int = None
    bitrate: int = 500000
    fd: bool = False
    data_bitrate: int = 2000000
    brs: bool = False
    extended_ids: bool = False
    dl: int = 8
    padding: bool = True
    p2_ms: int = 0
    p2star_ms: int = 0

    @property
    def flags(self) -> int:
        return ((TF_EXT_ID if self.extended_ids else 0) | (TF_FD if self.fd else 0) | (TF_BRS if self.brs else 0)
                | (TF_PAD if self.padding else 0) | (TF_FUNC if self.func_id is not None else 0))

    def encode(self, seq: int) -> bytes:
        return struct.pack("<BBIIIIIBBBHH", seq & 0xFF, self.flags, self.bitrate, self.data_bitrate if self.fd else 0,
                           self.tx_id, self.rx_id, self.func_id or 0, 0, self.dl, PAD_BYTE if self.padding else 0,
                           self.p2_ms, self.p2star_ms)

    @classmethod
    def decode(cls, payload: bytes) -> tuple:
        """-> (seq, Target)"""
        if len(payload) != TARGET_LEN:
            raise ValueError(f"TARGET of {len(payload)} bytes")
        (seq, flags, bitrate, data_bitrate, tx_id, rx_id, func_id, _ext, dl, _pad, p2,
         p2star) = struct.unpack("<BBIIIIIBBBHH", payload)
        return seq, cls(tx_id, rx_id, func_id if flags & TF_FUNC else None, bitrate, bool(flags & TF_FD),
                        data_bitrate, bool(flags & TF_BRS), bool(flags & TF_EXT_ID), dl, bool(flags & TF_PAD), p2,
                        p2star)


# ---- flash parameters --------------------------------------------------------------
@dataclass
class FlashParams:
    """The programming sequence (_DOC/UDS/README.md); the flags say which steps run."""
    flags: int = 0
    security_level: int = 1
    key_algo: int = ALGOS["BENCH_XOR"]
    comm_control: int = 0x03
    comm_type: int = 0x01
    reset_type: int = 0x01
    alfid: int = 0x44
    dfi: int = 0x00
    erase_rid: int = 0xFF00
    check_rid: int = 0xFF01
    max_block: int = 0
    fingerprint_did: int = 0xF15A
    fingerprint: bytes = b""

    def encode(self) -> bytes:
        if len(self.fingerprint) > FP_MAX:
            raise ValueError(f"fingerprint of {len(self.fingerprint)} bytes, at most {FP_MAX}")
        b = struct.pack("<HBBBBBBBHHHHB", self.flags, self.security_level, self.key_algo, self.comm_control,
                        self.comm_type, self.reset_type, self.alfid, self.dfi, self.erase_rid, self.check_rid,
                        self.max_block, self.fingerprint_did, len(self.fingerprint))
        return b + bytes(self.fingerprint) + bytes(FP_MAX - len(self.fingerprint))

    @classmethod
    def decode(cls, b: bytes) -> "FlashParams":
        if len(b) != PARAMS_LEN:
            raise ValueError(f"flash parameters of {len(b)} bytes")
        f = struct.unpack("<HBBBBBBBHHHHB", b[:18])
        return cls(*f[:12], fingerprint=bytes(b[18:18 + min(f[12], FP_MAX)]))

    def steps(self) -> list:
        """The flag names set, in order."""
        return [name for name, bit in FF.items() if self.flags & bit]


def encode_flash(seq: int, params: FlashParams, name: str) -> bytes:
    n = name.encode()
    if not 1 <= len(n) <= NAME_MAX:
        raise ValueError(f"file name of {len(n)} bytes, 1..{NAME_MAX}")
    return bytes([seq & 0xFF]) + params.encode() + bytes([len(n)]) + n


def encode_diag(seq: int, request: bytes, functional: bool = False) -> bytes:
    if not 1 <= len(request) <= DIAG_REQ_MAX:
        raise ValueError(f"request of {len(request)} bytes, 1..{DIAG_REQ_MAX}")
    return bytes([seq & 0xFF, DF_FUNCTIONAL if functional else 0]) + bytes(request)


def encode_unlock(seq: int, level: int, algo: int) -> bytes:
    return bytes([seq & 0xFF, level, algo])


# ---- device -> host ----------------------------------------------------------------
@dataclass
class Result:
    seq: int
    ref: int
    status: int
    data: bytes = b""

    @property
    def ok(self) -> bool:
        return self.status == ST_OK


@dataclass
class DiagPart:
    seq: int
    status: int
    total: int
    offset: int
    data: bytes


@dataclass
class Status:
    state: int
    step: int
    rec_idx: int
    rec_cnt: int
    done: int
    total: int
    last_sid: int
    last_nrc: int
    status: int

    @property
    def running(self) -> bool:
        return self.state == STATE_RUNNING

    @property
    def state_name(self) -> str:
        return STATES.get(self.state, str(self.state))

    @property
    def step_name(self) -> str:
        return STEPS.get(self.step, str(self.step))

    def describe(self) -> str:
        text = f"{self.state_name} {self.step_name}"
        if self.rec_cnt:
            text += f" record {min(self.rec_idx + 1, self.rec_cnt)}/{self.rec_cnt}"
        if self.total:
            text += f" {self.done}/{self.total} bytes ({100 * self.done // self.total} %)"
        if self.state not in (0, STATE_RUNNING) and self.status != ST_OK:
            text += f": {status_name(self.status)}"
            if self.last_nrc:
                text += f", SID 0x{self.last_sid:02x} NRC 0x{self.last_nrc:02x}"
        return text


def decode_result(p: bytes) -> Result:
    if len(p) < 3:
        raise ValueError(f"RESULT of {len(p)} bytes")
    return Result(p[0], p[1], p[2], bytes(p[3:]))


def decode_diag_rsp(p: bytes) -> DiagPart:
    if len(p) < 6:
        raise ValueError(f"DIAG_RSP of {len(p)} bytes")
    seq, st, total, offset = struct.unpack("<BBHH", p[:6])
    return DiagPart(seq, st, total, offset, bytes(p[6:]))


def decode_status(p: bytes) -> Status:
    if len(p) != STATUS_LEN:
        raise ValueError(f"STATUS of {len(p)} bytes")
    return Status(*struct.unpack("<BBBBIIBBB", p))


# ---- profile -----------------------------------------------------------------------
def load_profile(source) -> tuple:
    """A profile (path, JSON text or dict) -> (Target, FlashParams)."""
    if isinstance(source, dict):
        prof = source
    elif isinstance(source, str) and source.lstrip().startswith("{"):
        prof = json.loads(source)
    else:
        with open(source, encoding="utf-8") as f:
            prof = json.load(f)
    can, adr, tim = prof.get("can", {}), prof.get("addressing", {}), prof.get("timing", {})
    fd = bool(can.get("fd", False))
    target = Target(tx_id=_num(adr["tx_id"]), rx_id=_num(adr["rx_id"]),
                    func_id=_num(adr["functional_id"]) if adr.get("functional_id") is not None else None,
                    bitrate=_num(can.get("bitrate", 500000)), fd=fd,
                    data_bitrate=_num(can.get("data_bitrate", 2000000)), brs=bool(can.get("brs", False)),
                    extended_ids=bool(adr.get("extended_ids", False)), dl=_num(adr.get("dl", 64 if fd else 8)),
                    padding=bool(adr.get("padding", True)), p2_ms=_num(tim.get("p2_ms", 0)),
                    p2star_ms=_num(tim.get("p2star_ms", 0)))

    fl = prof.get("flash", {})
    p = FlashParams(alfid=_num(fl.get("alfid", 0x44)), dfi=_num(fl.get("dfi", 0)),
                    max_block=_num(fl.get("max_block", 0)))
    if fl.get("extended_session"):
        p.flags |= FF["EXT_SESSION"]
    if fl.get("dtc_off"):
        p.flags |= FF["DTC_OFF"]
    if fl.get("comm_control"):
        p.flags |= FF["COMM_OFF"]
        p.comm_control = _num(fl["comm_control"].get("control", 0x03))
        p.comm_type = _num(fl["comm_control"].get("type", 0x01))
    if fl.get("security"):
        p.flags |= FF["SECURITY"]
        p.security_level = _num(fl["security"].get("level", 1))
        algo = fl["security"].get("algo", "BENCH_XOR")
        p.key_algo = ALGOS[algo] if algo in ALGOS else _num(algo)
    if fl.get("fingerprint"):
        p.flags |= FF["FINGERPRINT"]
        p.fingerprint_did = _num(fl["fingerprint"]["did"])
        p.fingerprint = bytes.fromhex(fl["fingerprint"]["data"])
    if fl.get("erase"):
        p.flags |= FF["ERASE"] | (FF["ERASE_PER_RECORD"] if fl["erase"].get("per_record") else 0)
        p.erase_rid = _num(fl["erase"].get("rid", 0xFF00))
    if fl.get("check"):
        p.flags |= FF["CHECK"] | (FF["CHECK_CRC"] if fl["check"].get("crc") else 0)
        p.check_rid = _num(fl["check"].get("rid", 0xFF01))
    if fl.get("reset") is not None:
        p.flags |= FF["RESET"]
        p.reset_type = _num(fl["reset"])
    return target, p


def _hex(v: int, width: int = 2) -> str:
    return f"0x{v:0{width}X}"


def profile_to_dict(target: Target, params: FlashParams) -> dict:
    """(Target, FlashParams) -> a profile, the inverse of load_profile(). A step's
    section is written only when its flag is set, so the values of a step that is
    off are not kept."""
    f = params.flags
    fl = {}
    if f & FF["EXT_SESSION"]:
        fl["extended_session"] = True
    if f & FF["DTC_OFF"]:
        fl["dtc_off"] = True
    if f & FF["COMM_OFF"]:
        fl["comm_control"] = {"control": _hex(params.comm_control), "type": _hex(params.comm_type)}
    if f & FF["SECURITY"]:
        algo = next((n for n, v in ALGOS.items() if v == params.key_algo), _hex(params.key_algo))
        fl["security"] = {"level": params.security_level, "algo": algo}
    if f & FF["FINGERPRINT"]:
        fl["fingerprint"] = {"did": _hex(params.fingerprint_did, 4), "data": bytes(params.fingerprint).hex()}
    if f & FF["ERASE"]:
        fl["erase"] = {"rid": _hex(params.erase_rid, 4), "per_record": bool(f & FF["ERASE_PER_RECORD"])}
    if f & FF["CHECK"]:
        fl["check"] = {"rid": _hex(params.check_rid, 4), "crc": bool(f & FF["CHECK_CRC"])}
    if f & FF["RESET"]:
        fl["reset"] = _hex(params.reset_type)
    fl.update(alfid=_hex(params.alfid), dfi=_hex(params.dfi), max_block=params.max_block)
    can = {"bitrate": target.bitrate, "fd": target.fd}
    if target.fd:
        can.update(data_bitrate=target.data_bitrate, brs=target.brs)
    id_width = 8 if target.extended_ids else 3
    return {
        "can": can,
        "addressing": {"tx_id": _hex(target.tx_id, id_width), "rx_id": _hex(target.rx_id, id_width),
                       "functional_id": None if target.func_id is None else _hex(target.func_id, id_width),
                       "extended_ids": target.extended_ids, "dl": target.dl, "padding": target.padding},
        "timing": {"p2_ms": target.p2_ms, "p2star_ms": target.p2star_ms},
        "flash": fl,
    }


def save_profile(path: str, target: Target, params: FlashParams) -> None:
    """Write a profile that load_profile() (and setu_client.py --profile) reads."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profile_to_dict(target, params), f, indent=2)
        f.write("\n")


# ---- traffic monitor ---------------------------------------------------------------
def _target(p: bytes) -> str:
    try:
        seq, t = Target.decode(bytes(p))
    except ValueError:
        return p.hex(" ")
    return (f"seq={seq} tx=0x{t.tx_id:x} rx=0x{t.rx_id:x} {t.bitrate // 1000}k"
            + (f"/{t.data_bitrate // 1000}k FD" if t.fd else ""))


def _result(p: bytes) -> str:
    try:
        r = decode_result(bytes(p))
    except ValueError:
        return p.hex(" ")
    return f"seq={r.seq} {APP_NAMES.get(r.ref, hex(r.ref))} {status_name(r.status)}" + \
        (f" {r.data.hex(' ')}" if r.data else "")


def _diag_req(p: bytes) -> str:
    return f"seq={p[0]} {'func ' if len(p) > 1 and p[1] & DF_FUNCTIONAL else ''}{bytes(p[2:]).hex(' ')}" \
        if len(p) >= 2 else p.hex(" ")


def _diag_rsp(p: bytes) -> str:
    try:
        d = decode_diag_rsp(bytes(p))
    except ValueError:
        return p.hex(" ")
    return f"seq={d.seq} {status_name(d.status)} {d.offset}+{len(d.data)}/{d.total} {d.data[:16].hex(' ')}"


def _status(p: bytes) -> str:
    try:
        return decode_status(bytes(p)).describe()
    except ValueError:
        return p.hex(" ")


register_app_type(APP_TARGET, "UDS_TARGET", _target)
register_app_type(APP_RESULT, "UDS_RESULT", _result)
register_app_type(APP_DIAG_REQ, "UDS_DIAG_REQ", _diag_req)
register_app_type(APP_DIAG_RSP, "UDS_DIAG_RSP", _diag_rsp)
register_app_type(APP_UNLOCK, "UDS_UNLOCK", lambda p: f"seq={p[0]} level={p[1]} algo={p[2]}" if len(p) == 3
                  else p.hex(" "))
register_app_type(APP_FLASH, "UDS_FLASH", lambda p: f"seq={p[0]} {bytes(p[36:]).decode('ascii', 'replace')}"
                  if len(p) > 36 else p.hex(" "))
register_app_type(APP_STATUS, "UDS_STATUS", _status)
register_app_type(APP_ABORT, "UDS_ABORT", lambda p: f"seq={p[0]}" if p else "")
register_app_type(APP_STATUS_REQ, "UDS_STATUS_REQ", lambda p: f"seq={p[0]}" if p else "")


# ---- session -----------------------------------------------------------------------
class UdsSession:
    """Drives UDS on the device. `setu_cli` needs send_short(app_type, payload) and
    short_q (an asyncio.Queue of (app_type, payload)), as SETUClient has."""

    def __init__(self, setu_cli, log=print):
        self.setu_cli = setu_cli
        self.log = log
        self.seq = 0

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFF
        return self.seq

    def _drain(self):
        while not self.setu_cli.short_q.empty():
            self.setu_cli.short_q.get_nowait()

    async def _get(self, deadline: float):
        """The next (app_type, payload), or TimeoutError at the deadline."""
        left = deadline - time.perf_counter()
        if left <= 0:
            raise TimeoutError
        return await asyncio.wait_for(self.setu_cli.short_q.get(), left)

    async def _result(self, seq: int, ref: int, timeout: float) -> Result:
        deadline = time.perf_counter() + timeout
        while True:
            try:
                t, p = await self._get(deadline)
            except (TimeoutError, asyncio.TimeoutError):
                raise UdsError(f"{APP_NAMES[ref]}: no answer from the device") from None
            if t != APP_RESULT:
                continue
            try:
                r = decode_result(bytes(p))
            except ValueError:
                continue
            if r.seq == seq and r.ref == ref:
                return r

    async def target(self, target: Target) -> None:
        """Set the ECU (CAN configuration, addressing); raises UdsError unless OK."""
        self._drain()
        seq = self._next_seq()
        await self.setu_cli.send_short(APP_TARGET, target.encode(seq))
        r = await self._result(seq, APP_TARGET, TIMEOUT_TARGET)
        if not r.ok:
            raise UdsError(f"TARGET: {status_name(r.status)}", r.status)

    async def diag(self, request: bytes, functional: bool = False, timeout: float = None) -> tuple:
        """Send a UDS request; -> (status, response bytes). The response is the ECU's
        (positive, or 7F SID NRC with status NRC); empty without one. timeout:
        None is TIMEOUT_DIAG."""
        self._drain()
        seq = self._next_seq()
        await self.setu_cli.send_short(APP_DIAG_REQ, encode_diag(seq, request, functional))
        deadline = time.perf_counter() + (TIMEOUT_DIAG if timeout is None else timeout)
        data = bytearray()
        while True:
            try:
                t, p = await self._get(deadline)
            except (TimeoutError, asyncio.TimeoutError):
                raise UdsError("DIAG_REQ: no answer from the device") from None
            if t != APP_DIAG_RSP:
                continue
            try:
                part = decode_diag_rsp(bytes(p))
            except ValueError:
                continue
            if part.seq != seq:
                continue
            if part.offset != len(data):
                raise UdsError(f"DIAG_RSP: part at {part.offset}, expected {len(data)}")
            data += part.data
            if len(data) >= part.total:
                return part.status, bytes(data)

    async def unlock(self, level: int, algo: int) -> None:
        """SecurityAccess with an on-device algorithm; raises UdsError unless OK."""
        self._drain()
        seq = self._next_seq()
        await self.setu_cli.send_short(APP_UNLOCK, encode_unlock(seq, level, algo))
        r = await self._result(seq, APP_UNLOCK, TIMEOUT_UNLOCK)
        if not r.ok:
            nrc = r.data[0] if r.data else None
            raise UdsError(f"UNLOCK: {status_name(r.status)}" + (f" (NRC 0x{nrc:02x})" if nrc else ""), r.status,
                           nrc)

    async def status(self) -> Status:
        seq = self._next_seq()
        await self.setu_cli.send_short(APP_STATUS_REQ, bytes([seq]))
        deadline = time.perf_counter() + TIMEOUT_TARGET
        while True:
            try:
                t, p = await self._get(deadline)
            except (TimeoutError, asyncio.TimeoutError):
                raise UdsError("STATUS_REQ: no answer from the device") from None
            if t == APP_STATUS:
                return decode_status(bytes(p))

    async def request_abort(self) -> None:
        """Send ABORT without waiting for its RESULT: for use while follow_flash()
        reads the messages; the final STATUS (ABORTED) ends the follow."""
        await self.setu_cli.send_short(APP_ABORT, bytes([self._next_seq()]))

    async def abort(self) -> None:
        seq = self._next_seq()
        await self.setu_cli.send_short(APP_ABORT, bytes([seq]))
        r = await self._result(seq, APP_ABORT, TIMEOUT_TARGET)
        if not r.ok:
            raise UdsError(f"ABORT: {status_name(r.status)}", r.status)

    async def flash(self, name: str, params: FlashParams, progress=None, silence: float = None) -> Status:
        """Start a flash job of /FLASH_DISK:/FW/<name> and follow it to the end.
        progress(Status) sees every STATUS. Returns the final Status; raises UdsError
        if the job is refused or does not end DONE (the error carries the status).
        silence: ask with STATUS_REQ after this many quiet seconds (None: STATUS_SILENCE)."""
        await self.start_flash(name, params, silence)
        return await self.follow_flash(name, progress, silence)

    async def start_flash(self, name: str, params: FlashParams, timeout: float = None) -> None:
        """Send FLASH; returns once the device accepted it, raises UdsError if refused.
        The job's STATUS messages stay queued for follow_flash()."""
        self._drain()
        seq = self._next_seq()
        await self.setu_cli.send_short(APP_FLASH, encode_flash(seq, params, name))
        deadline = time.perf_counter() + (STATUS_SILENCE if timeout is None else timeout)
        while True:
            try:
                t, p = await self._get(deadline)
            except (TimeoutError, asyncio.TimeoutError):
                raise UdsError("FLASH: no answer from the device") from None
            if t != APP_RESULT:
                continue                                 # nothing of this job comes before its RESULT
            try:
                r = decode_result(bytes(p))
            except ValueError:
                continue
            if r.seq == seq and r.ref == APP_FLASH:
                if not r.ok:
                    raise UdsError(f"FLASH: {status_name(r.status)}", r.status)
                return

    async def follow_flash(self, name: str = "", progress=None, silence: float = None) -> Status:
        """Follow the running (or just started) job to its end: as flash(), after
        start_flash() or for a job found running (STATUS_REQ) after a reconnect."""
        silence = STATUS_SILENCE if silence is None else silence
        last = time.perf_counter()
        while True:
            try:
                t, p = await asyncio.wait_for(self.setu_cli.short_q.get(), silence)
            except (TimeoutError, asyncio.TimeoutError):
                # Quiet for a while (a long erase): ask
                await self.setu_cli.send_short(APP_STATUS_REQ, bytes([self._next_seq()]))
                if time.perf_counter() - last > 6 * silence:
                    raise UdsError("FLASH: the device stopped reporting") from None
                continue
            if t != APP_STATUS:
                continue
            try:
                st = decode_status(bytes(p))
            except ValueError:
                continue
            last = time.perf_counter()
            if progress:
                progress(st)
            if not st.running and st.state != 0:
                if st.state != 2:
                    label = f"flash {name}" if name else "flash"
                    raise UdsError(f"{label}: {st.describe()}", st.status, st.last_nrc or None)
                return st


# ---- command line ------------------------------------------------------------------
CLI_COMMANDS = ["target", "req", "unlock", "status", "abort"]


async def run_cli(session: UdsSession, sub: str, rest: list, profile=None, functional=False, level=1,
                  algo="BENCH_XOR"):
    """`setu_client.py uds SUB ...`: target (from --profile), req HEX, unlock, status, abort."""
    log = session.log
    if sub == "target":
        if profile is None:
            raise ValueError("target needs --profile")
        target, _ = load_profile(profile)
        await session.target(target)
        log(f"target tx 0x{target.tx_id:x} rx 0x{target.rx_id:x}, {target.bitrate} bit/s"
            + (f", data {target.data_bitrate} bit/s FD" if target.fd else ""))
        return
    if sub == "req":
        if not rest:
            raise ValueError("req HEX (e.g. 22F190)")
        req = bytes.fromhex("".join(rest))
        st, rsp = await session.diag(req, functional)
        log(f"{status_name(st)}: {rsp.hex(' ') if rsp else '(no response)'}")
        if st not in (ST_OK, ST_NRC):
            raise UdsError(f"req: {status_name(st)}", st)
        return
    if sub == "unlock":
        await session.unlock(level, ALGOS[algo] if algo in ALGOS else _num(algo))
        log(f"security level 0x{level:02x} unlocked")
        return
    if sub == "status":
        log((await session.status()).describe())
        return
    if sub == "abort":
        await session.abort()
        log("abort requested")
        return
    raise ValueError(f"unknown uds command '{sub}' ({', '.join(CLI_COMMANDS)})")
