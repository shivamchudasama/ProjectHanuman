#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
UDS ECU simulator (ISO 14229 server over ISO-TP) for the bench.

It plays the ECU that Project Hanuman flashes and diagnoses (_DOC/UDS/README.md):
a USB-CAN adapter on the same bus as the DK with its MCP2518FD Click, this script
on the PC. It answers the generic programming sequence the firmware runs, writes
the image it received to --out (as records [u32 LE address][u32 LE length][data],
the same layout as the device's stored file), and answers some diagnostics.

    pip install -r _TOOLS/EcuSim/requirements.txt
    python _TOOLS/EcuSim/ecu_sim.py --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 --out flashed.bin
    python _TOOLS/EcuSim/ecu_sim.py --interface pcan --fd --data-bitrate 2000000 --bus-arg f_clock_mhz=80 ...
    python _TOOLS/EcuSim/ecu_sim.py --interface virtual --channel test     # no hardware

Services: DiagnosticSessionControl (P2 50 ms, P2* 5 s), ECUReset, SecurityAccess
(BENCH_XOR, the firmware's algorithm 1; three wrong keys lock it), CommunicationControl,
ControlDTCSetting, TesterPresent, Read/WriteDataByIdentifier (F190 VIN, F15A
fingerprint), RoutineControl (FF00 erase, FF01 check with the image's CRC-32),
RequestDownload / TransferData / RequestTransferExit, ReadDTCInformation 02,
ClearDiagnosticInformation. Fault injection: --pending, --nrc-at, --slow-erase,
--drop-at-block.

The class EcuSim is the ECU without CAN (handle() takes a request, returns the
responses); _TEST/python/test_ecu_sim.py checks it against the uds_flash
conversation of _TEST/vectors/wire.json, which the firmware's test checks too.
"""

import argparse
import struct
import sys
import time
import zlib

BENCH_MASK = (0x5A, 0xA5, 0x3C, 0xC3)
ALGO_BENCH_XOR = 0x01
VIN = b"WMI0HANUMAN000001"
SESSION_TIMING = bytes([0x00, 0x32, 0x01, 0xF4])     # P2 50 ms, P2* 500 x 10 ms
DEFAULT_SEED = bytes.fromhex("11223344")
DEFAULT_MAX_BLOCK = 0x0FFA
ERASE_RID, CHECK_RID = 0xFF00, 0xFF01

# NRCs
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_BAD_LENGTH = 0x13
NRC_CONDITIONS = 0x22
NRC_SEQUENCE = 0x24
NRC_OUT_OF_RANGE = 0x31
NRC_SECURITY_DENIED = 0x33
NRC_INVALID_KEY = 0x35
NRC_EXCEEDED_ATTEMPTS = 0x36
NRC_TRANSFER_SUSPENDED = 0x71
NRC_WRONG_BSC = 0x73
NRC_PENDING = 0x78
NRC_NOT_IN_SESSION = 0x7F

SUB_FUNCTION_SIDS = (0x10, 0x11, 0x19, 0x27, 0x28, 0x31, 0x3E, 0x85)


def bench_xor(level: int, seed: bytes) -> bytes:
    """The firmware's BENCH_XOR (_ASW/_UDS/UdsKey.c): not secure, bench only."""
    out = bytearray()
    for i, s in enumerate(seed):
        v = s ^ BENCH_MASK[i & 3] ^ level
        out.append(((v << 1) | (v >> 7)) & 0xFF)
    return bytes(out)


def _neg(sid: int, nrc: int) -> bytes:
    return bytes([0x7F, sid, nrc])


def _be(data: bytes) -> int:
    return int.from_bytes(data, "big") if data else 0


class EcuSim:
    """A UDS server: state, services and fault injection, without CAN.

    handle(request) returns [(delay_seconds, response), ...]: usually one response,
    none for a suppressed positive response or a dropped request, a 0x78 first for
    a slow operation."""

    def __init__(self, seed: bytes = DEFAULT_SEED, max_block: int = DEFAULT_MAX_BLOCK, pending: int = 1,
                 nrc_at=None, slow_erase: float = 0.0, drop_at_block=None, vin: bytes = VIN, log=None):
        self.seed = bytes(seed)
        self.max_block = max_block
        self.pending = pending                  # 0x78s before entering the programming session
        self.nrc_at = nrc_at                    # (sid, nrc): answered once to the first such request
        self.slow_erase = slow_erase
        self.drop_at_block = drop_at_block      # TransferData block number (1-based) not answered
        self.vin = bytes(vin)
        self.log = log or (lambda *_: None)
        self.reset()
        self.records = []                       # [(address, bytes)] received, in order
        self.dtcs = [(0x012345, 0x2F), (0xC07300, 0x09)]
        self.fingerprint = b""
        self.requests = []                      # every request received

    def reset(self):
        """What an ECU reset clears."""
        self.session = 0x01
        self.unlocked = False
        self.seed_level = None
        self.attempts = 0
        self.download = None                    # [address, size, next bsc, data]
        self.blocks = 0

    # ---- helpers -------------------------------------------------------------
    def _secure(self) -> bool:
        return self.session == 0x02 and self.unlocked

    @property
    def image(self) -> bytes:
        """The received records as the device's file layout."""
        return b"".join(struct.pack("<II", a, len(d)) + d for a, d in self.records)

    def image_crc(self) -> int:
        crc = 0
        for _, d in self.records:
            crc = zlib.crc32(d, crc)
        return crc & 0xFFFFFFFF

    # ---- requests ------------------------------------------------------------
    def handle(self, req: bytes, functional: bool = False) -> list:
        req = bytes(req)
        self.requests.append(req)
        if not req:
            return []
        sid = req[0]
        if self.nrc_at and self.nrc_at[0] == sid:
            nrc = self.nrc_at[1]
            self.nrc_at = None
            self.log(f"injected NRC 0x{nrc:02x} for 0x{sid:02x}")
            return [(0.0, _neg(sid, nrc))]
        handler = {
            0x10: self._session, 0x11: self._reset, 0x14: self._clear_dtc, 0x19: self._read_dtc,
            0x22: self._read_did, 0x27: self._security, 0x28: self._comm_control, 0x2E: self._write_did,
            0x31: self._routine, 0x34: self._request_download, 0x36: self._transfer_data,
            0x37: self._transfer_exit, 0x3E: self._tester_present, 0x85: self._dtc_setting,
        }.get(sid)
        if handler is None:
            return [] if functional else [(0.0, _neg(sid, NRC_SERVICE_NOT_SUPPORTED))]
        rsps = handler(req)
        # A suppressed positive response
        if sid in SUB_FUNCTION_SIDS and len(req) >= 2 and (req[1] & 0x80) and rsps and rsps[-1][1][0] != 0x7F:
            return []
        return rsps

    def _session(self, req):
        if len(req) != 2:
            return [(0.0, _neg(0x10, NRC_BAD_LENGTH))]
        sub = req[1] & 0x7F
        if sub not in (0x01, 0x02, 0x03):
            return [(0.0, _neg(0x10, NRC_SUBFUNCTION_NOT_SUPPORTED))]
        out = []
        if sub == 0x02 and self.session != 0x02:
            out += [(0.05, _neg(0x10, NRC_PENDING))] * self.pending
            self.unlocked = False
        self.session = sub
        if sub == 0x01:
            self.unlocked = False
        return out + [(0.0, bytes([0x50, sub]) + SESSION_TIMING)]

    def _reset(self, req):
        if len(req) != 2:
            return [(0.0, _neg(0x11, NRC_BAD_LENGTH))]
        self.reset()
        return [(0.0, bytes([0x51, req[1] & 0x7F]))]

    def _security(self, req):
        if len(req) < 2:
            return [(0.0, _neg(0x27, NRC_BAD_LENGTH))]
        if self.session == 0x01:
            return [(0.0, _neg(0x27, NRC_NOT_IN_SESSION))]
        level = req[1] & 0x7F
        if level & 1:
            if self.attempts >= 3:
                return [(0.0, _neg(0x27, NRC_EXCEEDED_ATTEMPTS))]
            self.seed_level = level
            seed = bytes(len(self.seed)) if self.unlocked else self.seed
            return [(0.0, bytes([0x67, level]) + seed)]
        if self.seed_level != level - 1:
            return [(0.0, _neg(0x27, NRC_SEQUENCE))]
        self.seed_level = None
        if req[2:] != bench_xor(level - 1, self.seed):
            self.attempts += 1
            return [(0.0, _neg(0x27, NRC_EXCEEDED_ATTEMPTS if self.attempts >= 3 else NRC_INVALID_KEY))]
        self.unlocked = True
        self.attempts = 0
        return [(0.0, bytes([0x67, level]))]

    def _comm_control(self, req):
        if len(req) != 3:
            return [(0.0, _neg(0x28, NRC_BAD_LENGTH))]
        return [(0.0, bytes([0x68, req[1] & 0x7F]))]

    def _dtc_setting(self, req):
        if len(req) < 2:
            return [(0.0, _neg(0x85, NRC_BAD_LENGTH))]
        return [(0.0, bytes([0xC5, req[1] & 0x7F]))]

    def _tester_present(self, req):
        if len(req) != 2 or (req[1] & 0x7F) != 0:
            return [(0.0, _neg(0x3E, NRC_SUBFUNCTION_NOT_SUPPORTED))]
        return [(0.0, bytes([0x7E, 0x00]))]

    def _read_did(self, req):
        if len(req) != 3:
            return [(0.0, _neg(0x22, NRC_BAD_LENGTH))]
        did = _be(req[1:3])
        data = {0xF190: self.vin, 0xF15A: self.fingerprint}.get(did)
        if data is None:
            return [(0.0, _neg(0x22, NRC_OUT_OF_RANGE))]
        return [(0.0, b"\x62" + req[1:3] + data)]

    def _write_did(self, req):
        if len(req) < 4:
            return [(0.0, _neg(0x2E, NRC_BAD_LENGTH))]
        if _be(req[1:3]) != 0xF15A:
            return [(0.0, _neg(0x2E, NRC_OUT_OF_RANGE))]
        if not self._secure():
            return [(0.0, _neg(0x2E, NRC_SECURITY_DENIED))]
        self.fingerprint = req[3:]
        return [(0.0, b"\x6E" + req[1:3])]

    def _routine(self, req):
        if len(req) < 4:
            return [(0.0, _neg(0x31, NRC_BAD_LENGTH))]
        rtype, rid, args = req[1] & 0x7F, _be(req[2:4]), req[4:]
        if rtype != 0x01 or rid not in (ERASE_RID, CHECK_RID):
            return [(0.0, _neg(0x31, NRC_OUT_OF_RANGE))]
        if not self._secure():
            return [(0.0, _neg(0x31, NRC_SECURITY_DENIED))]
        ok = b"\x71\x01" + req[2:4]
        if rid == ERASE_RID:
            out = [(self.slow_erase, _neg(0x31, NRC_PENDING))] if self.slow_erase > 0 else []
            return out + [(0.0, ok + b"\x00")]
        status = 0x00 if (not args or _be(args[:4]) == self.image_crc()) else 0x01
        return [(0.0, ok + bytes([status]))]

    def _request_download(self, req):
        if len(req) < 4:
            return [(0.0, _neg(0x34, NRC_BAD_LENGTH))]
        alfid = req[2]
        n_addr, n_size = alfid & 0x0F, alfid >> 4
        if not (1 <= n_addr <= 4 and 1 <= n_size <= 4) or len(req) != 3 + n_addr + n_size:
            return [(0.0, _neg(0x34, NRC_OUT_OF_RANGE))]
        if not self._secure():
            return [(0.0, _neg(0x34, NRC_SECURITY_DENIED))]
        if self.download is not None:
            return [(0.0, _neg(0x34, NRC_CONDITIONS))]
        address = _be(req[3:3 + n_addr])
        size = _be(req[3 + n_addr:])
        self.download = [address, size, 1, bytearray()]
        return [(0.0, bytes([0x74, 0x20]) + struct.pack(">H", self.max_block))]

    def _transfer_data(self, req):
        if len(req) < 3:
            return [(0.0, _neg(0x36, NRC_BAD_LENGTH))]
        if self.download is None:
            return [(0.0, _neg(0x36, NRC_SEQUENCE))]
        address, size, bsc, data = self.download
        if req[1] != bsc:
            return [(0.0, _neg(0x36, NRC_WRONG_BSC))]
        if len(req) > self.max_block or len(data) + len(req) - 2 > size:
            return [(0.0, _neg(0x36, NRC_TRANSFER_SUSPENDED))]
        self.blocks += 1
        if self.drop_at_block is not None and self.blocks == self.drop_at_block:
            self.log(f"block {self.blocks} dropped")
            return []
        data += req[2:]
        self.download[2] = (bsc + 1) & 0xFF
        return [(0.0, bytes([0x76, req[1]]))]

    def _transfer_exit(self, req):
        if self.download is None:
            return [(0.0, _neg(0x37, NRC_SEQUENCE))]
        address, size, _, data = self.download
        if len(data) != size:
            return [(0.0, _neg(0x37, NRC_SEQUENCE))]
        self.records.append((address, bytes(data)))
        self.download = None
        self.log(f"record 0x{address:08x}: {size} bytes")
        return [(0.0, b"\x77")]

    def _read_dtc(self, req):
        if len(req) != 3 or req[1] & 0x7F != 0x02:
            return [(0.0, _neg(0x19, NRC_SUBFUNCTION_NOT_SUPPORTED))]
        body = b"".join(struct.pack(">I", dtc)[1:] + bytes([st]) for dtc, st in self.dtcs if st & req[2])
        return [(0.0, bytes([0x59, 0x02, 0xFF]) + body)]

    def _clear_dtc(self, req):
        if len(req) != 4:
            return [(0.0, _neg(0x14, NRC_BAD_LENGTH))]
        self.dtcs = []
        return [(0.0, b"\x54")]


# ---- CAN ---------------------------------------------------------------------------
def isotp_params(fd: bool, brs: bool) -> dict:
    return {"stmin": 0, "blocksize": 0, "tx_padding": 0xCC, "tx_data_length": 64 if fd else 8,
            "can_fd": fd, "bitrate_switch": brs, "max_frame_size": 4095,
            "rx_flowcontrol_timeout": 1000, "rx_consecutive_frame_timeout": 1000}


def make_stacks(bus, rx_id: int, tx_id: int, func_id, ext_ids: bool, fd: bool, brs: bool):
    """(notifier, physical stack, functional stack or None), started."""
    import can
    import isotp

    mode = isotp.AddressingMode.Normal_29bits if ext_ids else isotp.AddressingMode.Normal_11bits
    notifier = can.Notifier(bus, [])
    phys = isotp.NotifierBasedCanStack(bus, notifier, address=isotp.Address(mode, txid=tx_id, rxid=rx_id),
                                       params=isotp_params(fd, brs))
    func = None
    if func_id is not None:
        func = isotp.NotifierBasedCanStack(bus, notifier, address=isotp.Address(mode, txid=tx_id, rxid=func_id),
                                           params=isotp_params(fd, brs))
    for s in (phys, func):
        if s is not None:
            s.start()
    return notifier, phys, func


def serve(sim: EcuSim, phys, func=None, stop=lambda: False, out=None, log=print):
    """Answer requests until stop() is true."""
    while not stop():
        for stack, functional in ((phys, False), (func, True)):
            if stack is None:
                continue
            req = stack.recv(block=False)
            if req is None:
                continue
            log(f"<- {bytes(req).hex(' ')}{' (functional)' if functional else ''}")
            for delay, rsp in sim.handle(bytes(req), functional):
                if delay:
                    time.sleep(delay)
                phys.send(rsp)
                log(f"-> {rsp.hex(' ')}")
            if out and req[:1] == b"\x37":
                with open(out, "wb") as f:
                    f.write(sim.image)
        time.sleep(0.001)


def parse_int(text: str) -> int:
    return int(text, 0)


def parse_nrc_at(text: str):
    sid, _, nrc = text.partition(":")
    return int(sid, 16), int(nrc, 16)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interface", default="virtual", help="python-can interface (pcan, kvaser, slcan, gs_usb, "
                                                          "vector, socketcan, virtual)")
    ap.add_argument("--channel", default="test")
    ap.add_argument("--bitrate", type=int, default=500000)
    ap.add_argument("--fd", action="store_true", help="CAN FD frames (64-byte ISO-TP frames)")
    ap.add_argument("--brs", action="store_true", help="bit-rate switching (with --fd)")
    ap.add_argument("--data-bitrate", type=int, default=2000000)
    ap.add_argument("--bus-arg", action="append", default=[], metavar="KEY=VALUE",
                    help="extra python-can bus option (e.g. FD timing of the adapter); repeatable")
    ap.add_argument("--rx", type=parse_int, default=0x7E0, help="request ID the ECU listens on")
    ap.add_argument("--tx", type=parse_int, default=0x7E8, help="response ID")
    ap.add_argument("--functional", type=parse_int, default=0x7DF, help="functional request ID")
    ap.add_argument("--ext-ids", action="store_true", help="29-bit identifiers")
    ap.add_argument("--out", help="write the received image here (records, after every RequestTransferExit)")
    ap.add_argument("--seed", default=DEFAULT_SEED.hex())
    ap.add_argument("--max-block", type=parse_int, default=DEFAULT_MAX_BLOCK,
                    help="maxNumberOfBlockLength in RequestDownload answers")
    ap.add_argument("--pending", type=int, default=1, help="NRC 0x78s before entering the programming session")
    ap.add_argument("--nrc-at", type=parse_nrc_at, metavar="SID:NRC", help="answer the first SID request with NRC")
    ap.add_argument("--slow-erase", type=float, default=0.0, metavar="S", help="erase takes S seconds (NRC 0x78)")
    ap.add_argument("--drop-at-block", type=int, metavar="N", help="do not answer TransferData block N")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    import can

    log = (lambda *_: None) if args.quiet else print
    kwargs = {"interface": args.interface, "channel": args.channel, "bitrate": args.bitrate}
    if args.fd:
        kwargs.update(fd=True, data_bitrate=args.data_bitrate)
    for kv in args.bus_arg:
        k, _, v = kv.partition("=")
        try:
            kwargs[k] = int(v, 0)
        except ValueError:
            kwargs[k] = v
    sim = EcuSim(seed=bytes.fromhex(args.seed), max_block=args.max_block, pending=args.pending,
                 nrc_at=args.nrc_at, slow_erase=args.slow_erase, drop_at_block=args.drop_at_block, log=log)
    with can.Bus(**kwargs) as bus:
        notifier, phys, func = make_stacks(bus, args.rx, args.tx, args.functional, args.ext_ids, args.fd, args.brs)
        print(f"ECU on {args.interface}:{args.channel}, requests 0x{args.rx:x} (functional 0x{args.functional:x}), "
              f"responses 0x{args.tx:x}{', CAN FD' if args.fd else ''}. Ctrl+C stops.")
        try:
            serve(sim, phys, func, out=args.out, log=log)
        except KeyboardInterrupt:
            pass
        finally:
            for s in (phys, func):
                if s is not None:
                    s.stop()
            notifier.stop()
    if args.out and sim.records:
        print(f"{len(sim.records)} records, {sum(len(d) for _, d in sim.records)} bytes -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
