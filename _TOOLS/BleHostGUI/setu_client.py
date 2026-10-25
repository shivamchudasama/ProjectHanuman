#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
SETU reference GATT client (PC side).

Implements the Client role of SETU protocol v2 on top of `bleak`:
  - writes START / DATA frames into the server's DATA characteristic with
    Write Without Response (windowed ACK, Go-Back-N, CRC-32)
  - receives ACK / NACK / END / ABORT and short messages as CTRL notifications
  - sends single-frame ("short") messages

This client only sends. To receive (device -> PC), the receiver must host the
GATT service and bleak cannot: setu_receiver.py is the receiver, behind the
PC's own GATT service in blehost/core/gatt_server.py (Windows).

Usage:
    pip install bleak
    python setu_client.py caps
    python setu_client.py hex app.hex --name "ProjectHanuman"
    python setu_client.py hex app.hex --address AA:BB:CC:DD:EE:FF
    python setu_client.py hex app.hex --store APP1.BIN --name "ProjectHanuman"
    python setu_client.py fs ls --name "ProjectHanuman"
    python setu_client.py fs get /FW/APP1.BIN app1.bin --name "ProjectHanuman"
    python setu_client.py fs shell --name "ProjectHanuman"
    python setu_client.py provision --name "ProjectHanuman" [--ca DIR] [--out dev.pem]
    python setu_client.py provision --negative --name "ProjectHanuman"
    python setu_client.py deprovision --name "ProjectHanuman"
    python setu_client.py pair --central AA:BB:CC:DD:EE:01 --peripheral AA:BB:CC:DD:EE:02
    python setu_client.py pairstatus --address AA:BB:CC:DD:EE:01
    python setu_client.py unpair --address AA:BB:CC:DD:EE:01
    python setu_client.py uds target --profile ../EcuSim/profiles/sim.json
    python setu_client.py uds req 22F190 [--functional]
    python setu_client.py uds unlock --level 1 --algo BENCH_XOR
    python setu_client.py uds status | uds abort
    python setu_client.py flash APP1.BIN --profile ../EcuSim/profiles/sim.json
    python setu_client.py hostcert "Service laptop" [--ca DIR] [--host DIR] [--validity 730]
    python setu_client.py auth --name "ProjectHanuman" [--host DIR]
    python setu_client.py authstatus --name "ProjectHanuman"

A provisioned device serves only its one trusted host (_DOC/HostAuth/PROTOCOL.md):
hostcert issues this PC a host credential from the CA (--host: where it is kept),
auth authenticates the PC with it and pairs (LE SC passkey entry; Windows), and
authstatus reads the device's host state. The device advertises for a host only
while its host window is open (a press of DK Button 3; held 3 s, it forgets the
bonded host first). Every other command needs the trusted host on a provisioned
device; Windows re-encrypts its link with the stored keys.

hex is the upload the project firmware in _ASW accepts (_DOC/HexUpload/PROTOCOL.md);
with --store NAME the device also stores it as the file /FLASH_DISK:/FW/NAME on its
external flash (BEGIN / COMMIT), and the file's size and CRC-32 are checked.
fs runs the device's file commands (_DOC/FileSysManager/PROTOCOL.md), the
FileSystemPoC's UART test harness over BLE: fs mkdir|cd|openr|openw|delfile|deldir
PATH, fs write TEXT (or --hex HEX, or --from LOCALFILE), fs read [N], fs ls,
fs close, fs abort; fs get REMOTE LOCAL and fs put LOCAL REMOTE copy a whole file;
fs shell reads the UART harness's command lines (type help).
provision runs device provisioning (_DOC/Provisioning/PROTOCOL.md) with the CA
in --ca (the GUI's default folder if omitted; created if it does not exist);
it needs cryptography and Windows (the PC hosts a GATT service to receive the
CSR, see blehost/core/gatt_server.py). Provisioning is one-time: a provisioned
device refuses it until deprovision wipes its key, CSR and certificates (the
device then makes a fresh key and CSR). provision --negative wipes the device
first, sends every certificate it must reject, then provisions it.
pair orchestrates certificate-based OOB pairing of two provisioned devices
(_DOC/Pairing/PROTOCOL.md): it connects to both, sends START to each and
follows both until PAIRED or FAILED; the devices then keep their encrypted
link. pairstatus reads one device's pairing STATUS; unpair deletes its bond.
uds drives UDS (ISO 14229) on the device's CAN bus (_DOC/UDS/PROTOCOL.md): uds
target sets the ECU from a JSON profile (--profile: CAN, addressing, timing, and
the flash sequence; _TOOLS/EcuSim/profiles/sim.json), uds req HEX sends a raw
request and prints the ECU's response, uds unlock runs SecurityAccess with an
on-device key algorithm. flash NAME --profile P sets the target, then flashes the
stored file /FLASH_DISK:/FW/NAME (store it first with hex --store NAME) with the
profile's programming sequence, printing the progress; Ctrl+C aborts the job.
ping and send need a server that echoes shorts and accepts any appType; the
project firmware rejects every appType except 0x10.

--base selects the 96-bit base UUID the server was built with (BaseUUIDs.h);
the default is the project base in _ASW/_BLE_GENERIX/BaseUUIDs.h.

The module is also importable (the PC GUI in this folder uses it):
parse_ihex() raises ValueError, and SETUClient only needs an object with
write_gatt_char / read_gatt_char / mtu_size, so a caller can pass a wrapper.
"""

import argparse
import asyncio
import os
import struct
import sys
import time
import zlib

PROJECT_BASE = "16a1-4812-af35-f3f29a92f6ca"         # _ASW/_BLE_GENERIX/BaseUUIDs.h


def char_uuid(char_id: int, base: str) -> str:
    return f"b1c0{char_id:04x}-{base.lower()}"


T_START, T_DATA, T_ACK, T_NACK, T_END, T_ABORT = 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5
ABORT_BY_SENDER, ABORT_BY_RECEIVER = 0, 1
STATUS = {0: "OK", 1: "CRC_ERROR", 2: "TIMEOUT", 3: "ABORTED", 4: "REMOTE_ABORTED",
          5: "REJECTED", 6: "DISCONNECTED", 7: "SOURCE_ERROR", 8: "SINK_ERROR",
          9: "PROTOCOL_ERROR", 10: "NO_RESOURCES", 11: "OUT_OF_ORDER"}
ST_TIMEOUT, ST_ABORTED = 2, 3
CTRL_PAYLOAD_LEN = {T_ACK: 3, T_NACK: 3, T_END: 2, T_ABORT: 3}   # minimum payload per frame type
MAX_FRAME = 244
WINDOW = 16
ACK_TIMEOUT = 1.0
MAX_RETRIES = 5
APP_TYPE_RESULT, APP_TYPE_PING = 0x01, 0x02
APP_TYPE_SEGMENT, APP_TYPE_STORED = 0x10, 0x11       # hex upload (_DOC/HexUpload/PROTOCOL.md)
APP_TYPE_BEGIN, APP_TYPE_COMMIT, APP_TYPE_FILE = 0x12, 0x13, 0x14   # ... stored as a file
SEG_MAX = 65536                                      # server DS_BUF_SIZE
FILE_NAME_MAX = 32                                   # server DS_NAME_MAX
FILE_DIR = "/FLASH_DISK:/FW"                         # server DS_FILE_DIR
# Status codes of the device's file system (FsmgrStatus_E), in FILE and the file commands
FS_STATUS = {0: "OK", 1: "NOT_FOUND", 2: "EXISTS", 3: "NOT_EMPTY", 4: "NO_SPACE", 5: "BAD_ARG",
             6: "BAD_STATE", 7: "BUSY", 8: "NOT_MOUNTED", 9: "IO", 10: "NOT_SUPPORTED",
             11: "WRONG_TYPE", 12: "DENIED"}
FILE_TIMEOUT = 30.0                                  # BEGIN / COMMIT reply (flash work)


class FileReply(tuple):
    """FILE: (op, status, size, crc) for BEGIN or COMMIT."""
    __slots__ = ()

    def __new__(cls, op, status, size, crc):
        return tuple.__new__(cls, (op, status, size, crc))

    op = property(lambda s: s[0])
    status = property(lambda s: s[1])
    size = property(lambda s: s[2])
    crc = property(lambda s: s[3])

    @property
    def ok(self) -> bool:
        return self.status == 0

    @property
    def status_name(self) -> str:
        return FS_STATUS.get(self.status, f"0x{self.status:02x}")


def file_image(segments) -> bytes:
    """The file the device stores for these segments: [u32 LE address][u32 LE length][data] each."""
    return b"".join(struct.pack("<II", a, len(d)) + bytes(d) for a, d in segments)


def valid_file_name(name: str) -> bool:
    """A name BEGIN accepts: 1..32 of A-Z a-z 0-9 . _ -, not . / .. / UPLOAD.TMP."""
    ok = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
    return (0 < len(name) <= FILE_NAME_MAX and set(name) <= ok and name not in (".", "..")
            and name.upper() != "UPLOAD.TMP")


def parse_ihex(path: str, seg_max: int = SEG_MAX) -> list:
    """Intel HEX -> [(address, bytes)], contiguous runs split at seg_max bytes.

    Raises ValueError("<path>:<line>: <reason>") on a malformed file.
    """
    mem = {}
    upper = 0
    seg_wrap = False                                  # type 02: offsets wrap at 64 KiB
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if line[0] != ":":
                raise ValueError(f"{path}:{n}: record does not start with ':'")
            try:
                rec = bytes.fromhex(line[1:])
            except ValueError:
                raise ValueError(f"{path}:{n}: not a hex record") from None
            if len(rec) < 5 or len(rec) != rec[0] + 5 or sum(rec) & 0xFF:
                raise ValueError(f"{path}:{n}: bad length or checksum")
            addr, rtype, data = (rec[1] << 8) | rec[2], rec[3], rec[4:-1]
            if rtype == 0x00:
                for i, b in enumerate(data):
                    off = addr + i
                    mem[upper + (off & 0xFFFF if seg_wrap else off)] = b
            elif rtype == 0x01:
                break
            elif rtype == 0x02:
                upper, seg_wrap = int.from_bytes(data, "big") << 4, True
            elif rtype == 0x04:
                upper, seg_wrap = int.from_bytes(data, "big") << 16, False
            elif rtype in (0x03, 0x05):
                pass                                      # start address: not flash data
            else:
                raise ValueError(f"{path}:{n}: unknown record type 0x{rtype:02x}")

    segments = []
    for a in sorted(mem):
        if segments and segments[-1][0] + len(segments[-1][1]) == a and len(segments[-1][1]) < seg_max:
            segments[-1][1].append(mem[a])
        else:
            segments.append((a, bytearray([mem[a]])))
    return [(a, bytes(d)) for a, d in segments]


def frame(ftype: int, payload: bytes) -> bytes:
    return bytes([len(payload), ftype]) + payload


def seq_to_abs(seq: int, base: int) -> int:
    return base + ((seq - base) & 0xFF)


class SETUClient:
    """SETU Client role. `client` needs write_gatt_char, read_gatt_char and mtu_size."""

    def __init__(self, client, base: str = PROJECT_BASE, log=print):
        self.client = client
        self.log = log
        self.data_uuid, self.ctrl_uuid, self.caps_uuid = (char_uuid(i, base) for i in (1, 2, 3))
        self.frame_cap = min(client.mtu_size - 3, MAX_FRAME)
        self.ctrl_q: asyncio.Queue = asyncio.Queue()    # ACK/NACK/END/ABORT
        self.short_q: asyncio.Queue = asyncio.Queue()
        self.xfer_id = 0

    # ---- plumbing ----------------------------------------------------------
    def on_notify(self, _handle, data: bytearray):
        data = bytes(data)
        if len(data) < 2 or data[0] + 2 != len(data):
            self.log(f"! malformed frame {data.hex()}")
            return
        ftype = data[1]
        if ftype in CTRL_PAYLOAD_LEN and data[0] < CTRL_PAYLOAD_LEN[ftype]:
            self.log(f"! truncated frame 0x{ftype:02x}: {data.hex()}")
            return
        if ftype <= 0xEF:
            self.short_q.put_nowait((ftype, data[2:]))
        elif ftype in (T_ACK, T_NACK, T_END) or (ftype == T_ABORT and data[4] == ABORT_BY_RECEIVER):
            self.ctrl_q.put_nowait(data)
        else:
            self.log(f"! frame 0x{ftype:02x} is not valid on CTRL")

    async def write(self, data: bytes):
        await self.client.write_gatt_char(self.data_uuid, data, response=False)

    async def read_caps(self) -> tuple:
        """-> (protocol version, max frame, window)"""
        ver, max_frame, window, _ = bytes(await self.client.read_gatt_char(self.caps_uuid))[:4]
        return ver, max_frame, window

    # ---- short messages ----------------------------------------------------
    async def send_short(self, app_type: int, payload: bytes):
        assert len(payload) <= self.frame_cap - 2
        await self.write(frame(app_type, payload))

    # ---- client -> server transfer ----------------------------------------
    async def send(self, app_type: int, data: bytes, progress=None) -> str:
        """Send one object. Returns the END status name. progress(acked_bytes, total)
        is called as the ACKs advance. Cancelling the task sends ABORT to the server."""
        self.xfer_id = (self.xfer_id + 1) & 0xFF
        xid = self.xfer_id
        chunk = self.frame_cap - 4
        frames = (len(data) + chunk - 1) // chunk
        start = frame(T_START, struct.pack("<BBIBBI", xid, app_type, len(data), chunk,
                                           WINDOW, zlib.crc32(data)))
        window = WINDOW
        acked = nxt = 0
        started = False
        retries = 0
        try:
            await self.write(start)

            while True:
                if started:
                    while nxt < frames and nxt - acked < window:
                        off = nxt * chunk
                        await self.write(frame(T_DATA, bytes([xid, nxt & 0xFF]) + data[off:off + chunk]))
                        nxt += 1
                try:
                    f = await asyncio.wait_for(self.ctrl_q.get(), ACK_TIMEOUT)
                except asyncio.TimeoutError:
                    retries += 1
                    if retries > MAX_RETRIES:
                        await self.write(frame(T_ABORT, bytes([xid, ST_TIMEOUT, ABORT_BY_SENDER])))
                        return "TIMEOUT"
                    if not started:
                        await self.write(start)
                    nxt = acked                              # Go-Back-N
                    continue
                if f[2] != xid:
                    continue
                if f[1] == T_ACK:
                    if not started:
                        if f[3] == 0:
                            started, window = True, max(1, min(window, f[4]))
                        continue
                    a = seq_to_abs(f[3], acked)
                    if acked < a <= nxt:
                        acked, retries = a, 0
                        if progress:
                            progress(min(acked * chunk, len(data)), len(data))
                elif f[1] == T_NACK:
                    a = seq_to_abs(f[3], acked)
                    if a <= nxt:
                        acked = nxt = a
                elif f[1] == T_END:
                    if f[3] == 0 and progress:
                        progress(len(data), len(data))
                    return STATUS.get(f[3], hex(f[3]))
                elif f[1] == T_ABORT:
                    return "ABORTED_BY_SERVER:" + STATUS.get(f[3], hex(f[3]))
        except asyncio.CancelledError:
            try:                                         # best effort: tell the server
                await asyncio.wait_for(self.write(frame(T_ABORT, bytes([xid, ST_ABORTED, ABORT_BY_SENDER]))), 1.0)
            except Exception:
                pass
            raise

    # ---- hex upload (_DOC/HexUpload/PROTOCOL.md) ---------------------------
    async def upload_segment(self, addr: int, data: bytes, progress=None) -> tuple:
        """Send one hex segment and wait for STORED.

        Returns (status, stored); stored is (status, address, length) from STORED,
        or None when the transfer itself failed. Raises TimeoutError if STORED never comes.
        """
        while not self.short_q.empty():                  # drop leftovers of an earlier transfer
            self.short_q.get_nowait()
        status = await self.send(APP_TYPE_SEGMENT, struct.pack("<I", addr) + data, progress)
        if status != "OK":
            return status, None
        # RESULT arrives right away; STORED once the server has dumped the
        # segment to its serial log (slow; the timeout allows for a 115200 baud log)
        deadline = time.perf_counter() + 30 + len(data) / 500
        while True:
            try:
                app_type, payload = await asyncio.wait_for(
                    self.short_q.get(), max(0.1, deadline - time.perf_counter()))
            except asyncio.TimeoutError:
                raise TimeoutError(f"0x{addr:08x}: no STORED from the server") from None
            if app_type == APP_TYPE_STORED and len(payload) >= 9:
                return status, struct.unpack("<BII", payload[:9])

    async def _file_request(self, app_type: int, payload: bytes) -> FileReply:
        while not self.short_q.empty():
            self.short_q.get_nowait()
        await self.send_short(app_type, payload)
        deadline = time.perf_counter() + FILE_TIMEOUT
        while True:
            try:
                t, p = await asyncio.wait_for(self.short_q.get(),
                                              max(0.1, deadline - time.perf_counter()))
            except asyncio.TimeoutError:
                raise TimeoutError(f"no FILE reply to 0x{app_type:02x}") from None
            if t == APP_TYPE_FILE and len(p) >= 10 and p[0] == app_type:
                return FileReply(*struct.unpack("<BBII", p[:10]))

    async def begin_file(self, name: str) -> FileReply:
        """BEGIN: the following segments are stored as the file FILE_DIR/name."""
        return await self._file_request(APP_TYPE_BEGIN, name.encode())

    async def commit_file(self) -> FileReply:
        """COMMIT: close the file and give it its name; FILE carries its size and CRC-32."""
        return await self._file_request(APP_TYPE_COMMIT, b"")


async def find_device(address, name):
    from bleak import BleakScanner
    if address:
        return address
    print(f"scanning for '{name}' ...")
    dev = await BleakScanner.find_device_by_name(name, timeout=10.0)
    if dev is None:
        sys.exit(f"device '{name}' not found")
    return dev


class BleakPairLink:
    """The link object blehost.protocols.pairing.PairingOrchestrator expects,
    on a plain BleakClient (the GUI uses its BleLink instead)."""

    def __init__(self, label: str = ""):
        self.label = label
        self._client = None
        self.gatt = None

    async def connect(self, address: str, name: str = ""):
        from bleak import BleakClient
        client = BleakClient(await find_device(address, name))
        await client.connect()
        self._client = self.gatt = client

    async def disconnect(self):
        client, self._client, self.gatt = self._client, None, None
        if client is not None:
            await client.disconnect()

    async def start_notify(self, uuid: str, callback):
        await self._client.start_notify(uuid, callback)


async def pair(args):
    """Pair two provisioned devices; exit 1 unless both end PAIRED."""
    from blehost.protocols.pairing import PairingError, PairingOrchestrator

    if not args.central or not args.peripheral:
        sys.exit("pair: give --central ADDRESS and --peripheral ADDRESS")

    def on_status(label, st):
        print(f"  {label}: {st.describe()}")

    orch = PairingOrchestrator(BleakPairLink, log=print, on_status=on_status)
    try:
        out = await orch.pair((args.central, ""), (args.peripheral, ""))
    except PairingError as e:
        sys.exit(f"pairing not started: {e}")
    print(f"{'paired' if out.ok else 'pairing failed'}: {out.message()}")
    if not out.ok:
        sys.exit(1)


async def pair_status(args, unpair_it: bool = False):
    """Print one device's pairing STATUS (after UNPAIR with unpair_it)."""
    from blehost.protocols.pairing import PairingOrchestrator

    if not args.address:
        sys.exit(f"{args.command}: give --address ADDRESS")
    orch = PairingOrchestrator(BleakPairLink, log=print)
    st = await (orch.unpair(args.address) if unpair_it else orch.probe(args.address))
    print(f"{args.address}: {st.describe()} (provisioning state {st.prov_state}, "
          f"own address {st.own or '?'})")


async def provision_with_rejections(session, ca, validity_days):
    """Provision the device and, on the way, send every certificate it must
    reject, comparing each RESULT with the expected status. A provisioned device
    refuses certificates, so it is wiped first (DEPROVISION) when needed; the
    rejected cases run before the good CA and the good device certificate.
    Returns (failures, Outcome)."""
    from blehost.pki.negative import CA_CERT, DEV_CERT, negative_cases
    from blehost.protocols.provisioning import (KEY_READY, Outcome, ProvisioningError,
                                                status_name)

    status = await session.get_status()
    if status.state != KEY_READY:
        print(f"- device is {status.state_name}: removing its provisioning")
        await session.deprovision()
    got = await session.fetch_and_sign(ca, validity_days)
    issued = got.certificate

    async def expect(case) -> bool:
        try:
            await session.send_certificate(case.app_type, case.der)
            res = 0
        except ProvisioningError as e:
            if e.status is None:
                raise
            res = e.status
        ok = res == case.expected
        print(f"  {'ok  ' if ok else 'FAIL'} {case.name}: {status_name(res)}"
              f"{'' if ok else f' (expected {status_name(case.expected)})'}")
        return ok

    cases = negative_cases(ca, got.csr)
    failures = 0
    for case in (c for c in cases if c.app_type == CA_CERT):
        failures += not await expect(case)
    await session.send_certificate(CA_CERT, ca.cert_der)
    for case in (c for c in cases if c.app_type == DEV_CERT):
        failures += not await expect(case)
    await session.send_certificate(DEV_CERT, issued.der)
    return failures, Outcome(got.status, got.csr, issued.certificate, issued.der, issued.serial_hex)


async def provision(args):
    """Device provisioning from the command line (the GUI's Provisioning tab, headless)."""
    from bleak import BleakClient
    from cryptography.hazmat.primitives import serialization

    from blehost.core.gatt_server import PcGattServer
    from blehost.pki.authority import DEFAULT_FOLDER, CaError, CertificateAuthority
    from blehost.protocols.provisioning import ProvisioningError, ProvisioningSession

    folder = args.ca or DEFAULT_FOLDER
    try:
        ca = (CertificateAuthority.load(folder) if CertificateAuthority.exists(folder)
              else CertificateAuthority.create(folder))
    except CaError as e:
        sys.exit(f"CA: {e}")
    print(f"CA {ca.subject} ({folder})")

    # Publish the PC's service before connecting: the device discovers it on CSR_REQ
    pc = PcGattServer(args.base, log=print)
    try:
        await pc.start()
    except Exception as e:
        sys.exit(f"PC SETU service not available: {e}")

    target = await find_device(args.address, args.name)
    try:
        async with BleakClient(target, disconnected_callback=lambda _c: pc.link_lost()) as client:
            setu_cli = SETUClient(client, args.base)
            await client.start_notify(setu_cli.ctrl_uuid, setu_cli.on_notify)
            session = ProvisioningSession(setu_cli, pc.receiver, log=print, step=lambda t: print(f"- {t}"))
            try:
                if args.negative:
                    failures, out = await provision_with_rejections(session, ca, args.validity)
                    if failures:
                        sys.exit(f"device verification: {failures} case(s) answered wrongly")
                else:
                    out = await session.provision(ca, args.validity)
            except (ProvisioningError, ValueError) as e:
                sys.exit(f"provisioning failed: {e}")
    finally:
        await pc.stop()
    print(f"provisioned: serial {out.serial_hex}, {out.device_cert.subject.rfc4514_string()}")
    if args.out:
        with open(args.out, "wb") as f:
            f.write(out.device_cert.public_bytes(serialization.Encoding.PEM))
        print(f"device certificate written to {args.out}")


async def deprovision(args):
    """Wipe the device's provisioning (key, CSR, certificates); it makes a fresh
    key and CSR and is back in KEY_READY."""
    from bleak import BleakClient

    from blehost.protocols.provisioning import ProvisioningError, ProvisioningSession

    target = await find_device(args.address, args.name)
    async with BleakClient(target) as client:
        setu_cli = SETUClient(client, args.base)
        await client.start_notify(setu_cli.ctrl_uuid, setu_cli.on_notify)
        session = ProvisioningSession(setu_cli, None, log=print)
        try:
            await session.deprovision()
            st = await session.get_status()
        except ProvisioningError as e:
            sys.exit(f"deprovisioning failed: {e}")
    print(f"deprovisioned: device {st.state_name}, new CSR {st.csr_len} B, "
          f"key SHA-256 {st.pubkey_sha256.hex()[:16]}...")


def host_cert(args):
    """Issue a host credential from the CA (no device needed)."""
    from blehost.pki.authority import DEFAULT_FOLDER, CaError, CertificateAuthority
    from blehost.pki.host import DEFAULT_FOLDER as HOST_FOLDER, HostError

    if not args.arg:
        sys.exit("hostcert NAME: give the host's name")
    try:
        cred = CertificateAuthority.load(args.ca or DEFAULT_FOLDER).issue_host(
            args.arg, args.host or HOST_FOLDER, args.validity)
    except (CaError, HostError, ValueError, OSError) as e:
        sys.exit(f"hostcert: {e}")
    print(f"host credential for {cred.name} in {cred.folder} (SHA-256 {cred.fingerprint[:23]}...); "
          "keep the folder private: it holds the host key")


async def host_auth(args, status_only: bool = False):
    """Authenticate this PC to the device and bond with it (auth), or read the
    device's host state (authstatus)."""
    from bleak import BleakClient

    from blehost.core import winrt_pairing
    from blehost.core.gatt_server import PcGattServer
    from blehost.pki.host import DEFAULT_FOLDER as HOST_FOLDER, HostCredential, HostError
    from blehost.protocols import host_auth as ha

    cred = None
    if not status_only:
        try:
            cred = HostCredential.load(args.host or HOST_FOLDER)
        except HostError as e:
            sys.exit(f"auth: {e} (issue one with: hostcert NAME)")
        print(f"host {cred.name}")
    # Publish the PC's service before connecting: the device sends CHALLENGE to it
    pc = PcGattServer(args.base, log=print) if not status_only else None
    if pc is not None:
        try:
            await pc.start()
        except Exception as e:
            sys.exit(f"PC SETU service not available: {e}")

    target = await find_device(args.address, args.name)
    try:
        async with BleakClient(target, disconnected_callback=lambda _c: pc and pc.link_lost()) as client:
            setu_cli = SETUClient(client, args.base)
            await client.start_notify(setu_cli.ctrl_uuid, setu_cli.on_notify)

            async def pair_it(pk):
                level = await winrt_pairing.pair_with_pin(client, pk, log=print)
                print(f"paired ({level})")

            session = ha.HostAuthSession(setu_cli, pc.receiver if pc else None, cred, pair=pair_it,
                                         log=print, step=lambda t: print(f"- {t}"))
            try:
                if status_only:
                    st = await session.get_status()
                else:
                    await session.run()
                    st = await session.get_status()
            except (ha.HostAuthError, winrt_pairing.PairingFailed, winrt_pairing.PairingUnavailable) as e:
                sys.exit(f"{args.command}: {e}")
    finally:
        if pc is not None:
            await pc.stop()
    window = ", host window open" if st.window_open else ""
    bond = ", a host is bonded" if st.host_bonded else ""
    print(f"device: {st.state_name}{window}{bond}")


async def fs_command(args):
    """The device's file commands (the FileSystemPoC's UART test harness, over BLE)."""
    from bleak import BleakClient

    from blehost.protocols import filesystem as fsp

    sub = args.arg
    if sub is None:
        sys.exit("fs: give a command (" + ", ".join(fsp.CLI_COMMANDS) + ")")
    if sub not in fsp.CLI_COMMANDS:
        sys.exit(f"fs: unknown command '{sub}'")

    target = await find_device(args.address, args.name)
    async with BleakClient(target) as client:
        setu_cli = SETUClient(client, args.base)
        await client.start_notify(setu_cli.ctrl_uuid, setu_cli.on_notify)
        session = fsp.FileSystemSession(setu_cli, log=print)
        try:
            if sub == "shell":
                await fsp.shell(session)
            else:
                await fsp.run_cli(session, sub, args.rest, hex_data=args.hex_data,
                                  from_file=args.from_file)
        except (fsp.FsError, ValueError, OSError, TimeoutError) as e:
            sys.exit(f"fs {sub}: {e}")


async def uds_command(args):
    """UDS on the device's CAN bus: uds target|req|unlock|status|abort, and flash."""
    from bleak import BleakClient

    from blehost.protocols import uds

    if args.command == "uds":
        sub = args.arg
        if sub not in uds.CLI_COMMANDS:
            sys.exit("uds: give a command (" + ", ".join(uds.CLI_COMMANDS) + ")")
    elif args.arg is None or args.profile is None:
        sys.exit("flash NAME --profile PROFILE")

    target = await find_device(args.address, args.name)
    async with BleakClient(target) as client:
        setu_cli = SETUClient(client, args.base)
        await client.start_notify(setu_cli.ctrl_uuid, setu_cli.on_notify)
        session = uds.UdsSession(setu_cli, log=print)
        try:
            if args.command == "uds":
                await uds.run_cli(session, sub, args.rest, profile=args.profile, functional=args.functional,
                                  level=args.level, algo=args.algo)
                return
            await flash_file(session, uds, args.arg, args.profile)
        except (uds.UdsError, ValueError, OSError, KeyError, TimeoutError) as e:
            sys.exit(f"{args.command}: {e}")


async def flash_file(session, uds, name: str, profile: str):
    """Set the profile's target, flash /FLASH_DISK:/FW/NAME, print the progress."""
    target, params = uds.load_profile(profile)
    await session.target(target)
    print(f"target tx 0x{target.tx_id:x} rx 0x{target.rx_id:x}; steps: {', '.join(params.steps())}")
    shown = [None]

    def progress(st):
        line = st.describe()
        if line != shown[0]:
            print(line)
            shown[0] = line

    t0 = time.perf_counter()
    try:
        st = await session.flash(name, params, progress)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("aborting ...")
        await session.abort()
        raise
    dt = time.perf_counter() - t0
    print(f"flashed {name}: {st.total} bytes in {dt:.1f} s ({st.total * 8 / dt / 1000:.0f} kbit/s)")


async def main():
    from bleak import BleakClient

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["ping", "send", "caps", "hex", "provision", "deprovision",
                                        "pair", "pairstatus", "unpair", "fs", "uds", "flash",
                                        "hostcert", "auth", "authstatus"])
    ap.add_argument("arg", nargs="?", help="send: size in bytes (default 20000); hex: .hex file; "
                                           "fs: mkdir|cd|openr|openw|write|read|ls|delfile|deldir|"
                                           "close|abort|get|put|shell; uds: target|req|unlock|status|"
                                           "abort; flash: the stored file's name; hostcert: the "
                                           "host's name")
    ap.add_argument("rest", nargs="*", help="fs: the command's operands; uds req: the request (hex)")
    ap.add_argument("--profile", help="uds target, flash: JSON profile (target and flash sequence)")
    ap.add_argument("--functional", action="store_true", help="uds req: send to the functional ID")
    ap.add_argument("--level", type=lambda s: int(s, 0), default=1, help="uds unlock: requestSeed level")
    ap.add_argument("--algo", default="BENCH_XOR", help="uds unlock: key algorithm (name or number)")
    ap.add_argument("--store", metavar="NAME",
                    help="hex: also store the upload as the file /FLASH_DISK:/FW/NAME")
    ap.add_argument("--hex", dest="hex_data", metavar="HEX", help="fs write: data as hex")
    ap.add_argument("--from", dest="from_file", metavar="FILE", help="fs write: data from a file")
    ap.add_argument("--ca", help="provision, hostcert: CA folder (default: the GUI's)")
    ap.add_argument("--host", help="auth, hostcert: host credential folder (default: the GUI's)")
    ap.add_argument("--validity", type=int, default=365,
                    help="provision: device certificate days; hostcert: host certificate days")
    ap.add_argument("--out", help="provision: write the device certificate (PEM) here")
    ap.add_argument("--negative", action="store_true",
                    help="provision: wipe the device if needed, send the certificates it "
                         "must reject (blehost/pki/negative.py) and check each RESULT, "
                         "then provision it")
    ap.add_argument("--central", help="pair: address of the device to be the central")
    ap.add_argument("--peripheral", help="pair: address of the device to be the peripheral")
    ap.add_argument("--address")
    ap.add_argument("--name", default="ProjectHanuman")
    ap.add_argument("--base", default=PROJECT_BASE,
                    help="96-bit base UUID of the server, e.g. 16a1-4812-af35-f3f29a92f6ca")
    ap.add_argument("--seg-max", type=int, default=SEG_MAX,
                    help="hex: largest segment per transfer (server DS_BUF_SIZE)")
    args = ap.parse_args()

    segments = []
    if args.command == "hex":
        if not args.arg:
            sys.exit("hex: missing .hex file")
        try:
            segments = parse_ihex(args.arg, args.seg_max)
        except (OSError, ValueError) as e:
            sys.exit(str(e))
        print(f"{args.arg}: {len(segments)} segment(s), {sum(len(d) for _, d in segments)} bytes")
        if args.store is not None and not valid_file_name(args.store):
            sys.exit(f"--store: '{args.store}' is not a valid file name (1..{FILE_NAME_MAX} of "
                     "A-Z a-z 0-9 . _ -)")

    if args.command == "hostcert":
        host_cert(args)
        return
    if args.command in ("auth", "authstatus"):
        await host_auth(args, status_only=args.command == "authstatus")
        return
    if args.command == "provision":
        await provision(args)
        return
    if args.command == "deprovision":
        await deprovision(args)
        return
    if args.command == "pair":
        await pair(args)
        return
    if args.command in ("pairstatus", "unpair"):
        await pair_status(args, unpair_it=args.command == "unpair")
        return
    if args.command == "fs":
        await fs_command(args)
        return
    if args.command in ("uds", "flash"):
        await uds_command(args)
        return

    target = await find_device(args.address, args.name)
    async with BleakClient(target) as client:
        setu_cli = SETUClient(client, args.base)
        await client.start_notify(setu_cli.ctrl_uuid, setu_cli.on_notify)
        print(f"connected, ATT MTU {client.mtu_size} -> {setu_cli.frame_cap} B frames, "
              f"{setu_cli.frame_cap - 4} B per DATA frame")

        if args.command == "caps":
            ver, max_frame, window = await setu_cli.read_caps()
            print(f"protocol v{ver}, max frame {max_frame} B, window {window}")

        elif args.command == "ping":
            t0 = time.perf_counter()
            await setu_cli.send_short(APP_TYPE_PING, b"ping")
            app_type, payload = await asyncio.wait_for(setu_cli.short_q.get(), 5.0)
            print(f"echo type 0x{app_type:02x} {payload!r} in {(time.perf_counter() - t0) * 1e3:.1f} ms")

        elif args.command == "hex":
            if args.store is not None:
                rep = await setu_cli.begin_file(args.store)
                if not rep.ok:
                    sys.exit(f"BEGIN {args.store}: {rep.status_name}")
                print(f"storing as {FILE_DIR}/{args.store}")
            for addr, data in segments:
                t0 = time.perf_counter()
                try:
                    status, stored = await setu_cli.upload_segment(addr, data)
                except TimeoutError as e:
                    sys.exit(str(e))
                dt = time.perf_counter() - t0
                print(f"0x{addr:08x} {len(data)} B: {status}, {len(data) * 8 / dt / 1000:.0f} kbit/s")
                if status != "OK":
                    sys.exit(1)
                st, a, n = stored
                print(f"  stored: 0x{a:08x} {n} B, {STATUS.get(st, hex(st))}")
                if st != 0:
                    sys.exit(1)
            if args.store is not None:
                rep = await setu_cli.commit_file()
                image = file_image(segments)
                if not rep.ok:
                    sys.exit(f"COMMIT {args.store}: {rep.status_name}")
                if (rep.size, rep.crc) != (len(image), zlib.crc32(image)):
                    sys.exit(f"{args.store}: device file {rep.size} B crc 0x{rep.crc:08x}, "
                             f"expected {len(image)} B crc 0x{zlib.crc32(image):08x}")
                print(f"file {FILE_DIR}/{args.store}: {rep.size} B, crc 0x{rep.crc:08x} (matches)")
            print("hex upload done")

        else:
            data = os.urandom(int(args.arg or 20000))
            t0 = time.perf_counter()
            status = await setu_cli.send(0x10, data)
            dt = time.perf_counter() - t0
            print(f"client -> server: {len(data)} B, {status}, {len(data) * 8 / dt / 1000:.0f} kbit/s")
            try:
                app_type, payload = await asyncio.wait_for(setu_cli.short_q.get(), 2.0)
                if app_type == APP_TYPE_RESULT and len(payload) >= 9:
                    st, n, kbps = struct.unpack("<BII", payload[:9])
                    print(f"server reports: {STATUS.get(st, hex(st))}, {n} B, {kbps} kbit/s")
            except asyncio.TimeoutError:
                pass
            sys.exit(0 if status == "OK" else 1)


if __name__ == "__main__":
    asyncio.run(main())
