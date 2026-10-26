"""Device provisioning protocol, PC side (_DOC/Provisioning/PROTOCOL.md).

The PC is the CA. Over the device's SETU service it asks for STATUS and for
the CSR; the device sends the CSR back as a SETU transfer to the PC's own
SETU service (core/gatt_server.py), because only the side hosting the
service can receive a transfer. The PC then sends the CA certificate and the
device certificate, each answered with RESULT; the device stores both and
deletes its CSR. Provisioning is one-time: a provisioned device refuses
another run until DEPROVISION wipes it (fresh key and CSR).

ProvisioningSession is transport independent: it needs a SETUClient (PC ->
device) and a SETUReceiver (device -> PC), so the tests run it against a
simulated device.
"""

import asyncio
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography import x509

from ..pki.authority import public_key_sha256
from . import setu

# appTypes (0x20..0x2F, registered by the device's Prov.c)
GET_STATUS, STATUS, CSR_REQ, CSR, CA_CERT, DEV_CERT, RESULT = 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26
DEPROVISION = 0x27
APP_TYPE_NAMES = {GET_STATUS: "GET_STATUS", STATUS: "STATUS", CSR_REQ: "CSR_REQ", CSR: "CSR",
                  CA_CERT: "CA_CERT", DEV_CERT: "DEV_CERT", RESULT: "RESULT",
                  DEPROVISION: "DEPROVISION"}

STATES = {0: "NO_KEY", 1: "KEY_READY", 2: "CA_OK", 3: "PROVISIONED"}
NO_KEY, KEY_READY, CA_OK, PROVISIONED = 0, 1, 2, 3
FLAG_CSR_TX_BUSY = 0x01

ST_OK = 0x00
RESULT_STATUS = {0x00: "OK", 0x01: "BAD_STATE", 0x02: "TOO_LARGE", 0x03: "PARSE", 0x04: "NOT_CA",
                 0x05: "BAD_SIG", 0x06: "KEY_MISMATCH", 0x07: "SUBJECT_MISMATCH",
                 0x08: "BAD_PROFILE", 0x09: "NO_PEER_SVC", 0x0A: "INTERNAL", 0x0B: "TRANSFER"}
MAX_CERT_LEN = 1024
STATUS_LEN, RESULT_LEN = 36, 2

STATUS_TIMEOUT = 3.0        # STATUS / RESULT after a request
CSR_TIMEOUT = 30.0          # attach (discovery of the PC's service) + transfer
CERT_RESULT_TIMEOUT = 10.0  # verification on the device (ECDSA in software is slow)
DEPROVISION_TIMEOUT = 10.0  # wipe, then a new key and CSR on the device


def status_name(code: int) -> str:
    return RESULT_STATUS.get(code, f"0x{code:02x}")


@dataclass(frozen=True)
class DeviceStatus:
    state: int
    flags: int
    csr_len: int
    pubkey_sha256: bytes

    @property
    def state_name(self) -> str:
        return STATES.get(self.state, f"0x{self.state:02x}")

    @property
    def csr_busy(self) -> bool:
        return bool(self.flags & FLAG_CSR_TX_BUSY)


def parse_status(p: bytes) -> DeviceStatus:
    if len(p) < STATUS_LEN:
        raise ValueError(f"STATUS needs {STATUS_LEN} bytes, got {len(p)}")
    state, flags, csr_len = struct.unpack("<BBH", p[:4])
    return DeviceStatus(state, flags, csr_len, bytes(p[4:36]))


def parse_result(p: bytes) -> tuple:
    """-> (refAppType, status)"""
    if len(p) < RESULT_LEN:
        raise ValueError(f"RESULT needs {RESULT_LEN} bytes, got {len(p)}")
    return p[0], p[1]


def _status_text(p: bytes) -> str:
    try:
        s = parse_status(p)
    except ValueError:
        return p.hex(" ")
    busy = " CSR-busy" if s.csr_busy else ""
    return f"{s.state_name}{busy} csr={s.csr_len} B key={s.pubkey_sha256[:6].hex()}…"


def _result_text(p: bytes) -> str:
    try:
        ref, st = parse_result(p)
    except ValueError:
        return p.hex(" ")
    return f"{APP_TYPE_NAMES.get(ref, f'0x{ref:02x}')} {status_name(st)}"


for _t, _n in APP_TYPE_NAMES.items():
    setu.register_app_type(_t, _n, {STATUS: _status_text, RESULT: _result_text}.get(_t))


class ProvisioningError(Exception):
    """A step failed. `status` is the device's RESULT code when it gave one."""

    def __init__(self, text: str, status: Optional[int] = None):
        super().__init__(text)
        self.status = status


@dataclass
class Issued:
    """What fetch_and_sign() produced: the device's STATUS and CSR, and the
    certificate the CA issued for it (blehost.pki.authority.IssuedCert)."""
    status: DeviceStatus
    csr: bytes
    certificate: object


@dataclass
class Outcome:
    status: DeviceStatus
    csr: bytes
    device_cert: x509.Certificate
    device_cert_der: bytes
    serial_hex: str


class ProvisioningSession:
    """One provisioning run over an open link.

    client: SETUClient on the device's service (its CTRL notifications must
    already reach client.on_notify). receiver: SETUReceiver of the PC's
    service. step(text) reports progress (any thread-safe callable).
    """

    def __init__(self, client, receiver, log: Callable[[str], None] = print,
                 step: Optional[Callable[[str], None]] = None):
        self.client = client
        self.receiver = receiver
        self.log = log
        self.step = step or (lambda _t: None)
        # True once DEPROVISION succeeded: the device deleted every bond, so the
        # PC's keys for it are stale once this link ends (the caller removes them)
        self.wiped = False

    # ---- device replies (short messages on the device's CTRL) -----------------
    async def _wait_short(self, app_type: int, accept, timeout: float, what: str) -> bytes:
        async def wait():
            while True:
                t, p = await self.client.short_q.get()
                if t == app_type and accept(p):
                    return p
                self.log(f"provisioning: ignored {APP_TYPE_NAMES.get(t, hex(t))} {p.hex(' ')}")
        try:
            return await asyncio.wait_for(wait(), timeout)
        except asyncio.TimeoutError:
            raise ProvisioningError(f"no {what} from the device") from None

    async def _wait_result(self, ref: int, timeout: float) -> int:
        p = await self._wait_short(RESULT, lambda p: len(p) >= RESULT_LEN and p[0] == ref, timeout,
                                   f"RESULT for {APP_TYPE_NAMES[ref]}")
        return p[1]

    def _drain(self):
        while not self.client.short_q.empty():
            self.client.short_q.get_nowait()

    # ---- steps ----------------------------------------------------------------
    async def get_status(self, timeout: float = STATUS_TIMEOUT) -> DeviceStatus:
        self._drain()
        await self.client.send_short(GET_STATUS, b"")
        p = await self._wait_short(STATUS, lambda p: len(p) >= STATUS_LEN, timeout, "STATUS")
        return parse_status(p)

    async def fetch_csr(self, timeout: float = CSR_TIMEOUT) -> bytes:
        """Ask for the CSR; the device sends it to the PC's SETU service."""
        self._drain()
        self.receiver.drain()
        await self.client.send_short(CSR_REQ, b"")
        got_csr = asyncio.ensure_future(self.receiver.receive(CSR))
        refused = asyncio.ensure_future(self._wait_result(CSR_REQ, timeout))
        try:
            done, _ = await asyncio.wait({got_csr, refused}, timeout=timeout,
                                         return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (got_csr, refused):
                if not t.done():
                    t.cancel()
        if got_csr in done:
            r = got_csr.result()
            if r.status != "OK":
                raise ProvisioningError(f"CSR transfer failed: {r.status}")
            return r.data
        if refused in done and refused.exception() is None:
            st = refused.result()
            hint = (" (the PC's SETU service is not visible to the device)"
                    if st == 0x09 else "")
            raise ProvisioningError(f"device refused the CSR request: {status_name(st)}{hint}", st)
        raise ProvisioningError("no CSR from the device")

    async def send_certificate(self, app_type: int, der: bytes,
                               timeout: float = CERT_RESULT_TIMEOUT) -> None:
        """Send CA_CERT or DEV_CERT and wait for the device's RESULT."""
        name = APP_TYPE_NAMES[app_type]
        if not 0 < len(der) <= MAX_CERT_LEN:
            raise ProvisioningError(f"{name} is {len(der)} bytes, the device takes 1..{MAX_CERT_LEN}")
        self._drain()
        status = await self.client.send(app_type, der)
        if status != "OK":
            # A refusal at START also comes with RESULT, which says why
            try:
                st = await self._wait_result(app_type, 1.0)
            except ProvisioningError:
                raise ProvisioningError(f"{name} transfer failed: {status}") from None
            raise ProvisioningError(f"{name} refused: {status_name(st)}", st)
        st = await self._wait_result(app_type, timeout)
        if st != ST_OK:
            raise ProvisioningError(f"device rejected the {name}: {status_name(st)}", st)

    async def deprovision(self, timeout: float = DEPROVISION_TIMEOUT) -> None:
        """Wipe the device's key, CSR and certificates; it makes a fresh key and
        CSR and is back in KEY_READY (the DK button does the same)."""
        self._drain()
        await self.client.send_short(DEPROVISION, b"")
        st = await self._wait_result(DEPROVISION, timeout)
        if st != ST_OK:
            raise ProvisioningError(f"device refused DEPROVISION: {status_name(st)}", st)
        self.wiped = True

    async def fetch_and_sign(self, ca, validity_days: int = 365) -> Issued:
        """STATUS, CSR, check it, sign it. Refuses a provisioned device: it keeps
        its certificates until DEPROVISION."""
        self.step("reading device status")
        status = await self.get_status()
        self.log(f"provisioning: device {status.state_name}, CSR {status.csr_len} B")
        if status.state == NO_KEY:
            raise ProvisioningError("the device has no key/CSR (state NO_KEY)")
        if status.state == PROVISIONED:
            raise ProvisioningError("the device is already provisioned; remove its provisioning "
                                    "(DEPROVISION) first", 0x01)

        self.step("requesting the CSR")
        csr_der = await self.fetch_csr()
        self.log(f"provisioning: CSR received, {len(csr_der)} B")
        try:
            csr_key = x509.load_der_x509_csr(csr_der).public_key()
        except ValueError as e:
            raise ProvisioningError(f"the device sent no valid CSR ({e})") from None
        if public_key_sha256(csr_key) != status.pubkey_sha256:
            raise ProvisioningError("the CSR's key is not the key the device reported in STATUS")

        self.step("signing the CSR")
        issued = ca.sign_csr(csr_der, validity_days)
        self.log(f"provisioning: issued serial {issued.serial_hex} to {issued.certificate.subject.rfc4514_string()}")
        return Issued(status, csr_der, issued)

    async def provision(self, ca, validity_days: int = 365) -> Outcome:
        """The whole sequence: STATUS, CSR, sign, CA_CERT, DEV_CERT."""
        got = await self.fetch_and_sign(ca, validity_days)
        status, csr_der, issued = got.status, got.csr, got.certificate

        self.step("sending the CA certificate")
        await self.send_certificate(CA_CERT, ca.cert_der)
        self.step("sending the device certificate")
        await self.send_certificate(DEV_CERT, issued.der)
        self.step("provisioned")
        return Outcome(status, csr_der, issued.certificate, issued.der, issued.serial_hex)
