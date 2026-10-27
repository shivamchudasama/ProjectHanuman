"""Host authentication, PC side (_DOC/HostAuth/PROTOCOL.md).

The PC proves that it holds a host certificate of the device's CA, the device
proves that it holds its device certificate, and both end up with the same
six-digit passkey, which the PC then uses for LE Secure Connections passkey
entry (BleLink.pair_with_pin). The bond that results is the device's one
trusted host: only it reaches the device's functions afterwards.

    HELLO      PC -> device    [ver][Nh 16][Qh 65][host cert]       (transfer)
    CHALLENGE  device -> PC    [ver][Nd 16][Qd 65][SigD 64][dev cert] (transfer
                                to the PC's own SETU service)
    FINISH     PC -> device    [SigH 64]                            (short)
    RESULT     device -> PC    [refAppType][status][detail]          (short)

    T = SHA-256("PH-HOSTAUTH-1" || Nh || Nd || Qh || Qd ||
                SHA-256(host cert) || SHA-256(device cert))
    SigD = ECDSA(device key, "dev" || T), SigH = ECDSA(host key, "host" || T)
    passkey = u32be(HKDF-SHA256(Z, Nh || Nd, "PH-HOSTAUTH-1 passkey" || T, 4))
              mod 1000000

HostAuthSession is transport independent (a SETUClient, a SETUReceiver and a
pairing callable), so the tests run it against a simulated device.
"""

import asyncio
import hashlib
import os
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..pki.host import is_host_certificate
from . import setu

# appTypes (0x60..0x6F, registered by the device's HostAuth.c)
APP_FIRST, APP_LAST = 0x60, 0x6F
STATUS_REQ, STATUS, HELLO, CHALLENGE, FINISH, RESULT, REFUSED = 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
APP_TYPE_NAMES = {STATUS_REQ: "AUTH_STATUS_REQ", STATUS: "AUTH_STATUS", HELLO: "HELLO",
                  CHALLENGE: "CHALLENGE", FINISH: "FINISH", RESULT: "AUTH_RESULT", REFUSED: "REFUSED"}

STATES = {0: "UNPROVISIONED", 1: "OPEN", 2: "HOST_BONDED", 3: "AWAIT_FINISH", 4: "AWAIT_PAIRING",
          5: "TRUSTED"}
UNPROVISIONED, OPEN, HOST_BONDED, AWAIT_FINISH, AWAIT_PAIRING, TRUSTED = range(6)
FLAG_WINDOW_OPEN, FLAG_HOST_BOND = 0x01, 0x02

RESULT_STATUS = {0x00: "OK", 0x01: "BAD_STATE", 0x02: "PARSE", 0x03: "BAD_CERT", 0x04: "BAD_SIG",
                 0x05: "HOST_BONDED", 0x06: "NO_PC_SVC", 0x07: "BUSY", 0x08: "TIMEOUT",
                 0x09: "PAIRING", 0x0A: "INTERNAL", 0x0B: "TRANSFER"}
ST_OK = 0x00
CERT_STATUS = {0x03: "PARSE", 0x04: "NOT_CA", 0x05: "BAD_SIG", 0x08: "BAD_PROFILE", 0x0A: "INTERNAL"}

# Manufacturer data in the device's undirected advertising (_DOC/HostAuth/PROTOCOL.md §1):
# [company ID u16 LE][format][flags]; bleak hands over {company ID: [format][flags]}
ADV_COMPANY_ID = 0xFFFF            # Bluetooth SIG: for testing / internal use
ADV_FORMAT = 1
ADV_FLAG_PROVISIONED, ADV_FLAG_HOST_BOND = 0x01, 0x02

VERSION = 1
NONCE_LEN, POINT_LEN, SIG_LEN, HASH_LEN = 16, 65, 64, 32
HELLO_HDR_LEN = 1 + NONCE_LEN + POINT_LEN
CHALLENGE_HDR_LEN = HELLO_HDR_LEN + SIG_LEN
MAX_CERT_LEN = 1024
STATUS_LEN, RESULT_LEN = 2, 3
LABEL = b"PH-HOSTAUTH-1"
INFO = b"PH-HOSTAUTH-1 passkey"

STATUS_TIMEOUT = 3.0        # STATUS after STATUS_REQ
CHALLENGE_TIMEOUT = 20.0    # certificate check, ECDH, signature, Client attach, transfer
FINISH_TIMEOUT = 10.0       # signature check on the device
TRUSTED_TIMEOUT = 10.0      # after pairing: the bond and level 4


def status_name(code: int) -> str:
    return RESULT_STATUS.get(code, f"0x{code:02x}")


def state_name(code: int) -> str:
    return STATES.get(code, f"0x{code:02x}")


# ---- codecs ----------------------------------------------------------------------
@dataclass(frozen=True)
class AuthStatus:
    state: int
    flags: int

    @property
    def state_name(self) -> str:
        return state_name(self.state)

    @property
    def window_open(self) -> bool:
        return bool(self.flags & FLAG_WINDOW_OPEN)

    @property
    def host_bonded(self) -> bool:
        return bool(self.flags & FLAG_HOST_BOND)

    @property
    def trusted(self) -> bool:
        return self.state == TRUSTED


@dataclass
class AdvState:
    """What the device advertises about itself (manufacturer data)."""
    provisioned: bool
    host_bonded: bool


def parse_adv(manufacturer_data: dict) -> Optional[AdvState]:
    """The device's advertised state from a scan's manufacturer data
    ({company ID: payload}), or None: an older firmware, another device, or
    another format."""
    p = (manufacturer_data or {}).get(ADV_COMPANY_ID)
    if p is None or len(p) < 2 or p[0] != ADV_FORMAT:
        return None
    return AdvState(bool(p[1] & ADV_FLAG_PROVISIONED), bool(p[1] & ADV_FLAG_HOST_BOND))


async def forget_stale_keys(address: str, manufacturer_data: dict,
                            is_paired: Callable[[str], Awaitable[bool]],
                            unpair: Callable[[str], Awaitable[str]]) -> Optional[str]:
    """Before connecting: a device that advertises no host bond has none, so
    keys this PC holds for its address are stale (it was wiped or erased, or
    forgot its host). Windows would encrypt with them and drop every link, so
    they are removed. Returns the unpair result, or None when nothing was done
    (no advert, a host bond, or no keys here). is_paired/unpair work on an
    address without a link (core/winrt_pairing.py); their errors propagate."""
    st = parse_adv(manufacturer_data)
    if st is None or st.host_bonded:
        return None
    if not await is_paired(address):
        return None
    return await unpair(address)


def parse_status(p: bytes) -> AuthStatus:
    if len(p) < STATUS_LEN:
        raise ValueError(f"AUTH_STATUS needs {STATUS_LEN} bytes, got {len(p)}")
    return AuthStatus(p[0], p[1])


def parse_result(p: bytes) -> tuple:
    """-> (refAppType, status, detail)"""
    if len(p) < RESULT_LEN:
        raise ValueError(f"AUTH_RESULT needs {RESULT_LEN} bytes, got {len(p)}")
    return p[0], p[1], p[2]


def result_text(ref: int, st: int, detail: int) -> str:
    text = f"{APP_TYPE_NAMES.get(ref, f'0x{ref:02x}')} {status_name(st)}"
    if st == 0x03:
        text += f" ({CERT_STATUS.get(detail, f'0x{detail:02x}')})"
    elif st in (0x02, 0x09, 0x0B) and detail:
        text += f" (0x{detail:02x})"
    return text


def build_hello(nonce: bytes, point: bytes, cert_der: bytes) -> bytes:
    if len(nonce) != NONCE_LEN or len(point) != POINT_LEN:
        raise ValueError("bad nonce or point length")
    if not 0 < len(cert_der) <= MAX_CERT_LEN:
        raise ValueError(f"the host certificate is {len(cert_der)} bytes, the device takes 1..{MAX_CERT_LEN}")
    return bytes([VERSION]) + nonce + point + cert_der


@dataclass(frozen=True)
class Challenge:
    nonce: bytes
    point: bytes
    signature: bytes
    cert_der: bytes


def parse_challenge(p: bytes) -> Challenge:
    if len(p) <= CHALLENGE_HDR_LEN:
        raise ValueError(f"CHALLENGE is {len(p)} bytes, needs more than {CHALLENGE_HDR_LEN}")
    if p[0] != VERSION:
        raise ValueError(f"CHALLENGE version {p[0]}, expected {VERSION}")
    o = 1
    nonce, o = p[o:o + NONCE_LEN], o + NONCE_LEN
    point, o = p[o:o + POINT_LEN], o + POINT_LEN
    sig, o = p[o:o + SIG_LEN], o + SIG_LEN
    return Challenge(bytes(nonce), bytes(point), bytes(sig), bytes(p[o:]))


# ---- cryptography ----------------------------------------------------------------
def transcript(nonce_host: bytes, nonce_dev: bytes, point_host: bytes, point_dev: bytes,
               cert_host: bytes, cert_dev: bytes) -> bytes:
    return hashlib.sha256(LABEL + nonce_host + nonce_dev + point_host + point_dev
                          + hashlib.sha256(cert_host).digest()
                          + hashlib.sha256(cert_dev).digest()).digest()


def passkey(secret: bytes, nonce_host: bytes, nonce_dev: bytes, t: bytes) -> int:
    okm = HKDF(algorithm=hashes.SHA256(), length=4, salt=nonce_host + nonce_dev, info=INFO + t).derive(secret)
    return int.from_bytes(okm, "big") % 1000000


def sign_raw(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw(public_key: ec.EllipticCurvePublicKey, message: bytes, sig: bytes) -> bool:
    if len(sig) != SIG_LEN:
        return False
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def point_of(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)


def check_device_certificate(cert_der: bytes, ca_cert: x509.Certificate) -> x509.Certificate:
    """The device certificate the device must hold: issued by the CA, P-256,
    CA:FALSE, KeyUsage digitalSignature + keyAgreement, not a host certificate.
    Raises HostAuthError."""
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except ValueError as e:
        raise HostAuthError(f"the device sent no valid certificate ({e})") from None
    try:
        cert.verify_directly_issued_by(ca_cert)
    except (ValueError, TypeError, InvalidSignature):
        raise HostAuthError("the device's certificate is not issued by this CA "
                            "(another fleet, or not provisioned by it)") from None
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise HostAuthError("the device's certificate key is not P-256")
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise HostAuthError("the device's certificate is a CA certificate")
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        ku = None
    if ku is None or not ku.digital_signature or not ku.key_agreement:
        raise HostAuthError("the device's certificate does not allow digitalSignature and keyAgreement")
    if is_host_certificate(cert):
        raise HostAuthError("the peer presented a host certificate, not a device certificate")
    return cert


def _refused_text(p: bytes) -> str:
    if not p:
        return ""
    return (f"0x{p[0]:02x} {setu.app_type_name(p[0])}: not allowed for an untrusted host "
            "(authenticate on the Host Access page)")


def _status_text(p: bytes) -> str:
    try:
        s = parse_status(p)
    except ValueError:
        return p.hex(" ")
    flags = [n for n, f in (("window", FLAG_WINDOW_OPEN), ("host-bond", FLAG_HOST_BOND)) if s.flags & f]
    return s.state_name + (f" [{', '.join(flags)}]" if flags else "")


def _result_text(p: bytes) -> str:
    try:
        return result_text(*parse_result(p))
    except ValueError:
        return p.hex(" ")


for _t, _n in APP_TYPE_NAMES.items():
    setu.register_app_type(_t, _n, {STATUS: _status_text, RESULT: _result_text,
                                    REFUSED: _refused_text}.get(_t))


# ---- the session -----------------------------------------------------------------
class HostAuthError(Exception):
    """A step failed. `status` is the device's RESULT code when it gave one."""

    def __init__(self, text: str, status: Optional[int] = None, detail: int = 0):
        super().__init__(text)
        self.status = status
        self.detail = detail


@dataclass
class Authenticated:
    """What authenticate() gives: the passkey for the pairing, and the device's
    certificate (proven: it signed the transcript)."""
    passkey: int
    device_cert: x509.Certificate


class HostAuthSession:
    """One host authentication over an open link.

    client: SETUClient on the device's service (its CTRL notifications reach
    client.on_notify). receiver: SETUReceiver of the PC's service (CHALLENGE
    arrives there). credential: blehost.pki.host.HostCredential. pair:
    async callable(passkey) that pairs the link with LE SC passkey entry
    (BleLink.pair_with_pin). step(text) reports progress.
    """

    def __init__(self, client, receiver, credential,
                 pair: Optional[Callable[[int], Awaitable[None]]] = None,
                 log: Callable[[str], None] = print, step: Optional[Callable[[str], None]] = None,
                 rng=os.urandom):
        self.client = client
        self.receiver = receiver
        self.cred = credential
        self.pair = pair
        self.log = log
        self.step = step or (lambda _t: None)
        self.rng = rng

    async def _wait_short(self, app_type: int, accept, timeout: float, what: str) -> bytes:
        async def wait():
            while True:
                t, p = await self.client.short_q.get()
                if t == app_type and accept(p):
                    return p
                if t == REFUSED:
                    self.log(f"host auth: device refused {_refused_text(p)}")
                elif not APP_FIRST <= t <= APP_LAST:
                    self.log(f"host auth: ignored {setu.app_type_name(t)} {p.hex(' ')}")
        try:
            return await asyncio.wait_for(wait(), timeout)
        except asyncio.TimeoutError:
            raise HostAuthError(f"no {what} from the device") from None

    def _drain(self):
        while not self.client.short_q.empty():
            self.client.short_q.get_nowait()

    async def get_status(self, timeout: float = STATUS_TIMEOUT) -> AuthStatus:
        self._drain()
        await self.client.send_short(STATUS_REQ, b"")
        p = await self._wait_short(STATUS, lambda p: len(p) >= STATUS_LEN, timeout, "AUTH_STATUS")
        return parse_status(p)

    async def wait_trusted(self, timeout: float = TRUSTED_TIMEOUT) -> AuthStatus:
        """Wait for STATUS TRUSTED (sent by the device once the bonded host is at
        level 4), asking again now and then."""
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while True:
            left = end - loop.time()
            if left <= 0:
                raise HostAuthError("the device did not trust this host after pairing")
            try:
                p = await self._wait_short(STATUS, lambda p: len(p) >= STATUS_LEN, min(left, 2.0),
                                           "AUTH_STATUS")
                s = parse_status(p)
                if s.trusted:
                    return s
            except HostAuthError:
                await self.client.send_short(STATUS_REQ, b"")

    async def authenticate(self, timeout: float = CHALLENGE_TIMEOUT) -> Authenticated:
        """HELLO, CHALLENGE, FINISH. Returns the passkey once the device accepted
        FINISH (it now allows exactly one pairing on this link)."""
        eph = ec.generate_private_key(ec.SECP256R1())
        nh = self.rng(NONCE_LEN)
        qh = point_of(eph)
        host_cert = self.cred.cert_der
        hello = build_hello(nh, qh, host_cert)

        self.step("sending HELLO")
        self._drain()
        self.receiver.drain()
        got = asyncio.ensure_future(self.receiver.receive(CHALLENGE))
        try:
            status = await self.client.send(HELLO, hello)
            if status != "OK":
                st = await self._result_or_none(HELLO, 1.0)
                if st is not None:
                    raise HostAuthError(f"HELLO refused: {result_text(HELLO, *st)}", st[0], st[1])
                raise HostAuthError(f"HELLO transfer failed: {status}")
            self.step("waiting for the device's CHALLENGE")
            refused = asyncio.ensure_future(self._wait_short(RESULT, lambda p: len(p) >= RESULT_LEN
                                                             and p[0] == HELLO, timeout, "CHALLENGE"))
            try:
                done, _ = await asyncio.wait({got, refused}, timeout=timeout,
                                             return_when=asyncio.FIRST_COMPLETED)
            finally:
                if not refused.done():
                    refused.cancel()
            if got not in done:
                if refused in done and refused.exception() is None:
                    ref, st, detail = parse_result(refused.result())
                    hint = (" (the PC's SETU service is not visible to the device)"
                            if st == 0x06 else "")
                    raise HostAuthError(f"device refused HELLO: {result_text(ref, st, detail)}{hint}",
                                        st, detail)
                raise HostAuthError("no CHALLENGE from the device")
            r = got.result()
        finally:
            if not got.done():
                got.cancel()
        if r.status != "OK":
            raise HostAuthError(f"CHALLENGE transfer failed: {r.status}")
        try:
            ch = parse_challenge(r.data)
        except ValueError as e:
            raise HostAuthError(f"bad CHALLENGE: {e}") from None

        self.step("checking the device's certificate")
        dev_cert = check_device_certificate(ch.cert_der, self.cred.ca_certificate)
        try:
            dev_point_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ch.point)
        except ValueError:
            raise HostAuthError("the device's ephemeral key is not a P-256 point") from None
        t = transcript(nh, ch.nonce, qh, ch.point, host_cert, ch.cert_der)
        if not verify_raw(dev_cert.public_key(), b"dev" + t, ch.signature):
            raise HostAuthError("the device's signature does not verify: it does not hold "
                                "its certificate's key (or someone sits in between)")
        z = eph.exchange(ec.ECDH(), dev_point_key)
        pk = passkey(z, nh, ch.nonce, t)

        self.step("sending FINISH")
        self._drain()
        await self.client.send_short(FINISH, sign_raw(self.cred.key, b"host" + t))
        p = await self._wait_short(RESULT, lambda p: len(p) >= RESULT_LEN and p[0] == FINISH,
                                   FINISH_TIMEOUT, "RESULT for FINISH")
        ref, st, detail = parse_result(p)
        if st != ST_OK:
            raise HostAuthError(f"device refused FINISH: {result_text(ref, st, detail)}", st, detail)
        self.log(f"host auth: device {dev_cert.subject.rfc4514_string()} verified; pairing allowed")
        return Authenticated(pk, dev_cert)

    async def _result_or_none(self, ref: int, timeout: float):
        try:
            p = await self._wait_short(RESULT, lambda p: len(p) >= RESULT_LEN and p[0] == ref,
                                       timeout, "RESULT")
        except HostAuthError:
            return None
        return p[1], p[2]

    async def run(self) -> Authenticated:
        """The whole sequence: STATUS, handshake, pairing with the passkey,
        STATUS TRUSTED. A host the device trusts already returns at once."""
        if self.pair is None:
            raise HostAuthError("no pairing function: this PC cannot pair (Windows only)")
        self.step("reading the device's state")
        s = await self.get_status()
        self.log(f"host auth: device {s.state_name}")
        if s.trusted:
            self.step("trusted")
            return Authenticated(0, None)
        if s.state == UNPROVISIONED:
            raise HostAuthError("the device is not provisioned: provision it first", 0x01)
        if s.state == HOST_BONDED:
            raise HostAuthError("another host is bonded to the device: hold its Button 3 "
                                "for 3 s to forget it, then try again", 0x05)
        got = await self.authenticate()
        self.step("pairing (passkey entry)")
        await self.pair(got.passkey)
        self.step("waiting for the device to trust this host")
        await self.wait_trusted()
        self.step("trusted")
        return got
