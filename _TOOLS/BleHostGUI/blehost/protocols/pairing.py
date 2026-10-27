"""Device pairing (_DOC/Pairing/PROTOCOL.md): the host side.

The PC orchestrates certificate-based OOB pairing of two provisioned devices.
It talks to each device over the Pairing GATT service only: CONTROL (START /
CANCEL / UNPAIR) and STATUS (read and notified). The devices do the rest
between themselves.

PairingOrchestrator works on any link object with
    await connect(address, name), await disconnect(),
    gatt.read_gatt_char(uuid), gatt.write_gatt_char(uuid, data, response=...),
    await start_notify(uuid, callback(sender, data)), await stop_notify(uuid),
which is what core/ble_link.BleLink offers (the GUI) and what the command
line's small bleak adapter offers (setu_client.py pair). The command line
makes a link per device and run (make_link); the GUI lends the links of the
boards connected on its Device page (existing), which the orchestrator never
connects or disconnects.
"""

import asyncio
import enum
from dataclasses import dataclass
from typing import Callable, Optional

PROJECT_BASE = "16a1-4812-af35-f3f29a92f6ca"         # _ASW/_BLE_GENERIX/BaseUUIDs.h


def pair_uuid(char_id: int, base: str = PROJECT_BASE) -> str:
    """B1C1xxxx-<base>: the Pairing service (0) and its characteristics."""
    return f"b1c1{char_id:04x}-{base.lower()}"


SERVICE_UUID = pair_uuid(0)
CONTROL_UUID = pair_uuid(1)
STATUS_UUID = pair_uuid(2)
SECURED_UUID = pair_uuid(3)

# Between the devices (SETU appTypes); the host never sends these
APP_PEER_CERT, APP_OOB = 0x30, 0x31
APP_RANGE = (0x30, 0x3F)

OP_START, OP_CANCEL, OP_UNPAIR = 0x01, 0x02, 0x03
START_LEN = 9
STATUS_LEN = 19
OOB_FRAME_LEN = 96
OOB_SIGNED_LEN = 46
SECURED_VALUE = 0x01
ADDR_PUBLIC, ADDR_RANDOM = 0, 1
PROVISIONED = 3                                      # provisioning STATUS state

# CONTROL is the trusted host's only (host authentication): ATT error 0x08
# Insufficient Authorization otherwise; retried while a bonded link encrypts
ATT_ERR_AUTHORIZATION = 0x08
AUTH_RETRIES, AUTH_RETRY_DELAY = 6, 0.5


def is_authorization_error(e: Exception) -> bool:
    """Whether a GATT write failed with ATT Insufficient Authorization (bleak
    words it per backend: a protocol error code, or the error's name)."""
    text = str(e).lower()
    return (getattr(e, "att_error", None) == ATT_ERR_AUTHORIZATION or "authoriz" in text
            or "0x08" in text)


class Role(enum.IntEnum):
    NONE = 0
    CENTRAL = 1
    PERIPHERAL = 2


class State(enum.IntEnum):
    IDLE = 0
    ARMED = 1
    CONNECTED = 2
    CERT_EXCHANGE = 3
    CERT_VERIFIED = 4
    OOB_EXCHANGE = 5
    PAIRING = 6
    PAIRED = 7
    FAILED = 8


class Error(enum.IntEnum):
    NONE = 0
    NOT_PROVISIONED = 1
    BAD_ARG = 2
    BUSY = 3
    TIMEOUT = 4
    CONNECT = 5
    NO_PEER_SVC = 6
    PEER_CERT = 7
    OOB_SIG = 8
    SMP = 9
    TRANSFER = 10
    SECURED = 11
    LINK_LOST = 12
    CANCELLED = 13
    INTERNAL = 14


# PEER_CERT details are certificate statuses (provisioning RESULT codes)
CERT_STATUS = {3: "PARSE", 4: "NOT_CA", 5: "BAD_SIG", 8: "BAD_PROFILE", 10: "INTERNAL"}
ERROR_TEXT = {
    Error.NOT_PROVISIONED: "the device is not provisioned",
    Error.BAD_ARG: "the peer address is the device's own",
    Error.BUSY: "the device was busy with another transfer",
    Error.TIMEOUT: "timed out",
    Error.CONNECT: "could not connect to the peer",
    Error.NO_PEER_SVC: "the peer has no SETU service",
    Error.PEER_CERT: "the peer's certificate was rejected",
    Error.OOB_SIG: "the peer's OOB signature does not verify",
    Error.SMP: "LE Secure Connections pairing failed",
    Error.TRANSFER: "a transfer between the devices failed",
    Error.SECURED: "the encrypted link could not be proven",
    Error.LINK_LOST: "the link between the devices dropped",
    Error.CANCELLED: "cancelled",
    Error.INTERNAL: "internal error on the device",
}

# Each state's step in a run, for a step list (ARMED .. PAIRED)
STEPS = ("Reach the peer", "Connected", "Exchange certificates", "Peer certificate verified",
         "Exchange signed OOB data", "Pair (LE Secure Connections, OOB)", "Paired")

RUN_TIMEOUT = 75.0          # above the device's 60 s, so the device reports its own timeout
FAIL_GRACE = 5.0            # after one device fails, how long to wait for the other's status
POLL_PERIOD = 2.0           # STATUS is also read periodically, should a notification be lost
START_SETTLE = 0.5          # after START: a device acts on it within ms; older statuses are stale


# ---- addresses ---------------------------------------------------------------
def addr_wire(address: str, addr_type: int) -> bytes:
    """'C4:5E:2A:11:9F:03' -> [type][6 B, least significant byte first]."""
    raw = bytes.fromhex(address.replace(":", "").replace("-", ""))
    if len(raw) != 6:
        raise ValueError(f"not a Bluetooth address: {address!r}")
    if addr_type not in (ADDR_PUBLIC, ADDR_RANDOM):
        raise ValueError(f"address type {addr_type} is not 0 (public) or 1 (random)")
    return bytes([addr_type]) + raw[::-1]


def addr_text(wire: bytes) -> tuple:
    """7 wire bytes -> ('C4:5E:2A:11:9F:03', type); ('', 0) for all zero."""
    if len(wire) != 7:
        raise ValueError("an address is 7 bytes")
    if not any(wire):
        return "", 0
    return ":".join(f"{b:02X}" for b in wire[:0:-1]), wire[0]


# ---- CONTROL -----------------------------------------------------------------
def encode_start(role: Role, peer_address: str, peer_type: int) -> bytes:
    if role not in (Role.CENTRAL, Role.PERIPHERAL):
        raise ValueError("role must be CENTRAL or PERIPHERAL")
    return bytes([OP_START, int(role)]) + addr_wire(peer_address, peer_type)


def encode_cancel() -> bytes:
    return bytes([OP_CANCEL])


def encode_unpair() -> bytes:
    return bytes([OP_UNPAIR])


# ---- STATUS ------------------------------------------------------------------
def _enum_name(cls, value: int) -> str:
    try:
        return cls(value).name
    except ValueError:
        return f"0x{value:02x}"


@dataclass(frozen=True)
class PairStatus:
    state: int
    error: int
    detail: int
    prov_state: int
    role: int
    own: str
    own_type: int
    peer: str
    peer_type: int

    @property
    def state_name(self) -> str:
        return _enum_name(State, self.state)

    @property
    def error_name(self) -> str:
        return _enum_name(Error, self.error)

    @property
    def role_name(self) -> str:
        return _enum_name(Role, self.role)

    @property
    def provisioned(self) -> bool:
        return self.prov_state == PROVISIONED

    @property
    def running(self) -> bool:
        return State.ARMED <= self.state <= State.PAIRING

    @property
    def paired(self) -> bool:
        return self.state == State.PAIRED

    @property
    def failed(self) -> bool:
        return self.state == State.FAILED

    def step(self) -> int:
        """Index into STEPS (0 for ARMED); -1 outside a run."""
        if State.ARMED <= self.state <= State.PAIRED:
            return self.state - State.ARMED
        return -1

    def failure_text(self) -> str:
        """What a FAILED status means, in words (empty otherwise)."""
        if not self.failed:
            return ""
        what = ERROR_TEXT.get(self.error, f"error {self.error_name}")
        if self.error == Error.PEER_CERT:
            return f"{what} ({CERT_STATUS.get(self.detail, f'status {self.detail}')})"
        if self.error == Error.TIMEOUT:
            return f"{what} in {_enum_name(State, self.detail)}"
        if self.detail and self.error not in (Error.CANCELLED, Error.NOT_PROVISIONED, Error.BAD_ARG):
            return f"{what} (detail 0x{self.detail:02x})"
        return what

    def describe(self) -> str:
        text = self.state_name
        if self.role:
            text += f" as {self.role_name.lower()}"
        if self.peer:
            text += f", peer {self.peer}"
        if self.failed:
            text += f": {self.failure_text()}"
        return text


def paired_with_each_other(a: Optional[PairStatus], b: Optional[PairStatus]) -> bool:
    """Both PAIRED, each with the other as its peer: they hold a bond with each
    other, and a new run would only replace it. Unpair one of them first."""
    if a is None or b is None or not (a.paired and b.paired):
        return False
    if not (a.own and b.own and a.peer and b.peer):
        return False
    return a.peer.upper() == b.own.upper() and b.peer.upper() == a.own.upper()


def parse_status(data: bytes) -> PairStatus:
    data = bytes(data)
    if len(data) != STATUS_LEN:
        raise ValueError(f"STATUS is {STATUS_LEN} bytes, got {len(data)}")
    own, own_type = addr_text(data[5:12])
    peer, peer_type = addr_text(data[12:19])
    return PairStatus(data[0], data[1], data[2], data[3], data[4], own, own_type, peer, peer_type)


def status_summary(data: bytes) -> tuple:
    """Traffic monitor decoder for STATUS."""
    try:
        return "STATUS", parse_status(data).describe()
    except ValueError as e:
        return "STATUS", str(e)


def control_summary(data: bytes) -> tuple:
    """Traffic monitor decoder for CONTROL."""
    data = bytes(data)
    if data[:1] == bytes([OP_START]) and len(data) == START_LEN:
        peer, _ = addr_text(data[2:9])
        return "START", f"START as {_enum_name(Role, data[1]).lower()}, peer {peer}"
    names = {OP_CANCEL: "CANCEL", OP_UNPAIR: "UNPAIR"}
    name = names.get(data[0], f"0x{data[0]:02x}") if data else "?"
    return name, name


def register_decoders(registry) -> None:
    """Name the Pairing characteristics in a core.decoders.DecoderRegistry."""
    registry.register(CONTROL_UUID, "PAIR CONTROL", control_summary)
    registry.register(STATUS_UUID, "PAIR STATUS", status_summary)
    registry.register(SECURED_UUID, "PAIR SECURED")


# ---- orchestration -------------------------------------------------------------
class PairingError(Exception):
    """The run could not start or did not end PAIRED on both devices."""


@dataclass
class PairingOutcome:
    central: PairStatus
    peripheral: PairStatus

    @property
    def ok(self) -> bool:
        return self.central.paired and self.peripheral.paired

    def message(self) -> str:
        if self.ok:
            return "both devices paired (LE Secure Connections, OOB, bonded)"
        parts = []
        for label, st in (("central", self.central), ("peripheral", self.peripheral)):
            if not st.paired:
                parts.append(f"{label}: {st.failure_text() or st.state_name}")
        return "; ".join(parts)


class PairingDevice:
    """One device, over one link: STATUS (read and notified) and CONTROL."""

    def __init__(self, link, address: str, name: str = "", label: str = "",
                 on_status: Optional[Callable] = None, changed: Optional[asyncio.Event] = None,
                 owned: bool = True):
        self.link = link
        self.owned = owned              # opened and closed here; False: a borrowed, connected link
        self.address = address
        self.name = name
        self.label = label or address
        self.status: Optional[PairStatus] = None
        self._on_status = on_status
        self._changed = changed or asyncio.Event()
        self._subscribed = False

    async def open(self) -> PairStatus:
        """Connect (an owned link), subscribe to STATUS and read it."""
        if self.owned:
            await self.link.connect(self.address, self.name)
        elif not getattr(self.link, "connected", False):
            raise PairingError(f"the {self.label} device is not connected")
        await self.link.start_notify(STATUS_UUID, self._notified)
        self._subscribed = True
        return await self.read_status()

    async def close(self):
        """Disconnect an owned link; on a borrowed one only unsubscribe."""
        try:
            if self.owned:
                await self.link.disconnect()
            elif self._subscribed and getattr(self.link, "connected", False):
                await self.link.stop_notify(STATUS_UUID)
        except Exception:
            pass                                    # the link may be gone already
        self._subscribed = False

    async def read_status(self) -> PairStatus:
        self._update(await self.link.gatt.read_gatt_char(STATUS_UUID))
        return self.status

    async def command(self, data: bytes, auth_retries: int = AUTH_RETRIES, delay: float = AUTH_RETRY_DELAY):
        """CONTROL write with response: the device refuses a bad command with an ATT error.

        Only the device's trusted host may write CONTROL (host authentication). Right
        after connecting, the device may not trust the link yet (it is still being
        encrypted with the stored keys), so an authorization refusal is retried for
        a moment; if it persists, this PC is not the device's trusted host."""
        for attempt in range(auth_retries + 1):
            try:
                await self.link.gatt.write_gatt_char(CONTROL_UUID, data, response=True)
                return
            except Exception as e:
                if not is_authorization_error(e):
                    raise
                if attempt == auth_retries:
                    raise PairingError(f"the {self.label} device does not trust this PC: authenticate "
                                       "it on the Host Access page first") from None
                await asyncio.sleep(delay)

    def _notified(self, _sender, data):
        try:
            self._update(data)
        except ValueError:
            return
        # Only a notification wakes the follower: a read is its own polling
        self._changed.set()

    def _update(self, data):
        st = parse_status(data)
        self.status = st
        if self._on_status:
            self._on_status(self.label, st)

    async def wait_change(self, timeout: float):
        """Until a STATUS notification arrives (from either device sharing the
        event) or timeout."""
        try:
            await asyncio.wait_for(self._changed.wait(), timeout)
        except asyncio.TimeoutError:
            pass
        self._changed.clear()


class PairingOrchestrator:
    """Runs a pairing between two devices (and the single-device checks).

    make_link(label) returns a fresh, unconnected link object (see the module
    docstring); existing(address) returns a connected link to that device, or
    None. A device's existing link is used as it is; without one, make_link
    makes a link for the run (no make_link: PairingError, not connected).
    log(text) and on_status(label, PairStatus) are called on the event loop;
    a GUI forwards them to its own thread.
    """

    def __init__(self, make_link: Optional[Callable] = None, log: Callable = print,
                 on_status: Optional[Callable] = None, timeout: float = RUN_TIMEOUT,
                 fail_grace: float = FAIL_GRACE, poll: float = POLL_PERIOD,
                 start_settle: float = START_SETTLE, existing: Optional[Callable] = None):
        self._make_link = make_link
        self._existing = existing
        self._log = log
        self._on_status = on_status
        self.timeout = timeout
        self.fail_grace = fail_grace
        self.poll = poll
        self.start_settle = start_settle

    def _device(self, address: str, name: str, label: str,
                changed: Optional[asyncio.Event] = None) -> PairingDevice:
        link = self._existing(address) if self._existing else None
        if link is not None:
            return PairingDevice(link, address, name, label, self._on_status, changed, owned=False)
        if self._make_link is None:
            raise PairingError(f"{name or address} is not connected: connect it on the Device page")
        return PairingDevice(self._make_link(label), address, name, label, self._on_status, changed)

    async def probe(self, address: str, name: str = "") -> PairStatus:
        """Connect, read STATUS, disconnect."""
        dev = self._device(address, name, name or address)
        try:
            return await dev.open()
        finally:
            await dev.close()

    async def unpair(self, address: str, name: str = "") -> PairStatus:
        """UNPAIR one device (ends any run, drops its peer link, deletes the bond)."""
        dev = self._device(address, name, name or address)
        try:
            await dev.open()
            await dev.command(encode_unpair())
            self._log(f"{dev.label}: UNPAIR sent")
            for _ in range(5):
                await dev.wait_change(1.0)
                if dev.status.state == State.IDLE:
                    break
                await dev.read_status()
            return dev.status
        finally:
            await dev.close()

    async def pair(self, central: tuple, peripheral: tuple) -> PairingOutcome:
        """Pair central=(address, name) with peripheral=(address, name).

        Connects to both (or takes their existing links), checks they are
        provisioned, not in a run and not paired with each other already
        (paired_with_each_other), sends START to the peripheral then to the
        central, follows both STATUS until both are PAIRED or one has FAILED
        (or the time limit, which cancels both), and disconnects the links it
        made. Raises PairingError when the run cannot start."""
        if central[0].upper() == peripheral[0].upper():
            raise PairingError("choose two different devices")
        changed = asyncio.Event()
        c = self._device(central[0], central[1], "central", changed)
        p = self._device(peripheral[0], peripheral[1], "peripheral", changed)
        started = False
        try:
            for dev in (p, c):
                verb = "connecting to" if dev.owned else "using the link to"
                self._log(f"{dev.label}: {verb} {dev.name or dev.address}")
                st = await dev.open()
                self._log(f"{dev.label}: {st.describe()}")
                if not st.provisioned:
                    raise PairingError(f"the {dev.label} device is not provisioned")
                if st.running:
                    raise PairingError(f"the {dev.label} device is pairing already")
                if not st.own:
                    raise PairingError(f"the {dev.label} device did not report its address")
            if paired_with_each_other(c.status, p.status):
                raise PairingError("the devices are paired with each other already: "
                                   "unpair one of them first")
            await p.command(encode_start(Role.PERIPHERAL, c.status.own, c.status.own_type))
            started = True
            await c.command(encode_start(Role.CENTRAL, p.status.own, p.status.own_type))
            self._log(f"START sent: {c.name or c.address} central, {p.name or p.address} peripheral")
            await self._follow(c, p)
            return PairingOutcome(c.status, p.status)
        except asyncio.CancelledError:
            if started:
                await asyncio.shield(self._cancel_both(c, p))
            raise
        finally:
            await c.close()
            await p.close()

    async def _follow(self, c: PairingDevice, p: PairingDevice):
        """Until both PAIRED, or one FAILED (and the other has settled or the
        grace has passed), or the time limit (then CANCEL both)."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        fail_deadline = None
        # Statuses from before START (an older PAIRED, say) are not this run's
        await asyncio.sleep(self.start_settle)
        await self._refresh(c, p)
        while True:
            states = (c.status, p.status)
            if all(s.paired for s in states):
                self._log("both devices paired")
                return
            if any(s.failed for s in states):
                if all(s.failed or s.paired for s in states):
                    return
                if fail_deadline is None:
                    fail_deadline = loop.time() + self.fail_grace
                elif loop.time() >= fail_deadline:
                    return
            if loop.time() >= deadline:
                self._log("no result in time: cancelling")
                await self._cancel_both(c, p)
                return
            await c.wait_change(self.poll)
            await self._refresh(c, p)

    @staticmethod
    async def _refresh(*devices):
        for dev in devices:
            try:
                await dev.read_status()
            except Exception:
                pass                            # its link may be going down; the notification decides

    async def _cancel_both(self, c: PairingDevice, p: PairingDevice):
        for dev in (c, p):
            try:
                await dev.command(encode_cancel())
                await dev.read_status()
            except Exception:
                pass
