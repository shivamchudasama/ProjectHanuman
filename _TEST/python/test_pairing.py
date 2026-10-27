# SPDX-License-Identifier: MIT
"""Device pairing, host side (_TOOLS/BleHostGUI/blehost/protocols/pairing.py),
against _DOC/Pairing/PROTOCOL.md: constants, CONTROL and STATUS codecs and the
signed OOB frame against the wire.json vectors (the same ones the C tests use),
and the PairingOrchestrator against simulated devices that follow the
protocol's states (the rules of _ASW/_PAIR/Pair.c), each behind a fake link.
"""

import asyncio
import types

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from blehost.core.decoders import DecoderRegistry
from blehost.protocols import pairing as pp

A = ("C4:5E:2A:11:9F:03", pp.ADDR_RANDOM)
B = ("E1:02:03:04:05:06", pp.ADDR_RANDOM)
C_ADDR = "D0:11:22:33:44:55"


@pytest.fixture(scope="module")
def pv(vectors):
    return vectors["pairing"]


def _vec(entries, name):
    return next(e for e in entries if e["name"] == name)


# ---- constants and codecs against wire.json ---------------------------------------
def test_constants_match_vectors(pv):
    assert pp.SERVICE_UUID == pv["uuids"]["service"]
    assert pp.CONTROL_UUID == pv["uuids"]["control"]
    assert pp.STATUS_UUID == pv["uuids"]["status"]
    assert pp.SECURED_UUID == pv["uuids"]["secured"]
    assert (pp.APP_PEER_CERT, pp.APP_OOB) == (pv["app_types"]["PEER_CERT"], pv["app_types"]["OOB"])
    assert list(pp.APP_RANGE) == pv["app_type_range"]
    assert (pp.OP_START, pp.OP_CANCEL, pp.OP_UNPAIR) == tuple(pv["ops"][k] for k in ("START", "CANCEL", "UNPAIR"))
    assert {r.name: r.value for r in pp.Role} == pv["roles"]
    assert {s.name: s.value for s in pp.State} == pv["states"]
    assert {e.name: e.value for e in pp.Error} == pv["errors"]
    assert (pp.START_LEN, pp.STATUS_LEN) == (pv["start_len"], pv["status_len"])
    assert (pp.OOB_FRAME_LEN, pp.OOB_SIGNED_LEN) == (pv["oob_frame_len"], pv["oob_signed_len"])
    assert pp.SECURED_VALUE == pv["secured_value"]
    assert len(pp.STEPS) == pp.State.PAIRED - pp.State.ARMED + 1


def test_control_frames_match_vectors(pv):
    c = _vec(pv["controls"], "start_central")
    assert pp.encode_start(pp.Role.CENTRAL, c["peer"], c["peer_type"]).hex() == c["hex"]
    c = _vec(pv["controls"], "start_peripheral")
    assert pp.encode_start(pp.Role.PERIPHERAL, c["peer"], c["peer_type"]).hex() == c["hex"]
    assert pp.encode_cancel().hex() == _vec(pv["controls"], "cancel")["hex"]
    assert pp.encode_unpair().hex() == _vec(pv["controls"], "unpair")["hex"]
    with pytest.raises(ValueError):
        pp.encode_start(pp.Role.NONE, *A)


def test_status_vectors_parse(pv):
    for v in pv["statuses"]:
        st = pp.parse_status(bytes.fromhex(v["hex"]))
        assert (st.state, st.error, st.detail, st.prov_state, st.role) == \
            (v["state"], v["error"], v["detail"], v["prov_state"], v["role"]), v["name"]
        assert (st.own, st.own_type, st.peer, st.peer_type) == \
            (v["own"], v["own_type"], v["peer"], v["peer_type"]), v["name"]
    with pytest.raises(ValueError):
        pp.parse_status(bytes(18))


def test_status_meaning(pv):
    st = pp.parse_status(bytes.fromhex(_vec(pv["statuses"], "armed_central")["hex"]))
    assert st.running and st.provisioned and not st.paired and st.step() == 0
    assert st.describe() == "ARMED as central, peer E1:02:03:04:05:06"
    st = pp.parse_status(bytes.fromhex(_vec(pv["statuses"], "paired_peripheral")["hex"]))
    assert st.paired and not st.running and st.step() == len(pp.STEPS) - 1
    st = pp.parse_status(bytes.fromhex(_vec(pv["statuses"], "failed_peer_cert_bad_sig")["hex"]))
    assert st.failed and st.failure_text() == "the peer's certificate was rejected (BAD_SIG)"
    assert st.describe().endswith(": the peer's certificate was rejected (BAD_SIG)")
    st = pp.parse_status(bytes.fromhex(_vec(pv["statuses"], "failed_not_provisioned")["hex"]))
    assert not st.provisioned and st.failure_text() == "the device is not provisioned"
    st = pp.parse_status(bytes.fromhex(_vec(pv["statuses"], "idle_provisioned")["hex"]))
    assert st.step() == -1 and st.peer == "" and st.describe() == "IDLE"


@pytest.mark.parametrize("error, detail, text", [
    (pp.Error.TIMEOUT, pp.State.ARMED, "timed out in ARMED"),
    (pp.Error.SMP, 0x05, "LE Secure Connections pairing failed (detail 0x05)"),
    (pp.Error.CANCELLED, 0, "cancelled"),
    (pp.Error.LINK_LOST, 0x08, "the link between the devices dropped (detail 0x08)"),
    (0x63, 0, "error 0x63"),
])
def test_failure_texts(error, detail, text):
    st = pp.PairStatus(pp.State.FAILED, error, detail, 3, 1, A[0], 1, B[0], 1)
    assert st.failure_text() == text
    assert pp.PairStatus(pp.State.IDLE, 0, 0, 3, 0, A[0], 1, "", 0).failure_text() == ""


def test_addresses():
    wire = pp.addr_wire(*A)
    assert wire.hex() == "01039f112a5ec4"
    assert pp.addr_text(wire) == A
    assert pp.addr_text(bytes(7)) == ("", 0)
    assert pp.addr_wire("c4-5e-2a-11-9f-03", 0)[0] == 0
    for bad in (("C4:5E:2A:11:9F", 1), ("C4:5E:2A:11:9F:03", 2)):
        with pytest.raises(ValueError):
            pp.addr_wire(*bad)
    with pytest.raises(ValueError):
        pp.addr_text(bytes(6))


def test_decoders(pv):
    reg = DecoderRegistry()
    pp.register_decoders(reg)
    assert reg.name(pp.STATUS_UUID) == "PAIR STATUS"
    assert reg.decode(pp.STATUS_UUID, bytes.fromhex(_vec(pv["statuses"], "armed_central")["hex"])) == \
        ("STATUS", "ARMED as central, peer E1:02:03:04:05:06")
    assert reg.decode(pp.STATUS_UUID, b"\x00")[0] == "STATUS"
    assert reg.decode(pp.CONTROL_UUID, bytes.fromhex(_vec(pv["controls"], "start_central")["hex"])) == \
        ("START", "START as central, peer E1:02:03:04:05:06")
    assert reg.decode(pp.CONTROL_UUID, b"\x03") == ("UNPAIR", "UNPAIR")
    assert reg.decode(pp.CONTROL_UUID, b"\x09")[0] == "0x09"
    assert reg.name(pp.SECURED_UUID) == "PAIR SECURED"


def test_oob_vector_is_signed_over_rand_confirm_and_addresses(pv):
    """The signed layout the devices use (PairOob.c), checked with cryptography."""
    o = pv["oob"]
    r, c, sender, receiver = (bytes.fromhex(o[k]) for k in ("r", "c", "sender", "receiver"))
    sig = bytes.fromhex(o["signature_raw"])
    assert bytes.fromhex(o["message"]) == r + c + sender + receiver
    assert len(r + c + sender + receiver) == pp.OOB_SIGNED_LEN
    assert bytes.fromhex(o["frame"]) == r + c + sig and len(sig) == 64
    assert sender == pp.addr_wire(*A) and receiver == pp.addr_wire(*B)
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(o["public_key"]))
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    key.verify(der, r + c + sender + receiver, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignature):           # for another receiver it does not verify
        key.verify(der, r + c + sender + sender, ec.ECDSA(hashes.SHA256()))


# ---- simulated devices behind fake links -------------------------------------------
class SimDevice:
    """A device's Pairing service, following _DOC/Pairing/PROTOCOL.md §3-§5.

    outcome: what the run does after START: "pair" (to PAIRED), ("fail", error,
    detail), "hang" (stays in OOB_EXCHANGE), "lost" (fails LINK_LOST once the
    peer fails)."""

    def __init__(self, address, prov_state=3, state=pp.State.IDLE, outcome="pair"):
        self.address, self.addr_type = address, pp.ADDR_RANDOM
        self.prov_state = prov_state
        self.state, self.error, self.detail, self.role = state, 0, 0, 0
        self.peer, self.peer_type = "", 0
        self.outcome = outcome
        self.controls = []
        self.notify_cb = None
        self.peer_dev = None
        self.refuse_write = None
        self.task = None
        self.has_service = True             # False: a board without the Pairing service

    def status_bytes(self):
        own = pp.addr_wire(self.address, self.addr_type)
        peer = pp.addr_wire(self.peer, self.peer_type) if self.peer else bytes(7)
        return bytes([self.state, self.error, self.detail, self.prov_state, self.role]) + own + peer

    def _set(self, state, error=0, detail=0):
        self.state, self.error, self.detail = state, error, detail
        if self.notify_cb:
            self.notify_cb(None, self.status_bytes())

    async def control(self, data):
        if self.refuse_write:
            raise RuntimeError(self.refuse_write)
        self.controls.append(bytes(data))
        op = data[0]
        if op == pp.OP_START:
            self.role = data[1]
            self.peer, self.peer_type = pp.addr_text(bytes(data[2:9]))
            # Kept: the loop holds tasks only weakly
            self.task = asyncio.get_running_loop().create_task(self._run())
        elif op == pp.OP_CANCEL and pp.State.ARMED <= self.state <= pp.State.PAIRING:
            self._set(pp.State.FAILED, pp.Error.CANCELLED)
        elif op == pp.OP_UNPAIR:
            self.role, self.peer = 0, ""
            self._set(pp.State.IDLE)

    async def _run(self):
        self._set(pp.State.ARMED)
        for state in (pp.State.CONNECTED, pp.State.CERT_EXCHANGE, pp.State.CERT_VERIFIED,
                      pp.State.OOB_EXCHANGE):
            await asyncio.sleep(0.001)
            if self.state == pp.State.FAILED:
                return
            self._set(state)
        if self.outcome == "hang":
            return
        if self.outcome == "lost":
            while self.peer_dev.state != pp.State.FAILED:
                await asyncio.sleep(0.001)
            self._set(pp.State.FAILED, pp.Error.LINK_LOST, 0x08)
            return
        if isinstance(self.outcome, tuple):
            self._set(pp.State.FAILED, self.outcome[1], self.outcome[2])
            return
        self._set(pp.State.PAIRING)
        await asyncio.sleep(0.001)
        self._set(pp.State.PAIRED)


class FakeGatt:
    def __init__(self, link):
        self.link = link

    def has_characteristic(self, uuid):
        return self.link.dev.has_service and uuid in (pp.STATUS_UUID, pp.CONTROL_UUID)

    async def read_gatt_char(self, uuid):
        assert uuid == pp.STATUS_UUID
        self.link.reads += 1
        return self.link.dev.status_bytes()

    async def write_gatt_char(self, uuid, data, response=False):
        assert uuid == pp.CONTROL_UUID and response, "CONTROL is written with response"
        await self.link.dev.control(data)


class FakeLink:
    """The link interface PairingOrchestrator uses, onto a SimDevice."""

    def __init__(self, devices, label, opened):
        self.devices, self.label, self.opened = devices, label, opened
        self.dev = None
        self.gatt = None
        self.connected = False
        self.reads = 0
        self.disconnects = 0
        self.unsubscribed = 0

    async def connect(self, address, name=""):
        if address not in self.devices:
            raise OSError(f"{address} not found")
        self.dev = self.devices[address]
        self.gatt = FakeGatt(self)
        self.connected = True
        self.opened.append((self.label, address))

    async def disconnect(self):
        self.connected = False
        self.disconnects += 1
        if self.dev:
            self.dev.notify_cb = None

    async def start_notify(self, uuid, cb):
        assert uuid == pp.STATUS_UUID
        assert self.dev.notify_cb is None, "subscribed twice"
        self.dev.notify_cb = cb

    async def stop_notify(self, uuid):
        assert uuid == pp.STATUS_UUID
        self.unsubscribed += 1
        self.dev.notify_cb = None


class World:
    def __init__(self, *devices):
        self.devices = {d.address: d for d in devices}
        self.opened = []
        self.links = []
        self.logs = []
        self.statuses = []

    def make_link(self, label):
        link = FakeLink(self.devices, label, self.opened)
        self.links.append(link)
        return link

    def orchestrator(self, **kw):
        kw.setdefault("timeout", 2.0)
        kw.setdefault("fail_grace", 0.2)
        kw.setdefault("poll", 0.05)
        kw.setdefault("start_settle", 0.0)
        return pp.PairingOrchestrator(self.make_link, log=self.logs.append,
                                      on_status=lambda label, st: self.statuses.append((label, st.state)),
                                      **kw)


def _pair(world, central=A[0], peripheral=B[0], **kw):
    return asyncio.run(world.orchestrator(**kw).pair((central, "dev-c"), (peripheral, "dev-p")))


# ---- the orchestrator ---------------------------------------------------------------
def test_pair_both_devices():
    c, p = SimDevice(A[0]), SimDevice(B[0])
    world = World(c, p)
    out = _pair(world)
    assert out.ok and out.message().startswith("both devices paired")
    # START to the peripheral first, each with the other's own address
    assert [w.label for w in world.links] == ["central", "peripheral"]
    assert world.opened == [("peripheral", B[0]), ("central", A[0])]
    assert p.controls == [pp.encode_start(pp.Role.PERIPHERAL, *A)]
    assert c.controls == [pp.encode_start(pp.Role.CENTRAL, *B)]
    # Followed live, then both links closed
    assert ("central", pp.State.ARMED) in world.statuses
    assert ("peripheral", pp.State.PAIRED) in world.statuses
    assert not any(link.connected for link in world.links)


def test_refusals_before_start():
    for c, p, why in (
            (SimDevice(A[0], prov_state=1), SimDevice(B[0]), "central device is not provisioned"),
            (SimDevice(A[0]), SimDevice(B[0], prov_state=2), "peripheral device is not provisioned"),
            (SimDevice(A[0], state=pp.State.CERT_EXCHANGE), SimDevice(B[0]), "pairing already")):
        world = World(c, p)
        with pytest.raises(pp.PairingError, match=why):
            _pair(world)
        assert not c.controls and not p.controls, "no START when a check fails"
        assert not any(link.connected for link in world.links)
    with pytest.raises(pp.PairingError, match="two different"):
        _pair(World(SimDevice(A[0])), central=A[0], peripheral=A[0].lower())


def _bonded(address, peer, role=pp.Role.CENTRAL):
    dev = SimDevice(address, state=pp.State.PAIRED)
    dev.peer, dev.peer_type, dev.role = peer, 1, role
    return dev


def test_paired_with_each_other():
    st = lambda d: pp.parse_status(d.status_bytes())
    a, b = _bonded(A[0], B[0]), _bonded(B[0], A[0].lower(), pp.Role.PERIPHERAL)
    assert pp.paired_with_each_other(st(a), st(b)) and pp.paired_with_each_other(st(b), st(a))
    assert not pp.paired_with_each_other(st(a), None)
    assert not pp.paired_with_each_other(st(a), st(SimDevice(B[0]))), "B unpaired"
    assert not pp.paired_with_each_other(st(a), st(_bonded(B[0], C_ADDR))), "B bonded elsewhere"
    assert not pp.paired_with_each_other(st(SimDevice(A[0], state=pp.State.PAIRED)),
                                         st(SimDevice(B[0], state=pp.State.PAIRED))), "no peers"


def test_devices_paired_with_each_other_are_not_paired_again():
    c, p = _bonded(A[0], B[0]), _bonded(B[0], A[0], pp.Role.PERIPHERAL)
    world = World(c, p)
    with pytest.raises(pp.PairingError, match="paired with each other already"):
        _pair(world)
    assert not c.controls and not p.controls, "no START"
    assert not any(link.connected for link in world.links)
    # Once one of them is unpaired, the other's stale bond does not block a new run
    asyncio.run(world.orchestrator().unpair(B[0]))
    assert _pair(World(c, p)).ok


def test_unknown_device_raises_and_closes():
    world = World(SimDevice(A[0]))
    with pytest.raises(OSError):
        _pair(world)
    assert not any(link.connected for link in world.links)


def test_start_refused_by_the_device():
    c, p = SimDevice(A[0]), SimDevice(B[0])
    p.refuse_write = "ATT error 0xfe"
    with pytest.raises(RuntimeError, match="0xfe"):
        _pair(World(c, p))
    assert not c.controls


def test_one_device_fails_the_other_follows():
    c = SimDevice(A[0], outcome=("fail", pp.Error.PEER_CERT, 5))
    p = SimDevice(B[0], outcome="lost")
    c.peer_dev, p.peer_dev = p, c
    out = _pair(World(c, p))
    assert not out.ok
    assert out.central.error == pp.Error.PEER_CERT
    assert out.peripheral.error == pp.Error.LINK_LOST
    assert "central: the peer's certificate was rejected (BAD_SIG)" in out.message()
    assert "peripheral: the link between the devices dropped" in out.message()


def test_failure_without_the_other_settling_ends_after_the_grace():
    c = SimDevice(A[0], outcome=("fail", pp.Error.OOB_SIG, 0))
    p = SimDevice(B[0], outcome="hang")
    out = _pair(World(c, p))
    assert not out.ok and out.central.failed and out.peripheral.state == pp.State.OOB_EXCHANGE


def test_time_limit_cancels_both():
    c, p = SimDevice(A[0], outcome="hang"), SimDevice(B[0], outcome="hang")
    world = World(c, p)
    out = _pair(world, timeout=0.2)
    assert pp.encode_cancel() in c.controls and pp.encode_cancel() in p.controls
    assert out.central.error == pp.Error.CANCELLED and not out.ok
    assert "no result in time: cancelling" in world.logs


def test_cancelled_run_cancels_both_devices():
    c, p = SimDevice(A[0], outcome="hang"), SimDevice(B[0], outcome="hang")
    world = World(c, p)

    async def go():
        task = asyncio.ensure_future(world.orchestrator().pair((A[0], ""), (B[0], "")))
        while c.state != pp.State.OOB_EXCHANGE:
            await asyncio.sleep(0.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(go())
    assert pp.encode_cancel() in c.controls and pp.encode_cancel() in p.controls
    assert not any(link.connected for link in world.links)


def test_an_older_paired_status_is_not_this_runs():
    """Both were paired before: their PAIRED statuses until START is processed
    must not end the run at once (START_SETTLE)."""
    c = SimDevice(A[0], state=pp.State.PAIRED, outcome="hang")
    p = SimDevice(B[0], state=pp.State.PAIRED, outcome="hang")
    world = World(c, p)
    out = _pair(world, timeout=0.3, start_settle=0.01)
    assert not out.ok, "the new run never finished"


def test_lost_notifications_are_covered_by_reads():
    c, p = SimDevice(A[0]), SimDevice(B[0])
    world = World(c, p)
    orch = world.orchestrator()
    real = FakeLink.start_notify

    async def no_notify(self, uuid, cb):
        await real(self, uuid, lambda *_: None)
    FakeLink.start_notify = no_notify
    try:
        out = asyncio.run(orch.pair((A[0], ""), (B[0], "")))
    finally:
        FakeLink.start_notify = real
    assert out.ok
    assert sum(link.reads for link in world.links) > 2


def test_probe_and_unpair():
    dev = SimDevice(A[0], state=pp.State.PAIRED)
    dev.peer, dev.peer_type, dev.role = B[0], 1, 2
    world = World(dev)
    st = asyncio.run(world.orchestrator().probe(A[0], "dev"))
    assert st.paired and st.peer == B[0] and st.own == A[0]
    st = asyncio.run(world.orchestrator().unpair(A[0], "dev"))
    assert dev.controls == [pp.encode_unpair()]
    assert st.state == pp.State.IDLE and st.peer == ""
    assert "dev: UNPAIR sent" in world.logs
    assert not any(link.connected for link in world.links)


# ---- links lent by the GUI's Device page (existing=) ------------------------------
def _lent(world):
    """Connect a link to each device, as the Device page would; -> address -> link."""
    links = {}
    for addr in world.devices:
        link = world.make_link(f"board {addr[-5:]}")
        asyncio.run(link.connect(addr))
        links[addr] = link
    world.opened.clear()
    return links


def _lent_orchestrator(world, links, **kw):
    kw.setdefault("timeout", 2.0)
    kw.setdefault("fail_grace", 0.2)
    kw.setdefault("poll", 0.05)
    kw.setdefault("start_settle", 0.0)
    return pp.PairingOrchestrator(existing=lambda a: links.get(a.upper()), log=world.logs.append,
                                  on_status=lambda label, st: world.statuses.append((label, st.state)),
                                  **kw)


def test_pair_on_lent_links():
    c, p = SimDevice(A[0]), SimDevice(B[0])
    world = World(c, p)
    links = _lent(world)
    orch = _lent_orchestrator(world, links)
    out = asyncio.run(orch.pair((A[0], "dev-c"), (B[0], "dev-p")))
    assert out.ok
    assert world.opened == [], "no connect of its own"
    assert all(link.connected and link.disconnects == 0 for link in links.values()), "kept up"
    assert all(link.unsubscribed == 1 for link in links.values()), "STATUS unsubscribed"
    assert "peripheral: using the link to dev-p" in world.logs
    # Again on the same links: a second subscription would have failed
    asyncio.run(orch.unpair(A[0]))
    assert asyncio.run(orch.pair((A[0], ""), (B[0], ""))).ok


def test_probe_and_unpair_on_a_lent_link():
    dev = SimDevice(A[0], state=pp.State.PAIRED)
    dev.peer, dev.peer_type, dev.role = B[0], 1, 2
    world = World(dev)
    links = _lent(world)
    orch = _lent_orchestrator(world, links)
    assert asyncio.run(orch.probe(A[0], "dev")).paired
    assert asyncio.run(orch.unpair(A[0], "dev")).state == pp.State.IDLE
    link = links[A[0]]
    assert link.connected and link.disconnects == 0 and link.unsubscribed == 2


def test_a_device_without_a_link_is_refused():
    world = World(SimDevice(A[0]), SimDevice(B[0]))
    links = _lent(world)
    del links[B[0]]
    orch = _lent_orchestrator(world, links)
    with pytest.raises(pp.PairingError, match="dev-p is not connected"):
        asyncio.run(orch.pair((A[0], "dev-c"), (B[0], "dev-p")))
    # A lent link that dropped before the run
    links = _lent(World(SimDevice(A[0]), SimDevice(B[0])))
    links[B[0]].connected = False
    with pytest.raises(pp.PairingError, match="the peripheral device is not connected"):
        asyncio.run(_lent_orchestrator(world, links).pair((A[0], ""), (B[0], "")))
    assert links[A[0]].connected, "the other board's link is left alone"


# ---- CONTROL is the trusted host's (host authentication) --------------------------
class _AuthGatt:
    """CONTROL refused with ATT 0x08 for the first `refusals` writes."""

    def __init__(self, refusals, error=None):
        self.refusals = refusals
        self.writes = 0
        self.error = error or OSError("Protocol Error 0x08: Insufficient Authorization")

    async def write_gatt_char(self, uuid, data, response=False):
        self.writes += 1
        if self.writes <= self.refusals:
            raise self.error


def _auth_device(gatt):
    link = types.SimpleNamespace(gatt=gatt)
    return pp.PairingDevice(link, "AA", label="central")


def test_control_waits_for_trust_on_a_bonded_link():
    gatt = _AuthGatt(refusals=2)
    asyncio.run(_auth_device(gatt).command(pp.encode_cancel(), delay=0.0))
    assert gatt.writes == 3


def test_control_refused_for_an_untrusted_pc():
    gatt = _AuthGatt(refusals=99)
    with pytest.raises(pp.PairingError, match="does not trust this PC"):
        asyncio.run(_auth_device(gatt).command(pp.encode_cancel(), auth_retries=3, delay=0.0))
    assert gatt.writes == 4


def test_other_control_errors_are_not_retried():
    gatt = _AuthGatt(refusals=1, error=OSError("Protocol Error 0x0d: Invalid Attribute Value Length"))
    with pytest.raises(OSError, match="0x0d"):
        asyncio.run(_auth_device(gatt).command(b"\x01", delay=0.0))
    assert gatt.writes == 1


def test_authorization_error_detection():
    assert pp.is_authorization_error(OSError("Insufficient Authorization"))
    assert pp.is_authorization_error(OSError("ATT error 0x08"))
    e = OSError("x")
    e.att_error = 0x08
    assert pp.is_authorization_error(e)
    assert not pp.is_authorization_error(OSError("Insufficient Encryption (0x0f)"))
