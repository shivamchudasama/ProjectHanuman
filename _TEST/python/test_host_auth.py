# SPDX-License-Identifier: MIT
"""Host authentication, PC side (_TOOLS/BleHostGUI/blehost/protocols/host_auth.py):
the codecs and the cryptography against the wire.json "host_auth" vectors (made
by an independent generator), and HostAuthSession against a simulated device
that follows _DOC/HostAuth/PROTOCOL.md (the rules of _ASW/_HOST_AUTH/HostAuth.c),
doing the device's half of the cryptography for real.

The simulated device is built from the PC's own SETU pieces, wired back to back
as in test_provisioning.py: its Server is a SETUReceiver, its Client a SETUClient
writing into the PC's receiver."""

import asyncio
import hashlib
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import setu_client
import setu_receiver
from blehost.pki.authority import CertificateAuthority
from blehost.pki.host import is_host_certificate
from blehost.protocols import host_auth as ha
from blehost.protocols import setu as setu_proto


# ---- vectors ---------------------------------------------------------------------
@pytest.fixture(scope="module")
def hv(vectors):
    return vectors["host_auth"]


def test_constants_match_the_vectors(hv):
    a = hv["app_types"]
    assert (ha.STATUS_REQ, ha.STATUS, ha.HELLO, ha.CHALLENGE, ha.FINISH, ha.RESULT, ha.REFUSED) == (
        a["STATUS_REQ"], a["STATUS"], a["HELLO"], a["CHALLENGE"], a["FINISH"], a["RESULT"], a["REFUSED"])
    assert [ha.APP_FIRST, ha.APP_LAST] == hv["app_type_range"]
    assert {v: k for k, v in hv["states"].items()} == ha.STATES
    assert {v: k for k, v in hv["results"].items()} == ha.RESULT_STATUS
    assert (ha.FLAG_WINDOW_OPEN, ha.FLAG_HOST_BOND) == (hv["flags"]["WINDOW_OPEN"], hv["flags"]["HOST_BOND"])
    assert ha.VERSION == hv["version"]
    assert (ha.NONCE_LEN, ha.POINT_LEN, ha.SIG_LEN, ha.HASH_LEN) == (
        hv["nonce_len"], hv["point_len"], hv["sig_len"], hv["hash_len"])
    assert ha.HELLO_HDR_LEN + 1 == hv["hello_min_len"]
    assert ha.CHALLENGE_HDR_LEN == hv["challenge_header_len"]
    assert ha.MAX_CERT_LEN == hv["cert_max_len"]


# ---- the advert ----------------------------------------------------------------------
def adv_data(frame_hex: str) -> dict:
    """A wire.json advert frame as bleak hands it over: {company ID: the rest}."""
    raw = bytes.fromhex(frame_hex)
    return {int.from_bytes(raw[:2], "little"): raw[2:]}


def test_advert_constants_match_the_vectors(hv):
    adv = hv["advert"]
    assert (ha.ADV_COMPANY_ID, ha.ADV_FORMAT) == (adv["company_id"], adv["format"])
    assert (ha.ADV_FLAG_PROVISIONED, ha.ADV_FLAG_HOST_BOND) == (
        adv["flags"]["PROVISIONED"], adv["flags"]["HOST_BOND"])


def test_advert_vectors_decode(hv):
    frames = {f["name"]: adv_data(f["hex"]) for f in hv["advert"]["frames"]}
    assert ha.parse_adv(frames["unprovisioned"]) == ha.AdvState(False, False)
    assert ha.parse_adv(frames["provisioned"]) == ha.AdvState(True, False)
    assert ha.parse_adv(frames["provisioned_host"]) == ha.AdvState(True, True)


@pytest.mark.parametrize("data", [None, {}, {0x0059: bytes([1, 3])}, {0xFFFF: bytes([1])},
                                  {0xFFFF: bytes([2, 3])}])
def test_advert_absent_or_foreign(data):
    # Older firmware, another company's data, too short, another format
    assert ha.parse_adv(data) is None


def _keys(held):
    removed = []

    async def is_paired(addr):
        return addr in held

    async def unpair(addr):
        removed.append(addr)
        return "unpaired"
    return is_paired, unpair, removed


@pytest.mark.parametrize("flags, held, expect", [
    (0x00, True, "unpaired"),      # erased: unprovisioned, no host bond
    (0x01, True, "unpaired"),      # Button 3 held / host forgotten
    (0x03, True, None),            # a host bond: maybe this PC's, keys stay
    (0x00, False, None),           # nothing held here
])
def test_forget_stale_keys(flags, held, expect):
    is_paired, unpair, removed = _keys({"AA:BB"} if held else set())
    got = asyncio.run(ha.forget_stale_keys("AA:BB", {0xFFFF: bytes([1, flags])}, is_paired, unpair))
    assert got == expect and removed == (["AA:BB"] if expect else [])


def test_forget_stale_keys_without_an_advert():
    is_paired, unpair, removed = _keys({"AA:BB"})
    assert asyncio.run(ha.forget_stale_keys("AA:BB", {}, is_paired, unpair)) is None
    assert removed == [], "older firmware says nothing: the keys may be good"


def test_short_vectors_decode(hv):
    s = {x["name"]: bytes.fromhex(x["hex"]) for x in hv["shorts"]}
    st = ha.parse_status(s["status_trusted"][2:])
    assert st.trusted and st.host_bonded and not st.window_open
    st = ha.parse_status(s["status_open_window"][2:])
    assert st.state == ha.OPEN and st.window_open
    assert ha.parse_status(s["status_unprovisioned"][2:]).state_name == "UNPROVISIONED"
    assert ha.parse_result(s["result_finish_ok"][2:]) == (ha.FINISH, 0, 0)
    ref, st_, det = ha.parse_result(s["result_hello_bad_cert"][2:])
    assert ha.result_text(ref, st_, det) == "HELLO BAD_CERT (BAD_PROFILE)"
    assert setu_proto.decode_frame(s["refused_fs_cmd"])[1].startswith("REFUSED")
    with pytest.raises(ValueError):
        ha.parse_status(b"\x01")
    with pytest.raises(ValueError):
        ha.parse_result(b"\x62\x00")


def test_handshake_vector(hv):
    h = {k: (bytes.fromhex(v) if isinstance(v, str) else v) for k, v in hv["handshake"].items()}
    t = ha.transcript(h["nonce_host"], h["nonce_device"], h["point_host"], h["point_device"],
                      h["host_cert"], h["device_cert"])
    assert t == h["transcript"]
    host_eph = ec.derive_private_key(int.from_bytes(h["host_eph_private_key"], "big"), ec.SECP256R1())
    dev_q = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), h["point_device"])
    z = host_eph.exchange(ec.ECDH(), dev_q)
    assert z == h["secret"]
    assert ha.passkey(z, h["nonce_host"], h["nonce_device"], t) == h["passkey"]
    dev_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), h["device_public_key"])
    host_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), h["host_public_key"])
    assert ha.verify_raw(dev_pub, b"dev" + t, h["sig_device"])
    assert ha.verify_raw(host_pub, b"host" + t, h["sig_host"])
    # The roles are bound in: neither signature passes as the other's
    assert not ha.verify_raw(dev_pub, b"host" + t, h["sig_device"])
    assert not ha.verify_raw(host_pub, b"dev" + t, h["sig_host"])
    assert not ha.verify_raw(host_pub, b"host" + t, h["sig_host"][:-1])
    # Frames
    assert ha.build_hello(h["nonce_host"], h["point_host"], h["host_cert"]) == h["hello"]
    ch = ha.parse_challenge(h["challenge"])
    assert (ch.nonce, ch.point, ch.signature, ch.cert_der) == (
        h["nonce_device"], h["point_device"], h["sig_device"], h["device_cert"])
    assert h["finish"] == bytes([ha.SIG_LEN, ha.FINISH]) + h["sig_host"]
    # Certificates: the device's passes for a device, the host's does not
    ca = x509.load_der_x509_certificate(h["ca_cert"])
    ha.check_device_certificate(h["device_cert"], ca)
    with pytest.raises(ha.HostAuthError):
        ha.check_device_certificate(h["host_cert"], ca)
    assert is_host_certificate(x509.load_der_x509_certificate(h["host_cert"]))


def test_codec_errors():
    with pytest.raises(ValueError):
        ha.build_hello(b"\x00" * 15, b"\x04" * 65, b"c")
    with pytest.raises(ValueError):
        ha.build_hello(b"\x00" * 16, b"\x04" * 65, b"")
    with pytest.raises(ValueError):
        ha.build_hello(b"\x00" * 16, b"\x04" * 65, b"c" * 1025)
    with pytest.raises(ValueError):
        ha.parse_challenge(bytes([1]) + bytes(ha.CHALLENGE_HDR_LEN - 1))
    with pytest.raises(ValueError):
        ha.parse_challenge(bytes([2]) + bytes(ha.CHALLENGE_HDR_LEN + 10))
    assert ha.passkey(bytes(32), bytes(16), bytes(16), bytes(32)) <= 999999


# ---- a simulated device ----------------------------------------------------------
class _Link:
    def __init__(self, target, mtu=247):
        self.target = target
        self.mtu_size = mtu

    async def write_gatt_char(self, uuid, data, response=False):
        self.target().on_write(bytes(data))
        await asyncio.sleep(0)


def _device_cert(ca, key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "00112233-4455-5677-8899-aabbccddeeff")])
    ku = x509.KeyUsage(True, False, False, False, True, False, False, False, False)
    csr = (x509.CertificateSigningRequestBuilder().subject_name(name).add_extension(ku, critical=True)
           .sign(key, hashes.SHA256()))
    return ca.sign_csr(csr.public_bytes(serialization.Encoding.DER)).der


class FakeHostAuthDevice:
    """The device side per HostAuth.c: HELLO is checked against its CA (host
    role), answered with CHALLENGE to the PC's service; FINISH is verified; the
    one pairing it then allows must use the derived passkey, and makes the PC
    the trusted host."""

    def __init__(self, ca, state=ha.OPEN):
        self.ca = ca
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert_der = _device_cert(ca, self.key)
        self.state = state
        self.window = True
        self.host_bonded = state in (ha.HOST_BONDED, ha.TRUSTED)
        self.passkey = None
        self.t = None
        self.host_key = None
        self.sign_with = None                  # another key: a device that cannot prove itself
        self.cert_override = None              # send another certificate
        self.silent_challenge = False
        self.finish_result = None              # force a RESULT for FINISH
        self.paired_with = []
        log = lambda *_: None                  # noqa: E731
        self.pc_client = setu_client.SETUClient(_Link(lambda: self.rx), log=log)
        self.pc_receiver = setu_receiver.SETUReceiver(lambda f: self.dev_client.on_notify(0, f), log=log)
        self.rx = setu_receiver.SETUReceiver(lambda f: self.pc_client.on_notify(0, f),
                                             accept=self._accept, log=log)
        self.dev_client = setu_client.SETUClient(_Link(lambda: self.pc_receiver), log=log)
        self.task = None

    def _short(self, app_type, payload):
        self.pc_client.on_notify(0, bytearray(setu_client.frame(app_type, payload)))

    def _result(self, ref, st, detail=0):
        self._short(ha.RESULT, bytes([ref, st, detail]))

    def _status(self):
        flags = (ha.FLAG_WINDOW_OPEN if self.window else 0) | (ha.FLAG_HOST_BOND if self.host_bonded else 0)
        self._short(ha.STATUS, bytes([self.state, flags]))

    def _accept(self, app_type, total):
        if app_type != ha.HELLO or self.state in (ha.UNPROVISIONED, ha.TRUSTED):
            code = 0x01
        elif self.state == ha.HOST_BONDED:
            code = 0x05
        elif self.state != ha.OPEN:
            code = 0x07
        elif not ha.HELLO_HDR_LEN < total <= ha.HELLO_HDR_LEN + ha.MAX_CERT_LEN:
            code = 0x02
        else:
            return True
        asyncio.get_running_loop().call_soon(self._result, app_type, code)
        return False

    async def _on_hello(self, data):
        if data[0] != ha.VERSION:
            return self._result(ha.HELLO, 0x02, data[0])
        nh, qh, cert_der = data[1:17], data[17:82], data[82:]
        cert = x509.load_der_x509_certificate(cert_der)
        try:
            cert.verify_directly_issued_by(self.ca.certificate)
        except Exception:
            return self._result(ha.HELLO, 0x03, 0x05)
        if not is_host_certificate(cert):
            return self._result(ha.HELLO, 0x03, 0x08)
        self.host_key = cert.public_key()
        eph = ec.generate_private_key(ec.SECP256R1())
        nd = os.urandom(16)
        qd = ha.point_of(eph)
        dev_cert = self.cert_override or self.cert_der
        self.t = ha.transcript(nh, nd, qh, qd, cert_der, dev_cert)
        z = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), qh))
        self.passkey = ha.passkey(z, nh, nd, self.t)
        sig = ha.sign_raw(self.sign_with or self.key, b"dev" + self.t)
        self.state = ha.AWAIT_FINISH
        if self.silent_challenge:
            return
        st = await self.dev_client.send(ha.CHALLENGE, bytes([ha.VERSION]) + nd + qd + sig + dev_cert)
        if st != "OK":
            self.state = ha.OPEN
            self._result(ha.HELLO, 0x0B)

    def _on_finish(self, p):
        if self.state != ha.AWAIT_FINISH:
            return self._result(ha.FINISH, 0x01)
        if self.finish_result is not None:
            self.state = ha.OPEN
            return self._result(ha.FINISH, self.finish_result)
        if len(p) != ha.SIG_LEN or not ha.verify_raw(self.host_key, b"host" + self.t, p):
            self.state = ha.OPEN
            return self._result(ha.FINISH, 0x04)
        self.state = ha.AWAIT_PAIRING
        self._result(ha.FINISH, 0x00)
        self._status()

    async def pair(self, pk):
        """The PC's LE SC passkey entry: only after FINISH, only with the passkey."""
        self.paired_with.append(pk)
        if self.state != ha.AWAIT_PAIRING or pk != self.passkey:
            raise RuntimeError("pairing failed: authentication failure")
        self.state = ha.TRUSTED
        self.host_bonded = True
        self._status()

    async def run(self):
        while True:
            s = asyncio.ensure_future(self.rx.short_q.get())
            o = asyncio.ensure_future(self.rx.results.get())
            done, pending = await asyncio.wait({s, o}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            if s in done:
                t, p = s.result()
                if t == ha.STATUS_REQ:
                    self._status()
                elif t == ha.FINISH:
                    self._on_finish(p)
            if o in done:
                r = o.result()
                if r.status == "OK" and r.app_type == ha.HELLO:
                    await self._on_hello(r.data)

    async def __aenter__(self):
        self.task = asyncio.ensure_future(self.run())
        return self

    async def __aexit__(self, *exc):
        self.task.cancel()

    def session(self, cred, pair=None, steps=None):
        return ha.HostAuthSession(self.pc_client, self.pc_receiver, cred, pair=pair or self.pair,
                                  log=lambda *_: None, step=(steps.append if steps is not None else None))


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority.create(str(tmp_path / "ca"), {"CN": "Test CA"})


@pytest.fixture
def cred(ca, tmp_path):
    return ca.issue_host("Test Host", str(tmp_path / "host"))


def run(coro):
    return asyncio.run(coro)


# ---- the session -----------------------------------------------------------------
def test_authenticates_and_pairs(ca, cred):
    steps = []

    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            got = await dev.session(cred, steps=steps).run()
            return dev, got
    dev, got = run(go())
    assert dev.state == ha.TRUSTED
    assert dev.paired_with == [dev.passkey] and got.passkey == dev.passkey
    assert got.device_cert.public_key() == dev.key.public_key()
    assert steps == ["reading the device's state", "sending HELLO", "waiting for the device's CHALLENGE",
                     "checking the device's certificate", "sending FINISH", "pairing (passkey entry)",
                     "waiting for the device to trust this host", "trusted"]


def test_trusted_host_returns_at_once(ca, cred):
    async def go():
        async with FakeHostAuthDevice(ca, state=ha.TRUSTED) as dev:
            await dev.session(cred).run()
            return dev
    assert run(go()).paired_with == []


def test_states_that_stop_the_run(ca, cred):
    async def go(state):
        async with FakeHostAuthDevice(ca, state=state) as dev:
            await dev.session(cred).run()
    with pytest.raises(ha.HostAuthError, match="another host is bonded") as e:
        run(go(ha.HOST_BONDED))
    assert e.value.status == 0x05
    with pytest.raises(ha.HostAuthError, match="not provisioned"):
        run(go(ha.UNPROVISIONED))


def test_host_of_another_ca_is_refused(ca, tmp_path):
    other = CertificateAuthority.create(str(tmp_path / "other"), {"CN": "Other CA"})
    foreign = other.issue_host("Foreign", str(tmp_path / "foreign"))

    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            await dev.session(foreign).run()
    with pytest.raises(ha.HostAuthError, match="BAD_CERT") as e:
        run(go())
    assert e.value.status == 0x03 and e.value.detail == 0x05


def test_device_that_cannot_prove_itself(ca, cred):
    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            dev.sign_with = ec.generate_private_key(ec.SECP256R1())
            await dev.session(cred).run()
            return dev
    with pytest.raises(ha.HostAuthError, match="signature does not verify"):
        run(go())


def test_device_of_another_fleet(ca, cred, tmp_path):
    other = CertificateAuthority.create(str(tmp_path / "other"), {"CN": "Other CA"})

    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            dev.cert_override = _device_cert(other, dev.key)
            await dev.session(cred).run()
    with pytest.raises(ha.HostAuthError, match="not issued by this CA"):
        run(go())


def test_a_host_certificate_is_no_device(ca, cred):
    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            dev.cert_override = cred.cert_der
            await dev.session(cred).run()
    with pytest.raises(ha.HostAuthError, match="keyAgreement"):
        run(go())


def test_device_certificate_with_the_host_role(ca):
    from blehost.pki import negative

    key = ec.generate_private_key(ec.SECP256R1())
    cert = negative._dev_cert(ca.key, ca.certificate.subject,
                              x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dev")]),
                              key.public_key(), client_auth=True)
    with pytest.raises(ha.HostAuthError, match="host certificate"):
        ha.check_device_certificate(cert.public_bytes(serialization.Encoding.DER), ca.certificate)
    with pytest.raises(ha.HostAuthError, match="no valid certificate"):
        ha.check_device_certificate(b"\x30\x00", ca.certificate)


def test_finish_refused(ca, cred):
    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            dev.finish_result = 0x04
            await dev.session(cred).run()
    with pytest.raises(ha.HostAuthError, match="refused FINISH: FINISH BAD_SIG") as e:
        run(go())
    assert e.value.status == 0x04


def test_wrong_passkey_is_not_trusted(ca, cred):
    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            async def bad_pair(pk):
                await dev.pair((pk + 1) % 1000000)
            await dev.session(cred, pair=bad_pair).run()
    with pytest.raises(RuntimeError, match="authentication failure"):
        run(go())


def test_no_challenge_times_out(ca, cred, monkeypatch):
    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            dev.silent_challenge = True
            await dev.session(cred).authenticate(timeout=0.3)
    with pytest.raises(ha.HostAuthError, match="no CHALLENGE"):
        run(go())


def test_busy_device_refuses_hello(ca, cred):
    async def go():
        async with FakeHostAuthDevice(ca, state=ha.AWAIT_FINISH) as dev:
            await dev.session(cred).authenticate()
    with pytest.raises(ha.HostAuthError, match="HELLO refused: HELLO BUSY"):
        run(go())


def test_without_pairing_function(ca, cred):
    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            await ha.HostAuthSession(dev.pc_client, dev.pc_receiver, cred, pair=None,
                                     log=lambda *_: None).run()
    with pytest.raises(ha.HostAuthError, match="cannot pair"):
        run(go())


def test_refused_messages_are_named(ca, cred):
    logs = []

    async def go():
        async with FakeHostAuthDevice(ca) as dev:
            s = ha.HostAuthSession(dev.pc_client, dev.pc_receiver, cred, pair=dev.pair, log=logs.append)
            dev._short(ha.REFUSED, bytes([0x27]))
            return await _status_after_refusal(dev, s)
    st = run(go())
    assert st.state == ha.OPEN
    assert any("device refused 0x27" in line and "untrusted host" in line for line in logs)


async def _status_after_refusal(dev, s):
    await s.client.send_short(ha.STATUS_REQ, b"")
    p = await s._wait_short(ha.STATUS, lambda p: len(p) >= 2, 2.0, "AUTH_STATUS")
    return ha.parse_status(p)


def test_transcript_binds_every_value():
    base = (b"\x01" * 16, b"\x02" * 16, b"\x04" * 65, b"\x05" * 65, b"host", b"dev")
    t0 = ha.transcript(*base)
    for i in range(len(base)):
        changed = list(base)
        changed[i] = bytes([changed[i][0] ^ 1]) + changed[i][1:]
        assert ha.transcript(*changed) != t0
    assert t0 == hashlib.sha256(b"PH-HOSTAUTH-1" + b"".join(base[:4]) + hashlib.sha256(b"host").digest()
                                + hashlib.sha256(b"dev").digest()).digest()
