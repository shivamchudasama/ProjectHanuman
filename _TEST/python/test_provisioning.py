# SPDX-License-Identifier: MIT
"""ProvisioningSession (_TOOLS/BleHostGUI/blehost/protocols/provisioning.py)
against a simulated device that follows _DOC/Provisioning/PROTOCOL.md (the
rules of _ASW/_PROV/Prov.c), plus the protocol constants and decoders against
the wire.json vectors.

The simulated device is built from the PC's own SETU pieces, wired back to
back: its Server is a SETUReceiver, its Client a SETUClient writing
into the PC's receiver (the PC's GATT server in real life)."""

import asyncio
import hashlib
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import setu_client
import setu_receiver
from blehost.pki import negative
from blehost.pki.authority import CertificateAuthority
from blehost.protocols import setu as setu_proto
from blehost.protocols import provisioning as prov


class _Link:
    """Write Without Response into a receiver's DATA."""

    def __init__(self, target, mtu=247):
        self.target = target
        self.mtu_size = mtu

    async def write_gatt_char(self, uuid, data, response=False):
        self.target().on_write(bytes(data))
        await asyncio.sleep(0)


class FakeDevice:
    """The device side of provisioning, per Prov.c: certificates are kept (and
    the CSR deleted) once the device certificate verifies, a provisioned device
    refuses CSR_REQ / CA_CERT / DEV_CERT, and DEPROVISION makes a fresh key and
    CSR with the same subject."""

    def __init__(self, csr_der, has_pc_service=True, state=prov.KEY_READY):
        self.csr = self.first_csr = csr_der
        self.subject =x509.load_der_x509_csr(csr_der).subject
        self._set_key(x509.load_der_x509_csr(csr_der).public_key())
        self.has_pc_service = has_pc_service
        self.state = state
        self.silent = False
        self.ca = None
        self.dev_cert = None
        self.stored = None                     # (CA, device certificate) once provisioned
        self.received = []                     # (appType, DER) of every complete certificate
        self.force_result = {}                 # appType -> RESULT status to answer instead
        self.der_result = {}                   # DER -> RESULT status to answer instead
        log = lambda *_: None                  # noqa: E731
        # PC side: client on the device's service, receiver of the PC's service
        self.pc_client = setu_client.SETUClient(_Link(lambda: self.rx), log=log)
        self.pc_receiver = setu_receiver.SETUReceiver(lambda f: self.dev_client.on_notify(0, f), log=log)
        # device side: its Server, and its Client on the PC's service
        self.rx = setu_receiver.SETUReceiver(lambda f: self.pc_client.on_notify(0, f),
                                       accept=self._accept, log=log)
        self.dev_client = setu_client.SETUClient(_Link(lambda: self.pc_receiver), log=log)
        self.task = None

    def _set_key(self, key):
        self.key = key
        self.status_hash = hashlib.sha256(key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).digest()

    def _wipe(self):
        """DEPROVISION: forget everything, new key and CSR."""
        priv = ec.generate_private_key(ec.SECP256R1())
        b = x509.CertificateSigningRequestBuilder().subject_name(self.subject)
        for ext in x509.load_der_x509_csr(self.first_csr).extensions:   # as the device's DER.c
            value = ext.value
            if isinstance(value, x509.SubjectKeyIdentifier):
                value = x509.SubjectKeyIdentifier.from_public_key(priv.public_key())
            b = b.add_extension(value, ext.critical)
        self.csr = b.sign(priv, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        self._set_key(priv.public_key())
        self.ca = self.dev_cert = self.stored = None
        self.state = prov.KEY_READY

    # ---- replies ------------------------------------------------------------
    def _short(self, app_type, payload):
        if not self.silent:
            self.pc_client.on_notify(0, bytearray(setu_client.frame(app_type, payload)))

    def _result(self, ref, status):
        self._short(prov.RESULT, bytes([ref, status]))

    def _accept(self, app_type, total):
        if app_type not in (prov.CA_CERT, prov.DEV_CERT) or self.state in (prov.NO_KEY, prov.PROVISIONED):
            code = 0x01
        elif app_type == prov.DEV_CERT and self.state < prov.CA_OK:
            code = 0x01
        elif not 0 < total <= prov.MAX_CERT_LEN:
            code = 0x02
        else:
            return True
        asyncio.get_running_loop().call_soon(self._result, app_type, code)
        return False

    # ---- behaviour ----------------------------------------------------------
    async def _on_short(self, t, p):
        if t == prov.GET_STATUS:
            csr_len = len(self.csr) if self.csr else 0
            self._short(prov.STATUS, struct.pack("<BBH", self.state, 0, csr_len) + self.status_hash)
        elif t == prov.DEPROVISION:
            st = self.force_result.get(prov.DEPROVISION, 0x00)
            if st == 0x00:
                self._wipe()
            self._result(prov.DEPROVISION, st)
        elif t == prov.CSR_REQ:
            if self.state in (prov.NO_KEY, prov.PROVISIONED):
                self._result(prov.CSR_REQ, 0x01)
            elif not self.has_pc_service:
                self._result(prov.CSR_REQ, 0x09)
            else:
                st = await self.dev_client.send(prov.CSR, self.csr)
                self._result(prov.CSR, 0x00 if st == "OK" else 0x0B)

    def _verify(self, app_type, der):
        self.received.append((app_type, der))
        if der in self.der_result:
            return self.der_result[der]
        if app_type in self.force_result:
            return self.force_result[app_type]
        cert = x509.load_der_x509_certificate(der)
        if app_type == prov.CA_CERT:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca or cert.subject != cert.issuer:
                return 0x04
            cert.verify_directly_issued_by(cert)
            self.ca = cert
            self.state = prov.CA_OK
            return 0x00
        try:
            cert.verify_directly_issued_by(self.ca)
        except Exception:
            return 0x05
        if cert.public_key() != self.key:
            return 0x06
        if cert.subject != x509.load_der_x509_csr(self.csr).subject:
            return 0x07
        self.dev_cert = cert
        self.stored = (self.ca, cert)
        self.csr = None                        # not needed any more
        self.state = prov.PROVISIONED
        return 0x00

    async def run(self):
        while True:
            s = asyncio.ensure_future(self.rx.short_q.get())
            o = asyncio.ensure_future(self.rx.results.get())
            done, pending = await asyncio.wait({s, o}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            if s in done:
                await self._on_short(*s.result())
            if o in done:
                r = o.result()
                if r.status == "OK":
                    self._result(r.app_type, self._verify(r.app_type, r.data))

    async def __aenter__(self):
        self.task = asyncio.ensure_future(self.run())
        return self

    async def __aexit__(self, *exc):
        self.task.cancel()

    def session(self):
        return prov.ProvisioningSession(self.pc_client, self.pc_receiver, log=lambda *_: None)


@pytest.fixture(scope="session")
def device_csr(vectors):
    return bytes.fromhex(vectors["provisioning"]["csr"]["der"])


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority.create(str(tmp_path / "ca"), {"CN": "Test CA"})


def run(coro):
    return asyncio.run(coro)


# ---- the whole sequence --------------------------------------------------------
def test_provisions_the_device(ca, device_csr):
    steps = []

    async def go():
        async with FakeDevice(device_csr) as dev:
            s = dev.session()
            s.step = steps.append
            out = await s.provision(ca, validity_days=30)
            return dev, out
    dev, out = run(go())
    assert dev.state == prov.PROVISIONED
    assert dev.stored == (ca.certificate, out.device_cert) and dev.csr is None
    assert out.csr == device_csr
    assert dev.ca == ca.certificate and dev.dev_cert == out.device_cert
    out.device_cert.verify_directly_issued_by(ca.certificate)
    assert out.status.state_name == "KEY_READY"
    assert steps[-1] == "provisioned"


def test_provisioned_device_refuses_another_run(ca, device_csr):
    async def go():
        async with FakeDevice(device_csr) as dev:
            await dev.session().provision(ca)
            await dev.session().provision(ca)
    with pytest.raises(prov.ProvisioningError, match="already provisioned.*DEPROVISION") as e:
        run(go())
    assert e.value.status == 0x01


def test_provisioned_device_refuses_csr_and_certificates(ca, device_csr):
    async def go():
        async with FakeDevice(device_csr) as dev:
            out = await dev.session().provision(ca)
            errors = []
            for step in (dev.session().fetch_csr(timeout=1.0),
                         dev.session().send_certificate(prov.CA_CERT, ca.cert_der),
                         dev.session().send_certificate(prov.DEV_CERT, out.device_cert_der)):
                with pytest.raises(prov.ProvisioningError) as e:
                    await step
                errors.append(e.value.status)
            return dev, errors
    dev, errors = run(go())
    assert errors == [0x01, 0x01, 0x01]
    assert dev.state == prov.PROVISIONED


def test_deprovision_then_reprovision_with_another_ca(tmp_path, device_csr):
    ca1 = CertificateAuthority.create(str(tmp_path / "a"))
    ca2 = CertificateAuthority.create(str(tmp_path / "b"))

    async def go():
        async with FakeDevice(device_csr) as dev:
            first = await dev.session().provision(ca1)
            s = dev.session()
            assert not s.wiped
            await s.deprovision()
            assert s.wiped, "the device deleted its bonds: the caller drops the PC's keys"
            st = await dev.session().get_status()
            second = await dev.session().provision(ca2)
            return dev, first, st, second
    dev, first, st, second = run(go())
    assert st.state == prov.KEY_READY and st.csr_len > 0
    assert st.pubkey_sha256 != first.status.pubkey_sha256, "a new key"
    assert second.device_cert.public_key() != first.device_cert.public_key()
    dev.dev_cert.verify_directly_issued_by(ca2.certificate)


def test_deprovision_refused(device_csr):
    async def go():
        async with FakeDevice(device_csr) as dev:
            dev.force_result[prov.DEPROVISION] = 0x01
            await dev.session().deprovision()
    with pytest.raises(prov.ProvisioningError, match="DEPROVISION: BAD_STATE") as e:
        run(go())
    assert e.value.status == 0x01


def test_refused_deprovision_wipes_nothing(device_csr):
    async def go():
        async with FakeDevice(device_csr) as dev:
            dev.force_result[prov.DEPROVISION] = 0x01
            s = dev.session()
            with pytest.raises(prov.ProvisioningError):
                await s.deprovision()
            return s.wiped
    assert run(go()) is False


# ---- provision --negative (setu_client.provision_with_rejections) ------------
@pytest.fixture
def few_cases(monkeypatch):
    """Two cases the fake device answers as told (it does not parse X.509 for them)."""
    cases = [negative.Case("ca_bad", negative.CA_CERT, b"\x30\x03\x01\x01\xaa", negative.NOT_CA),
             negative.Case("dev_bad", negative.DEV_CERT, b"\x30\x03\x01\x01\xbb", negative.BAD_SIG)]
    monkeypatch.setattr(negative, "negative_cases", lambda _ca, _csr: cases)
    return cases


@pytest.mark.parametrize("provisioned_before", [False, True])
def test_negative_run_wipes_rejects_then_provisions(ca, device_csr, few_cases, provisioned_before):
    async def go():
        async with FakeDevice(device_csr) as dev:
            for c in few_cases:
                dev.der_result[c.der] = c.expected
            if provisioned_before:
                await dev.session().provision(ca)
                dev.received.clear()
            failures, out = await setu_client.provision_with_rejections(dev.session(), ca, 30)
            return dev, failures, out
    dev, failures, out = run(go())
    assert failures == 0
    assert dev.state == prov.PROVISIONED and dev.dev_cert == out.device_cert
    # Rejected CA, good CA, rejected device certificate, good device certificate
    assert dev.received == [(prov.CA_CERT, few_cases[0].der), (prov.CA_CERT, ca.cert_der),
                            (prov.DEV_CERT, few_cases[1].der), (prov.DEV_CERT, out.device_cert_der)]


def test_negative_run_counts_wrong_answers(ca, device_csr, few_cases):
    async def go():
        async with FakeDevice(device_csr) as dev:
            dev.der_result[few_cases[0].der] = few_cases[0].expected
            dev.der_result[few_cases[1].der] = 0x00          # accepted: wrong
            return await setu_client.provision_with_rejections(dev.session(), ca, 30)
    failures, _ = run(go())
    assert failures == 1


# ---- failures -----------------------------------------------------------------
def test_device_without_key(ca, device_csr):
    async def go():
        async with FakeDevice(device_csr, state=prov.NO_KEY) as dev:
            await dev.session().provision(ca)
    with pytest.raises(prov.ProvisioningError, match="NO_KEY"):
        run(go())


def test_pc_service_not_visible(ca, device_csr):
    async def go():
        async with FakeDevice(device_csr, has_pc_service=False) as dev:
            await dev.session().provision(ca)
    with pytest.raises(prov.ProvisioningError, match="NO_PEER_SVC.*not visible") as e:
        run(go())
    assert e.value.status == 0x09


def test_csr_key_must_match_status(ca, device_csr):
    async def go():
        async with FakeDevice(device_csr) as dev:
            dev.status_hash = bytes(32)
            await dev.session().provision(ca)
    with pytest.raises(prov.ProvisioningError, match="not the key"):
        run(go())


@pytest.mark.parametrize("app_type, code, name", [
    (prov.CA_CERT, 0x04, "NOT_CA"), (prov.CA_CERT, 0x03, "PARSE"),
    (prov.DEV_CERT, 0x05, "BAD_SIG"), (prov.DEV_CERT, 0x06, "KEY_MISMATCH"),
    (prov.DEV_CERT, 0x07, "SUBJECT_MISMATCH"), (prov.DEV_CERT, 0x08, "BAD_PROFILE"),
])
def test_device_rejects_a_certificate(ca, device_csr, app_type, code, name):
    async def go():
        async with FakeDevice(device_csr) as dev:
            dev.force_result[app_type] = code
            await dev.session().provision(ca)
    with pytest.raises(prov.ProvisioningError, match=name) as e:
        run(go())
    assert e.value.status == code


def test_refused_at_start_reports_the_reason(device_csr):
    async def go():
        async with FakeDevice(device_csr) as dev:
            await dev.session().send_certificate(prov.DEV_CERT, b"\x30\x00")   # before the CA
    with pytest.raises(prov.ProvisioningError, match="DEV_CERT refused: BAD_STATE") as e:
        run(go())
    assert e.value.status == 0x01


@pytest.mark.parametrize("size", [0, prov.MAX_CERT_LEN + 1])
def test_certificate_size_checked_before_sending(device_csr, size):
    async def go():
        async with FakeDevice(device_csr) as dev:
            await dev.session().send_certificate(prov.CA_CERT, bytes(size))
    with pytest.raises(prov.ProvisioningError, match="1..1024"):
        run(go())


def test_silent_device_times_out(device_csr):
    async def go():
        async with FakeDevice(device_csr) as dev:
            dev.silent = True
            await dev.session().get_status(timeout=0.05)
    with pytest.raises(prov.ProvisioningError, match="no STATUS"):
        run(go())


def test_status_reads_the_device(device_csr):
    async def go():
        async with FakeDevice(device_csr) as dev:
            return await dev.session().get_status(), dev
    st, dev = run(go())
    assert (st.state, st.csr_len, st.pubkey_sha256) == (prov.KEY_READY, len(device_csr), dev.status_hash)


# ---- constants and decoders against wire.json -------------------------------------
def test_constants_match_vectors(vectors):
    p = vectors["provisioning"]
    names = {v: k for k, v in p["app_types"].items()}
    assert prov.APP_TYPE_NAMES == names
    assert prov.STATES == {v: k for k, v in p["states"].items()}
    assert prov.RESULT_STATUS == {v: k for k, v in p["status"].items()}
    assert prov.FLAG_CSR_TX_BUSY == p["flags"]["CSR_TX_BUSY"]
    assert prov.MAX_CERT_LEN == p["max_cert_len"]


def _short(vectors, name):
    s = next(s for s in vectors["provisioning"]["shorts"] if s["name"] == name)
    return s, bytes.fromhex(s["hex"])


@pytest.mark.parametrize("name", ["status_key_ready", "status_csr_busy", "status_provisioned"])
def test_status_vectors_parse(vectors, name):
    s, wire = _short(vectors, name)
    st = prov.parse_status(wire[2:])
    assert (st.state, st.flags, st.csr_len, st.pubkey_sha256.hex()) == \
        (s["state"], s["flags"], s["csr_len"], s["pubkey_sha256"])
    assert st.csr_busy == bool(s["flags"] & 1)


def test_requests_are_the_golden_frames(vectors):
    for name, t in (("get_status", prov.GET_STATUS), ("csr_req", prov.CSR_REQ),
                    ("deprovision", prov.DEPROVISION)):
        assert setu_client.frame(t, b"") == _short(vectors, name)[1]


@pytest.mark.parametrize("name, text", [
    ("result_ca_ok", "RESULT CA_CERT OK"),
    ("result_dev_bad_sig", "RESULT DEV_CERT BAD_SIG"),
    ("result_csr_no_peer", "RESULT CSR_REQ NO_PEER_SVC"),
    ("result_csr_delivered", "RESULT CSR OK"),
    ("result_csr_req_bad_state", "RESULT CSR_REQ BAD_STATE"),
    ("result_deprovision_ok", "RESULT DEPROVISION OK"),
])
def test_monitor_decodes_results(vectors, name, text):
    _, wire = _short(vectors, name)
    assert setu_proto.decode_frame(wire) == ("SHORT", text)


def test_monitor_decodes_status(vectors):
    _, wire = _short(vectors, "status_csr_busy")
    kind, text = setu_proto.decode_frame(wire)
    assert kind == "SHORT" and text.startswith("STATUS CA_OK CSR-busy csr=420 B key=")


def test_short_parsers_reject_short_payloads():
    with pytest.raises(ValueError):
        prov.parse_status(bytes(35))
    with pytest.raises(ValueError):
        prov.parse_result(b"\x24")
