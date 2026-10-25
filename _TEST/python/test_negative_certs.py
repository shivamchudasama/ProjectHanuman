# SPDX-License-Identifier: MIT
"""The negative certificate set (_TOOLS/BleHostGUI/blehost/pki/negative.py) that
drives the device's verification on hardware: every case must carry exactly the
defect its name and expected RESULT status claim, and nothing else, so a device
answer that differs points at the device, not at the test data."""

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import SignatureAlgorithmOID

from blehost.pki import negative as neg
from blehost.pki.authority import CertificateAuthority
from blehost.pki.host import is_host_certificate

P256_SPKI_LEN = 91


@pytest.fixture(scope="module")
def setup(tmp_path_factory, vectors):
    ca = CertificateAuthority.create(str(tmp_path_factory.mktemp("ca")), {"CN": "Good CA"})
    csr_der = bytes.fromhex(vectors["provisioning"]["csr"]["der"])
    cases = {c.name: c for c in neg.negative_cases(ca, csr_der)}
    return ca, x509.load_der_x509_csr(csr_der), cases


def load(case):
    return x509.load_der_x509_certificate(case.der)


def signed_by(cert, issuer_cert):
    try:
        cert.verify_directly_issued_by(issuer_cert)
        return True
    except (InvalidSignature, ValueError):
        return False


def ku(cert):
    return cert.extensions.get_extension_for_class(x509.KeyUsage).value


def is_ca(cert):
    return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca


def test_expected_statuses_and_order(setup):
    _, _, cases = setup
    got = [(c.name, c.app_type, c.expected) for c in cases.values()]
    assert [n for n, t, _ in got if t == neg.CA_CERT] == [n for n, _, _ in got][:6], "CA cases first"
    expected = {"ca_not_der": neg.PARSE, "ca_without_ca_flag": neg.NOT_CA, "ca_not_self_issued": neg.NOT_CA,
                "ca_without_cert_sign": neg.NOT_CA, "ca_bad_self_signature": neg.BAD_SIG,
                "ca_p384": neg.BAD_PROFILE, "dev_other_ca": neg.BAD_SIG, "dev_bad_signature": neg.BAD_SIG,
                "dev_foreign_key": neg.KEY_MISMATCH, "dev_other_subject": neg.SUBJECT_MISMATCH,
                "dev_other_device_cn": neg.SUBJECT_MISMATCH, "dev_ca_flag": neg.BAD_PROFILE, "dev_no_key_agreement": neg.BAD_PROFILE,
                "dev_no_digital_signature": neg.BAD_PROFILE, "dev_sha384": neg.BAD_PROFILE,
                "dev_host_role": neg.BAD_PROFILE}
    assert {n: e for n, _, e in got} == expected
    assert all(0 < len(c.der) <= 1024 for c in cases.values())


def test_ca_cases_have_only_their_defect(setup):
    ca, _, c = setup
    with pytest.raises(ValueError):
        load(c["ca_not_der"])

    cert = load(c["ca_without_ca_flag"])
    assert not is_ca(cert) and cert.subject == cert.issuer and signed_by(cert, cert)

    cert = load(c["ca_not_self_issued"])
    assert is_ca(cert) and cert.subject != cert.issuer and signed_by(cert, ca.certificate)

    cert = load(c["ca_without_cert_sign"])
    assert is_ca(cert) and not ku(cert).key_cert_sign and signed_by(cert, cert)

    cert = load(c["ca_bad_self_signature"])
    assert is_ca(cert) and ku(cert).key_cert_sign and not signed_by(cert, cert)

    cert = load(c["ca_p384"])
    assert isinstance(cert.public_key().curve, ec.SECP384R1)
    assert cert.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256 and signed_by(cert, cert)


def test_device_cases_have_only_their_defect(setup):
    ca, csr, c = setup

    def ok_except(cert, *, by=True, key=True, subject=True, leaf=True, agree=True, sign=True, sha256=True,
                  device_role=True):
        assert signed_by(cert, ca.certificate) == by
        assert (cert.public_key() == csr.public_key()) == key
        assert (cert.subject == csr.subject) == subject
        assert (not is_ca(cert)) == leaf
        assert ku(cert).key_agreement == agree
        assert ku(cert).digital_signature == sign
        assert (cert.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256) == sha256
        assert (not is_host_certificate(cert)) == device_role
        assert cert.issuer == ca.certificate.subject

    ok_except(load(c["dev_other_ca"]), by=False)
    ok_except(load(c["dev_bad_signature"]), by=False)
    ok_except(load(c["dev_foreign_key"]), key=False)
    ok_except(load(c["dev_other_subject"]), subject=False)
    other = load(c["dev_other_device_cn"])
    ok_except(other, subject=False)
    # Only the CN's bytes differ: a length check alone would not catch it
    assert len(other.subject.public_bytes()) == len(csr.subject.public_bytes())
    assert [a.oid for a in other.subject] == [a.oid for a in csr.subject]
    ok_except(load(c["dev_ca_flag"]), leaf=False)
    ok_except(load(c["dev_no_key_agreement"]), agree=False)
    ok_except(load(c["dev_no_digital_signature"]), sign=False)
    ok_except(load(c["dev_sha384"]), sha256=False)
    ok_except(load(c["dev_host_role"]), device_role=False)


def test_key_usage_never_empty(setup):
    # An empty KeyUsage BIT STRING would fail mbedTLS parsing (PARSE), not the rule
    _, _, c = setup
    for case in c.values():
        if case.name == "ca_not_der":
            continue
        assert any(getattr(ku(load(case)), f) for f in ("digital_signature", "key_agreement", "key_cert_sign"))


def test_device_keys_are_p256(setup):
    _, _, c = setup
    for name in ("dev_other_ca", "dev_foreign_key", "dev_ca_flag"):
        spki = load(c[name]).public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)
        assert len(spki) == P256_SPKI_LEN
