# SPDX-License-Identifier: MIT
"""Host credentials (_TOOLS/BleHostGUI/blehost/pki/host.py) and their issuance by
the CA (CertificateAuthority.issue_host): the profile the device requires
(ge_VerifyHostCertificate: CA:FALSE, digitalSignature, EKU clientAuth, issued by
the CA), the folder's contents, and every load error. Also: a device CSR may
not obtain the host role."""

import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from blehost.pki import host as hostmod
from blehost.pki.authority import CaError, CertificateAuthority, CsrRejected
from blehost.pki.host import HostCredential, HostError, is_host_certificate


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority.create(str(tmp_path / "ca"), {"CN": "Test CA"})


def test_issue_writes_a_credential_with_the_host_profile(ca, tmp_path):
    folder = str(tmp_path / "host")
    cred = ca.issue_host("Service laptop", folder, validity_days=30)
    assert sorted(os.listdir(folder)) == ["ca_cert.pem", "host_cert.pem", "host_key.pem"]
    cert = cred.certificate
    cert.verify_directly_issued_by(ca.certificate)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Service laptop"
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and not ku.key_agreement and not ku.key_cert_sign
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert is_host_certificate(cert)
    assert isinstance(cert.public_key().curve, ec.SECP256R1)
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 30
    assert len(cred.cert_der) <= 1024
    # Recorded by the CA, as a host
    entry = ca.issued()[f"{cert.serial_number:x}"]
    assert entry["role"] == "host"


def test_load_round_trip(ca, tmp_path):
    folder = str(tmp_path / "host")
    issued = ca.issue_host("H", folder)
    assert HostCredential.exists(folder)
    cred = HostCredential.load(folder)
    assert cred.cert_der == issued.cert_der
    assert cred.ca_certificate == ca.certificate
    assert cred.name == "CN=H" and cred.fingerprint.count(":") == 31
    assert cred.not_after == issued.not_after


def test_issue_refuses(ca, tmp_path):
    folder = str(tmp_path / "host")
    ca.issue_host("H", folder)
    with pytest.raises(HostError, match="already exists"):
        ca.issue_host("H2", folder)
    with pytest.raises(CaError, match="name"):
        ca.issue_host("", str(tmp_path / "h2"))
    with pytest.raises(CaError, match="one day"):
        ca.issue_host("H", str(tmp_path / "h3"), validity_days=0)


def test_load_errors(ca, tmp_path):
    with pytest.raises(HostError, match="missing"):
        HostCredential.load(str(tmp_path / "nothing"))

    folder = str(tmp_path / "host")
    ca.issue_host("H", folder)
    other = ec.generate_private_key(ec.SECP256R1())
    key_path = os.path.join(folder, hostmod.KEY_FILE)
    good_key = open(key_path, "rb").read()
    with open(key_path, "wb") as f:
        f.write(other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    with pytest.raises(HostError, match="does not match"):
        HostCredential.load(folder)
    with open(key_path, "wb") as f:
        f.write(ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises(HostError, match="P-256"):
        HostCredential.load(folder)
    with open(key_path, "wb") as f:
        f.write(good_key)

    # Another CA in the folder
    other_ca = CertificateAuthority.create(str(tmp_path / "ca2"), {"CN": "Other"})
    with open(os.path.join(folder, hostmod.CA_FILE), "wb") as f:
        f.write(other_ca.certificate.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(HostError, match="not issued by the CA"):
        HostCredential.load(folder)


def test_a_certificate_without_the_host_role_is_no_credential(ca, tmp_path):
    folder = str(tmp_path / "host")
    cred = ca.issue_host("H", folder)
    # The same key, certified without clientAuth
    now = cred.certificate.not_valid_before_utc
    plain = (x509.CertificateBuilder().subject_name(cred.certificate.subject).issuer_name(ca.certificate.subject)
             .public_key(cred.key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(cred.not_after)
             .sign(ca.key, hashes.SHA256()))
    with open(os.path.join(folder, hostmod.CERT_FILE), "wb") as f:
        f.write(plain.public_bytes(serialization.Encoding.PEM))
    assert not is_host_certificate(plain)
    with pytest.raises(HostError, match="clientAuth"):
        HostCredential.load(folder)


def test_device_csr_cannot_ask_for_the_host_role(ca):
    key = ec.generate_private_key(ec.SECP256R1())
    ku = x509.KeyUsage(True, False, False, False, True, False, False, False, False)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dev")]))
           .add_extension(ku, critical=True)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
           .sign(key, hashes.SHA256()))
    with pytest.raises(CsrRejected, match="extendedKeyUsage"):
        ca.sign_csr(csr.public_bytes(serialization.Encoding.DER))
