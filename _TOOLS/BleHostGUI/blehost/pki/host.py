"""Host credential: the PC's own key and host certificate, for host
authentication (_DOC/HostAuth/PROTOCOL.md).

A credential lives in a folder of its own, written by
CertificateAuthority.issue_host():
    host_key.pem      host private key (unencrypted PEM: keep the folder private)
    host_cert.pem     host certificate (CA:FALSE, digitalSignature, EKU clientAuth)
    ca_cert.pem       the CA certificate the host certificate chains to; the PC
                      checks the device's certificate against it

The CA's private key is not part of it: a laptop that operates devices in the
field carries the credential only.
"""

import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

DEFAULT_FOLDER = os.path.join(os.path.expanduser("~"), ".blehost", "host")
KEY_FILE, CERT_FILE, CA_FILE = "host_key.pem", "host_cert.pem", "ca_cert.pem"


class HostError(Exception):
    """The credential folder is missing, incomplete, inconsistent or exists."""


def is_host_certificate(cert: x509.Certificate) -> bool:
    """Whether a certificate carries the host role (EKU clientAuth)."""
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.CLIENT_AUTH in eku


@dataclass
class HostCredential:
    folder: str
    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate
    ca_certificate: x509.Certificate

    @staticmethod
    def exists(folder: str = DEFAULT_FOLDER) -> bool:
        return os.path.exists(os.path.join(folder, CERT_FILE))

    @classmethod
    def load(cls, folder: str = DEFAULT_FOLDER) -> "HostCredential":
        try:
            with open(os.path.join(folder, KEY_FILE), "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            with open(os.path.join(folder, CERT_FILE), "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            with open(os.path.join(folder, CA_FILE), "rb") as f:
                ca = x509.load_pem_x509_certificate(f.read())
        except FileNotFoundError as e:
            raise HostError(f"no host credential in {folder} ({os.path.basename(e.filename)} missing)") from None
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise HostError("the host key is not a P-256 key")
        point = serialization.PublicFormat.UncompressedPoint
        if (key.public_key().public_bytes(serialization.Encoding.X962, point)
                != cert.public_key().public_bytes(serialization.Encoding.X962, point)):
            raise HostError("the host key does not match the host certificate")
        if not is_host_certificate(cert):
            raise HostError("the certificate has no clientAuth extendedKeyUsage (not a host certificate)")
        try:
            cert.verify_directly_issued_by(ca)
        except (ValueError, TypeError, InvalidSignature):
            raise HostError("the host certificate is not issued by the CA in the folder") from None
        return cls(folder, key, cert, ca)

    def save(self) -> None:
        if self.exists(self.folder):
            raise HostError(f"a host credential already exists in {self.folder}")
        os.makedirs(self.folder, exist_ok=True)
        key_path = os.path.join(self.folder, KEY_FILE)
        with open(key_path, "wb") as f:
            f.write(self.key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        with open(os.path.join(self.folder, CA_FILE), "wb") as f:
            f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(self.folder, CERT_FILE), "wb") as f:
            f.write(self.certificate.public_bytes(serialization.Encoding.PEM))

    @property
    def cert_der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def name(self) -> str:
        return self.certificate.subject.rfc4514_string()

    @property
    def fingerprint(self) -> str:
        return self.certificate.fingerprint(hashes.SHA256()).hex(":").upper()

    @property
    def not_after(self):
        return self.certificate.not_valid_after_utc
