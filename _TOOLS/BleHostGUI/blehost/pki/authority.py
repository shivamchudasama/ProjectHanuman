"""Certificate Authority for device provisioning (the PC side of
_DOC/Provisioning/PROTOCOL.md).

Mirrors Supporting Scripts/create_authority_certificate.py (a self-signed P-256
CA) and production_line_tool.py sign_csr() (turn a device CSR into a device
certificate), without Simplicity Commander and NVM3: the CSR and the
certificates travel over BLE instead.

A CA lives in a folder:
    ca_key.pem        CA private key (unencrypted PEM: keep the folder private)
    ca_cert.pem       self-signed CA certificate
    issued.json       serial (hex) -> subject, public-key hash, validity
    issued/<serial>.pem   every certificate issued

The profile matches what the device verifies (_ASW/_DEVICE_CERT/DeviceCert_Verify.c):
X.509 v3, P-256, ecdsa-with-SHA256; the CA is self-signed with CA:TRUE and
keyCertSign; a device certificate is CA:FALSE and allows digitalSignature
(pairing signs OOB data with the device key) and keyAgreement, and
carries the CSR's subject and public key unchanged. A host certificate
(issue_host(), for the PC that operates devices: _DOC/HostAuth/PROTOCOL.md) is
CA:FALSE, digitalSignature and extendedKeyUsage clientAuth, the host role; a
device CSR asking for an extendedKeyUsage is refused.
"""

import datetime
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID

DEFAULT_FOLDER = os.path.join(os.path.expanduser("~"), ".blehost", "ca")
KEY_FILE, CERT_FILE, DB_FILE, ISSUED_DIR = "ca_key.pem", "ca_cert.pem", "issued.json", "issued"
MAX_CERT_LEN = 1024                   # device buffer (DEVICE_CERT_MAX_DER_LEN)
MAX_SERIAL_TRIES = 10

# Subject fields accepted by create(), in certificate order
SUBJECT_FIELDS = (("C", NameOID.COUNTRY_NAME), ("ST", NameOID.STATE_OR_PROVINCE_NAME),
                  ("L", NameOID.LOCALITY_NAME), ("O", NameOID.ORGANIZATION_NAME),
                  ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME), ("CN", NameOID.COMMON_NAME))


class CaError(Exception):
    """The CA folder is missing, incomplete or already exists, or the CA expired."""


class CsrRejected(Exception):
    """The CSR does not meet the device certificate profile. str() says why."""


@dataclass(frozen=True)
class IssuedCert:
    certificate: x509.Certificate
    der: bytes
    serial_hex: str


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def public_key_sha256(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """SHA-256 of the uncompressed point, as the device sends in STATUS."""
    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).digest()


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


class CertificateAuthority:
    def __init__(self, folder: str, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate):
        self.folder = folder
        self.key = key
        self.certificate = cert

    # ---- create / load ---------------------------------------------------
    @classmethod
    def create(cls, folder: str = DEFAULT_FOLDER, subject: dict = None,
               validity_days: int = 3650) -> "CertificateAuthority":
        """Make a new CA (P-256 key, self-signed certificate) in an empty folder.

        subject: {"C": .., "ST": .., "L": .., "O": .., "OU": .., "CN": ..}; at
        least CN. Refuses to overwrite an existing CA.
        """
        subject = dict(subject or {"CN": "BLE Host Provisioning CA"})
        if not subject.get("CN"):
            raise CaError("the CA needs a common name (CN)")
        if validity_days < 1:
            raise CaError("validity must be at least one day")
        if os.path.exists(os.path.join(folder, KEY_FILE)) or os.path.exists(os.path.join(folder, CERT_FILE)):
            raise CaError(f"a CA already exists in {folder}")
        unknown = set(subject) - {k for k, _ in SUBJECT_FIELDS}
        if unknown:
            raise CaError(f"unknown subject field(s): {', '.join(sorted(unknown))}")

        name = x509.Name([x509.NameAttribute(oid, subject[k]) for k, oid in SUBJECT_FIELDS
                          if subject.get(k)])
        key = ec.generate_private_key(ec.SECP256R1())
        now = _now()
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=validity_days))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False,
                                             key_agreement=False, key_cert_sign=True, crl_sign=True,
                                             encipher_only=False, decipher_only=False), critical=True)
                .add_extension(ski, critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
                               critical=False)
                .sign(key, hashes.SHA256()))

        os.makedirs(os.path.join(folder, ISSUED_DIR), exist_ok=True)
        key_path = os.path.join(folder, KEY_FILE)
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        with open(os.path.join(folder, CERT_FILE), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(folder, DB_FILE), "w") as f:
            json.dump({}, f)
        return cls(folder, key, cert)

    @classmethod
    def load(cls, folder: str = DEFAULT_FOLDER) -> "CertificateAuthority":
        try:
            with open(os.path.join(folder, KEY_FILE), "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            with open(os.path.join(folder, CERT_FILE), "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
        except FileNotFoundError as e:
            raise CaError(f"no CA in {folder} ({os.path.basename(e.filename)} missing)") from None
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise CaError("the CA key is not a P-256 key")
        if public_key_sha256(key.public_key()) != public_key_sha256(cert.public_key()):
            raise CaError("the CA key does not match the CA certificate")
        return cls(folder, key, cert)

    @staticmethod
    def exists(folder: str = DEFAULT_FOLDER) -> bool:
        return os.path.exists(os.path.join(folder, CERT_FILE))

    # ---- properties ------------------------------------------------------
    @property
    def cert_der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def subject(self) -> str:
        return self.certificate.subject.rfc4514_string()

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.certificate)

    @property
    def not_after(self) -> datetime.datetime:
        return self.certificate.not_valid_after_utc

    def issued(self) -> dict:
        try:
            with open(os.path.join(self.folder, DB_FILE)) as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    # ---- signing ---------------------------------------------------------
    @staticmethod
    def check_csr(csr_der: bytes) -> x509.CertificateSigningRequest:
        """Parse a device CSR and check it against the device certificate
        profile. Raises CsrRejected."""
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except ValueError as e:
            raise CsrRejected(f"not a DER CSR ({e})") from None
        if not csr.is_signature_valid:
            raise CsrRejected("CSR signature does not verify (the device does not hold the key)")
        key = csr.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise CsrRejected("public key is not P-256")
        if csr.signature_algorithm_oid != SignatureAlgorithmOID.ECDSA_WITH_SHA256:
            raise CsrRejected("CSR is not signed with ecdsa-with-SHA256")
        if not csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            raise CsrRejected("subject has no common name")
        exts = {e.oid: e for e in csr.extensions}
        bc = exts.get(x509.BasicConstraints.oid)
        if bc is not None and bc.value.ca:
            raise CsrRejected("CSR asks for a CA certificate")
        ku = exts.get(x509.KeyUsage.oid)
        if ku is None or not ku.value.key_agreement or not ku.value.digital_signature:
            raise CsrRejected("KeyUsage digitalSignature and keyAgreement are required "
                              "(pairing signs with the key); wipe the device for a new CSR")
        if x509.ExtendedKeyUsage.oid in exts:
            # The CSR's extensions are copied: a device must not obtain the host role
            raise CsrRejected("a device CSR must not ask for extendedKeyUsage "
                              "(clientAuth marks host certificates)")
        return csr

    def issue_host(self, name: str, folder: str, validity_days: int = 730):
        """Issue a host certificate and write a host credential to folder.

        The host gets a fresh P-256 key; its certificate is CA:FALSE, KeyUsage
        digitalSignature (it signs the handshake) and extendedKeyUsage
        clientAuth, the host role the device requires (ge_VerifyHostCertificate).
        The folder gets host_key.pem, host_cert.pem and a copy of ca_cert.pem
        (blehost.pki.host): a laptop in the field needs the credential, not the
        CA key. Refuses to overwrite a credential. Returns the HostCredential.
        """
        from .host import HostCredential, HostError
        if not name:
            raise CaError("the host needs a name (CN)")
        if validity_days < 1:
            raise CaError("validity must be at least one day")
        if HostCredential.exists(folder):
            raise HostError(f"a host credential already exists in {folder}")
        now = _now()
        ca = self.certificate
        if not ca.not_valid_before_utc <= now <= ca.not_valid_after_utc:
            raise CaError("the CA certificate is not valid now")

        issued = self.issued()
        for _ in range(MAX_SERIAL_TRIES):
            serial = x509.random_serial_number()
            if f"{serial:x}" not in issued:
                break
        else:
            raise CaError("could not find an unused serial number")

        key = ec.generate_private_key(ec.SECP256R1())
        ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(ca.subject)
                .public_key(key.public_key())
                .serial_number(serial)
                .not_valid_before(now)
                .not_valid_after(min(now + datetime.timedelta(days=validity_days),
                                     ca.not_valid_after_utc))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False,
                                             key_agreement=False, key_cert_sign=False, crl_sign=False,
                                             encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                               critical=False)
                .sign(self.key, hashes.SHA256()))
        cert.verify_directly_issued_by(ca)

        serial_hex = f"{serial:x}"
        issued[serial_hex] = {
            "role": "host",
            "subject": cert.subject.rfc4514_string(),
            "public_key_sha256": public_key_sha256(cert.public_key()).hex(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
        }
        os.makedirs(os.path.join(self.folder, ISSUED_DIR), exist_ok=True)
        with open(os.path.join(self.folder, ISSUED_DIR, serial_hex + ".pem"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(self.folder, DB_FILE), "w") as f:
            json.dump(issued, f, indent=2)
        cred = HostCredential(folder, key, cert, ca)
        cred.save()
        return cred

    def sign_csr(self, csr_der: bytes, validity_days: int = 365) -> IssuedCert:
        """Issue a device certificate for a CSR (see check_csr for the checks).

        Subject and public key come from the CSR unchanged. The certificate gets
        BasicConstraints CA:FALSE (critical), the CSR's other extensions (as
        sign_csr() does), an AuthorityKeyIdentifier, a serial not used before,
        and the requested validity, cut at the CA's own expiry.
        """
        if validity_days < 1:
            raise CsrRejected("validity must be at least one day")
        now = _now()
        ca = self.certificate
        if not ca.not_valid_before_utc <= now <= ca.not_valid_after_utc:
            raise CaError("the CA certificate is not valid now")
        csr = self.check_csr(csr_der)

        issued = self.issued()
        for _ in range(MAX_SERIAL_TRIES):
            serial = x509.random_serial_number()
            if f"{serial:x}" not in issued:
                break
        else:
            raise CaError("could not find an unused serial number")

        builder = (x509.CertificateBuilder()
                   .subject_name(csr.subject)
                   .issuer_name(ca.subject)
                   .public_key(csr.public_key())
                   .serial_number(serial)
                   .not_valid_before(now)
                   .not_valid_after(min(now + datetime.timedelta(days=validity_days),
                                        ca.not_valid_after_utc))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
        for ext in csr.extensions:
            if ext.oid not in (x509.BasicConstraints.oid, x509.AuthorityKeyIdentifier.oid):
                builder = builder.add_extension(ext.value, ext.critical)
        try:
            ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        except x509.ExtensionNotFound:
            pass
        cert = builder.sign(self.key, hashes.SHA256())

        try:
            cert.verify_directly_issued_by(ca)
        except (ValueError, TypeError, InvalidSignature) as e:      # cannot happen: we just signed it
            raise CaError(f"issued certificate does not verify against the CA: {e}") from None
        der = cert.public_bytes(serialization.Encoding.DER)
        if len(der) > MAX_CERT_LEN:
            raise CsrRejected(f"certificate is {len(der)} bytes, the device takes {MAX_CERT_LEN}")

        serial_hex = f"{serial:x}"
        issued[serial_hex] = {
            "subject": cert.subject.rfc4514_string(),
            "public_key_sha256": public_key_sha256(cert.public_key()).hex(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
        }
        os.makedirs(os.path.join(self.folder, ISSUED_DIR), exist_ok=True)
        with open(os.path.join(self.folder, ISSUED_DIR, serial_hex + ".pem"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(self.folder, DB_FILE), "w") as f:
            json.dump(issued, f, indent=2)
        return IssuedCert(cert, der, serial_hex)
