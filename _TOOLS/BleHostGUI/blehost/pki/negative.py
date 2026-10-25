"""Certificates the device must reject, for testing its verification
(_ASW/_DEVICE_CERT/DeviceCert_Verify.c).

The same set drives the device code twice: on the host, where
_TEST/tools/gen_cert_vectors.py turns it into C vectors for the
devicecert_verify test (real Mbed TLS / TF-PSA-Crypto), and on a real device
(setu_client.py provision --negative, the CI hil-tests job). Each case is
built from the device's own CSR, because a device certificate only passes with
the device's key and subject, and carries the RESULT status the device must
answer.

Order matters: CA cases come first (the device keeps its previous CA when one
is rejected); the device-certificate cases then run against the good CA, which
the runner sends before them.
"""

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CERT, DEV_CERT = 0x24, 0x25
OK, PARSE, NOT_CA, BAD_SIG, KEY_MISMATCH, SUBJECT_MISMATCH, BAD_PROFILE = 0, 3, 4, 5, 6, 7, 8


@dataclass(frozen=True)
class Case:
    name: str
    app_type: int           # CA_CERT or DEV_CERT
    der: bytes
    expected: int           # RESULT status the device must send


def _der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _ku(key_agreement=False, cert_sign=False, digital_signature=True):
    # Keep at least one bit set: an all-zero KeyUsage would be an empty BIT
    # STRING, which mbedTLS refuses to parse, and the case would test PARSE
    # instead of the profile rule it is about.
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=key_agreement, key_cert_sign=cert_sign,
                         crl_sign=cert_sign, encipher_only=False, decipher_only=False)


def _builder(subject, issuer, public_key, days=30):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days)))


def _ca_cert(key, name, ca=True, signer=None, issuer=None, cert_sign=True):
    b = _builder(name, issuer or name, key.public_key(), 365)
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
    b = b.add_extension(_ku(cert_sign=cert_sign), critical=True)
    return b.sign(signer or key, hashes.SHA256())


def _dev_cert(ca_key, ca_name, subject, public_key, ca_flag=False, key_agreement=True, alg=None,
              digital_signature=True, client_auth=False):
    b = _builder(subject, ca_name, public_key)
    b = b.add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
    b = b.add_extension(_ku(key_agreement=key_agreement, digital_signature=digital_signature),
                        critical=False)
    if client_auth:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    return b.sign(ca_key, alg or hashes.SHA256())


def _flip_last(der: bytes) -> bytes:
    """Corrupt the signature (its last byte) without breaking the encoding."""
    return der[:-1] + bytes([der[-1] ^ 0x01])


def _other_cn(subject: x509.Name) -> x509.Name:
    """subject with its CN's last character changed: same fields, same length."""
    attrs = []
    for a in subject:
        if a.oid == NameOID.COMMON_NAME:
            last = "0" if a.value[-1] != "0" else "1"
            a = x509.NameAttribute(NameOID.COMMON_NAME, a.value[:-1] + last)
        attrs.append(a)
    return x509.Name(attrs)


def negative_cases(ca, csr_der: bytes) -> list:
    """Cases for the device that sent csr_der, with `ca` (CertificateAuthority) as
    the good CA. Returns [Case]; the good CA itself is ca.cert_der."""
    csr = x509.load_der_x509_csr(csr_der)
    dev_key = csr.public_key()
    subject = csr.subject
    good_name = ca.certificate.subject

    other_key = ec.generate_private_key(ec.SECP256R1())
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
    p384_key = ec.generate_private_key(ec.SECP384R1())

    cases = [
        # ---- CA certificate (sent before the good CA) ----
        Case("ca_not_der", CA_CERT, b"\x30\x03\x02\x01\x00", PARSE),
        Case("ca_without_ca_flag", CA_CERT, _der(_ca_cert(other_key, other_name, ca=False)), NOT_CA),
        Case("ca_not_self_issued", CA_CERT,
             _der(_ca_cert(other_key, other_name, signer=ca.key, issuer=good_name)), NOT_CA),
        Case("ca_without_cert_sign", CA_CERT, _der(_ca_cert(other_key, other_name, cert_sign=False)), NOT_CA),
        Case("ca_bad_self_signature", CA_CERT, _flip_last(_der(_ca_cert(other_key, other_name))), BAD_SIG),
        Case("ca_p384", CA_CERT, _der(_ca_cert(p384_key, other_name)), BAD_PROFILE),
        # ---- device certificate (after the good CA) ----
        Case("dev_other_ca", DEV_CERT, _der(_dev_cert(other_key, good_name, subject, dev_key)), BAD_SIG),
        Case("dev_bad_signature", DEV_CERT,
             _flip_last(_der(_dev_cert(ca.key, good_name, subject, dev_key))), BAD_SIG),
        Case("dev_foreign_key", DEV_CERT,
             _der(_dev_cert(ca.key, good_name, subject, other_key.public_key())), KEY_MISMATCH),
        Case("dev_other_subject", DEV_CERT,
             _der(_dev_cert(ca.key, good_name,
                            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "someone else")]),
                            dev_key)), SUBJECT_MISMATCH),
        # Another device's subject: the same fields and length, another CN (a UUID
        # of the same size), so only the bytes tell it apart
        Case("dev_other_device_cn", DEV_CERT,
             _der(_dev_cert(ca.key, good_name, _other_cn(subject), dev_key)), SUBJECT_MISMATCH),
        Case("dev_ca_flag", DEV_CERT, _der(_dev_cert(ca.key, good_name, subject, dev_key, ca_flag=True)),
             BAD_PROFILE),
        Case("dev_no_key_agreement", DEV_CERT,
             _der(_dev_cert(ca.key, good_name, subject, dev_key, key_agreement=False)), BAD_PROFILE),
        Case("dev_no_digital_signature", DEV_CERT,
             _der(_dev_cert(ca.key, good_name, subject, dev_key, digital_signature=False)), BAD_PROFILE),
        Case("dev_sha384", DEV_CERT,
             _der(_dev_cert(ca.key, good_name, subject, dev_key, alg=hashes.SHA384())), BAD_PROFILE),
        # The host role (EKU clientAuth) on a device certificate
        Case("dev_host_role", DEV_CERT,
             _der(_dev_cert(ca.key, good_name, subject, dev_key, client_auth=True)), BAD_PROFILE),
    ]
    return cases
