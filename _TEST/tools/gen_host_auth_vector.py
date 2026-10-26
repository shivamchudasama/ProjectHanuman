#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write the "host_auth" section of _TEST/vectors/wire.json.

The section holds the host authentication contract (_DOC/HostAuth/PROTOCOL.md):
appTypes, states, flags, RESULT codes, golden short frames, and one whole
handshake made with fresh keys:

    T = SHA-256("PH-HOSTAUTH-1" || Nh || Nd || Qh || Qd ||
                SHA-256(host cert) || SHA-256(device cert))
    SigD = ECDSA-P256-SHA256(device key, "dev" || T)      raw r || s
    SigH = ECDSA-P256-SHA256(host key, "host" || T)
    Z = ECDH(ephemeral keys)
    passkey = u32be(HKDF-SHA256(Z, salt = Nh || Nd,
                    info = "PH-HOSTAUTH-1 passkey" || T, L = 4)) mod 1000000

The certificates come from a throwaway CA. The C test (host_auth_crypto, on the
real TF-PSA-Crypto) recomputes T, Z and the passkey and checks both signatures;
the Python tests check blehost.protocols.host_auth against the same values.
Deliberately independent of blehost, so a bug there does not reach the vector.

Run after a change to the wire format, then rebuild the tests:

    python _TEST/tools/gen_host_auth_vector.py

Only the "host_auth" section is replaced (or appended, see wire_section.py).
Needs cryptography (in _TEST/requirements-test.txt).
"""

import datetime
import hashlib
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from wire_section import replace_section

APP_TYPES = {"STATUS_REQ": 0x60, "STATUS": 0x61, "HELLO": 0x62, "CHALLENGE": 0x63,
             "FINISH": 0x64, "RESULT": 0x65, "REFUSED": 0x66}
STATES = {"UNPROVISIONED": 0, "OPEN": 1, "HOST_BONDED": 2, "AWAIT_FINISH": 3,
          "AWAIT_PAIRING": 4, "TRUSTED": 5}
FLAGS = {"WINDOW_OPEN": 0x01, "HOST_BOND": 0x02}
RESULTS = {"OK": 0, "BAD_STATE": 1, "PARSE": 2, "BAD_CERT": 3, "BAD_SIG": 4, "HOST_BONDED": 5,
           "NO_PC_SVC": 6, "BUSY": 7, "TIMEOUT": 8, "PAIRING": 9, "INTERNAL": 10, "TRANSFER": 11}
ADV_COMPANY_ID = 0xFFFF           # Bluetooth SIG: for testing / internal use
ADV_FORMAT = 1
ADV_FLAGS = {"PROVISIONED": 0x01, "HOST_BOND": 0x02}
VERSION = 1
LABEL = b"PH-HOSTAUTH-1"
INFO = b"PH-HOSTAUTH-1 passkey"


def short(name, app_type, payload: bytes) -> dict:
    return {"name": name, "app_type": app_type, "hex": (bytes([len(payload), app_type]) + payload).hex()}


def point(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)


def scalar(key) -> bytes:
    return key.private_numbers().private_value.to_bytes(32, "big")


def raw_sig(key, message: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vector"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def certificates():
    """A CA, a device certificate (digitalSignature + keyAgreement, no EKU) and a
    host certificate (digitalSignature, EKU clientAuth), as the PC CA issues them."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("Vector CA")).issuer_name(name("Vector CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                         critical=True)
          .sign(ca_key, hashes.SHA256()))

    def leaf(key, cn, key_agreement, eku):
        b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(True, False, False, False, key_agreement, False, False,
                                          False, False), critical=True))
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                                critical=False)
        return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    dev_key = ec.generate_private_key(ec.SECP256R1())
    host_key = ec.generate_private_key(ec.SECP256R1())
    return (ca.public_bytes(serialization.Encoding.DER), dev_key,
            leaf(dev_key, "6f1c2a7e-0b3d-5e44-9a10-2b3c4d5e6f70", True, False),
            host_key, leaf(host_key, "Host Vector", False, True))


def handshake() -> dict:
    ca_der, dev_key, dev_cert, host_key, host_cert = certificates()
    eph_h = ec.generate_private_key(ec.SECP256R1())
    eph_d = ec.generate_private_key(ec.SECP256R1())
    nh, nd = os.urandom(16), os.urandom(16)
    qh, qd = point(eph_h), point(eph_d)
    t = hashlib.sha256(LABEL + nh + nd + qh + qd + hashlib.sha256(host_cert).digest()
                       + hashlib.sha256(dev_cert).digest()).digest()
    z = eph_h.exchange(ec.ECDH(), eph_d.public_key())
    assert z == eph_d.exchange(ec.ECDH(), eph_h.public_key())
    okm = HKDF(algorithm=hashes.SHA256(), length=4, salt=nh + nd, info=INFO + t).derive(z)
    passkey = int.from_bytes(okm, "big") % 1000000
    sig_d = raw_sig(dev_key, b"dev" + t)
    sig_h = raw_sig(host_key, b"host" + t)
    hello = bytes([VERSION]) + nh + qh + host_cert
    challenge = bytes([VERSION]) + nd + qd + sig_d + dev_cert
    return {
        "ca_cert": ca_der.hex(),
        "device_cert": dev_cert.hex(), "device_private_key": scalar(dev_key).hex(),
        "device_public_key": point(dev_key).hex(),
        "host_cert": host_cert.hex(), "host_private_key": scalar(host_key).hex(),
        "host_public_key": point(host_key).hex(),
        "host_eph_private_key": scalar(eph_h).hex(), "device_eph_private_key": scalar(eph_d).hex(),
        "nonce_host": nh.hex(), "nonce_device": nd.hex(),
        "point_host": qh.hex(), "point_device": qd.hex(),
        "transcript": t.hex(), "secret": z.hex(), "hkdf_output": okm.hex(), "passkey": passkey,
        "sig_device": sig_d.hex(), "sig_host": sig_h.hex(),
        "hello": hello.hex(), "challenge": challenge.hex(),
        "finish": short("finish", APP_TYPES["FINISH"], sig_h)["hex"],
    }


def advert() -> dict:
    """The manufacturer data in the device's undirected advertising:
    [company ID u16 LE][format][flags]. A PC holding keys for a device that
    advertises no host bond knows those keys are stale."""
    def frame(name, flags):
        return {"name": name, "hex": (ADV_COMPANY_ID.to_bytes(2, "little")
                                      + bytes([ADV_FORMAT, flags])).hex()}
    p, h = ADV_FLAGS["PROVISIONED"], ADV_FLAGS["HOST_BOND"]
    return {
        "company_id": ADV_COMPANY_ID, "format": ADV_FORMAT, "len": 4, "flags": ADV_FLAGS,
        "frames": [frame("unprovisioned", 0), frame("provisioned", p),
                   frame("provisioned_host", p | h)],
    }


def section() -> dict:
    a, s, f, r = APP_TYPES, STATES, FLAGS, RESULTS
    return {
        "_comment": [
            "Host authentication (_DOC/HostAuth/PROTOCOL.md). Shorts are [len][appType][payload]:",
            "STATUS [state][flags], RESULT [refAppType][status][detail], REFUSED [appType].",
            "HELLO = [ver][Nh 16][Qh 65][host cert], CHALLENGE = [ver][Nd 16][Qd 65][SigD 64][device",
            "cert]; T, Z, the passkey and both raw ECDSA signatures as in gen_host_auth_vector.py.",
            "Regenerate the whole section with _TEST/tools/gen_host_auth_vector.py."
        ],
        "app_types": a,
        "app_type_range": [0x60, 0x6F],
        "states": s,
        "flags": f,
        "results": r,
        "version": VERSION,
        "nonce_len": 16, "point_len": 65, "sig_len": 64, "hash_len": 32,
        "hello_min_len": 1 + 16 + 65 + 1, "challenge_header_len": 1 + 16 + 65 + 64,
        "cert_max_len": 1024,
        "shorts": [
            short("status_req", a["STATUS_REQ"], b""),
            short("status_open_window", a["STATUS"], bytes([s["OPEN"], f["WINDOW_OPEN"]])),
            short("status_host_bonded", a["STATUS"], bytes([s["HOST_BONDED"], f["HOST_BOND"]])),
            short("status_trusted", a["STATUS"], bytes([s["TRUSTED"], f["HOST_BOND"]])),
            short("status_unprovisioned", a["STATUS"], bytes([s["UNPROVISIONED"], f["WINDOW_OPEN"]])),
            short("result_finish_ok", a["RESULT"], bytes([a["FINISH"], r["OK"], 0])),
            short("result_hello_bad_cert", a["RESULT"], bytes([a["HELLO"], r["BAD_CERT"], 0x08])),
            short("result_finish_bad_sig", a["RESULT"], bytes([a["FINISH"], r["BAD_SIG"], 0])),
            short("result_hello_host_bonded", a["RESULT"], bytes([a["HELLO"], r["HOST_BONDED"], 0])),
            short("refused_fs_cmd", a["REFUSED"], bytes([0x40])),
        ],
        "advert": advert(),
        "handshake": handshake(),
    }


def main() -> None:
    replace_section("host_auth", section())
    print("host_auth vectors written")


if __name__ == "__main__":
    main()
