# Device Provisioning — Protocol

This is the contract between the firmware in `_ASW` (module [`_PROV`](../../_ASW/_PROV/Prov.c)) and a **provisioner**: the PC that acts as the Certificate Authority (CA). The provisioner gets the device's Certificate Signing Request (CSR), issues a device certificate, and sends it to the device with the CA certificate. The device verifies both, stores both and deletes its CSR. Everything runs on SETU, specified in [../SETU/PROTOCOL.md](../SETU/PROTOCOL.md).

There are two provisioners: the **Provisioning** tab of the PC GUI in [_TOOLS/BleHostGUI](../../_TOOLS/BleHostGUI/README.md), and the `provision` command of [setu_client.py](../../_TOOLS/BleHostGUI/setu_client.py). Both use [blehost/protocols/provisioning.py](../../_TOOLS/BleHostGUI/blehost/protocols/provisioning.py). Design, trust model and limitations are in [README.md](README.md).

**Who may provision.** An unprovisioned device takes provisioning from any host that connects. It advertises only while its host window is open: a press of DK Button 3. Once provisioned, the device serves only its trusted host ([../HostAuth/PROTOCOL.md §2](../HostAuth/PROTOCOL.md#2-the-gate)). Every message of this range except GET_STATUS, DEPROVISION included, needs that host. A refused short message is answered with REFUSED (`0x66`), a refused transfer with a rejected START.

The key, the CSR and, once the device is provisioned, both certificates persist across resets in the device's Internal Trusted Storage (ITS). Provisioning is **one-time**: a provisioned device refuses another run until it is wiped, by the DEPROVISION message (§3) or by holding Button 0 on the DK. A wipe destroys the key, the CSR and both certificates and makes a fresh key and CSR, as on a chip-erased device. The device also logs each certificate on the serial terminal (§8).

## 1. Roles and services

| Side | BLE role | Hosts | SETU roles |
|---|---|---|---|
| Device | Peripheral | Its SETU service | Server: receives the certificates. Client: sends the CSR |
| Provisioner | Central | A SETU service of its own, with the same UUIDs | Client: sends requests and certificates. Receiver: gets the CSR |

A SETU transfer always goes from the GATT client to the side that hosts the service. The CSR travels from the device to the provisioner, so **the provisioner hosts a SETU service too**, and the device attaches its SETU Client to it over the same connection. The device finds it only when it is asked for the CSR (§5). It does not need to be advertised.

## 2. GATT

The device's service is the one in [../HexUpload/PROTOCOL.md §2](../HexUpload/PROTOCOL.md#2-gatt-table): DATA, CTRL with its CCCD, and CAPS under `B1C00000-16A1-4812-AF35-F3F29A92F6CA`.

The provisioner's service must have:

| Attribute | UUID | Properties | Notes |
|---|---|---|---|
| Primary service | `B1C00000-…` | — | Same base as the device (`BaseUUIDs.h`) |
| DATA | `B1C00001-…` | Write Without Response | The device writes START / DATA / ABORT here |
| CTRL | `B1C00002-…` | Notify, with CCCD | The provisioner sends ACK / NACK / END / ABORT here. The device subscribes before sending |
| CAPS | `B1C00003-…` | Read | Optional. The device does not read it |

The provisioner's receiver follows [SETU §7](../SETU/PROTOCOL.md#7-receiver-behaviour). The device sends with chunk `min(ATT_MTU − 3, 244) − 4`, so the provisioner must accept chunks up to 240.

## 3. Application messages

appTypes `0x20`–`0x2F` are provisioning's (the device's router gives this range to `_PROV`; see [../HexUpload/PROTOCOL.md §3](../HexUpload/PROTOCOL.md#3-application-messages) for the whole registry).

| appType | Direction | Kind | Payload |
|---|---|---|---|
| `0x20` GET_STATUS | provisioner → device | short message | none |
| `0x21` STATUS | device → provisioner | short message | `[u8 state][u8 flags][u16 LE CSR length][32 B SHA-256 of the public key]` |
| `0x22` CSR_REQ | provisioner → device | short message | none |
| `0x23` CSR | device → provisioner | SETU transfer, to the provisioner's service | DER CSR (PKCS#10) |
| `0x24` CA_CERT | provisioner → device | SETU transfer | DER X.509 CA certificate, 1–1024 bytes |
| `0x25` DEV_CERT | provisioner → device | SETU transfer | DER X.509 device certificate, 1–1024 bytes |
| `0x26` RESULT | device → provisioner | short message | `[u8 refAppType][u8 status]` |
| `0x27` DEPROVISION | provisioner → device | short message | none. Wipe and make a fresh key and CSR; answered with RESULT |

Short messages from the provisioner go to the device's DATA. Short messages from the device arrive as CTRL notifications of the device's service. All other appTypes in the range are reserved. The device ignores short messages with them, and refuses transfers with them (§6).

### 3.1 STATUS

| Field | Values |
|---|---|
| `state` | `0` NO_KEY: no key or CSR (generation failed), provisioning impossible until a wipe. `1` KEY_READY: key and CSR ready. `2` CA_OK: a CA certificate is verified and held in RAM (not stored). `3` PROVISIONED: the device certificate is verified, both certificates are stored and the CSR is deleted |
| `flags` | bit 0 CSR_TX_BUSY: a CSR request is being served. Other bits 0 |
| CSR length | Bytes of the DER CSR, 0 in NO_KEY and PROVISIONED (no CSR any more) |
| Public key hash | SHA-256 over the uncompressed P-256 point (`04 ‖ X ‖ Y`, 65 bytes). All zero if unavailable. The provisioner checks that the CSR carries this key |

### 3.2 RESULT

`refAppType` is the request or transfer it answers: `0x22` (CSR_REQ refused), `0x23` (CSR transfer outcome), `0x24`, `0x25` or `0x27` (DEPROVISION).

| `status` | Name | Meaning |
|---|---|---|
| `0x00` | OK | Done: CSR delivered; the certificate is verified and in force (for DEV_CERT: both certificates stored); the device is wiped and has a fresh key and CSR |
| `0x01` | BAD_STATE | Not allowed now: device certificate before a CA, no key, already provisioned, request already running, DEPROVISION while the CSR or a certificate is in progress or a pairing runs, wrong appType |
| `0x02` | TOO_LARGE | Certificate empty or above 1024 bytes |
| `0x03` | PARSE | Not a parsable DER X.509 certificate |
| `0x04` | NOT_CA | CA certificate is not CA:TRUE, not self-issued, or does not allow keyCertSign |
| `0x05` | BAD_SIG | Signature does not verify: the CA's own, or the device certificate's against the CA |
| `0x06` | KEY_MISMATCH | Device certificate carries another public key than the device's |
| `0x07` | SUBJECT_MISMATCH | Device certificate subject differs from the CSR subject (byte for byte) |
| `0x08` | BAD_PROFILE | Outside the profile (§7): key not P-256, signature not ecdsa-with-SHA256, not X.509 v3, device certificate CA:TRUE or without digitalSignature and keyAgreement |
| `0x09` | NO_PEER_SVC | The device found no SETU service on the provisioner |
| `0x0A` | INTERNAL | Crypto, storage, memory or SETU failure on the device. For DEV_CERT: the certificates could not be stored (neither is kept; the state stays CA_OK and the device certificate can be sent again). For DEPROVISION: something could not be erased, or no new key and CSR could be made (state NO_KEY) |
| `0x0B` | TRANSFER | The CSR transfer failed (its END or ABORT was not OK) |

A provisioner MUST treat an unknown status as a failure.

## 4. States

| State | Event | Action | Next |
|---|---|---|---|
| (boot) | Nothing stored: key and CSR generated (first boot) or loaded | — | KEY_READY |
| (boot) | Key or CSR unavailable | — | NO_KEY |
| (boot) | Certificate pair stored; the CA re-verifies, the device certificate verifies against it and carries the device's key | Restore the CA as the trust anchor; remove a leftover CSR | PROVISIONED |
| (boot) | Certificate pair stored but corrupt, incomplete, or failing that re-verification; or the key is gone | Wipe (as DEPROVISION) | KEY_READY |
| KEY_READY, CA_OK | CA_CERT verified | Keep it in RAM as the trust anchor (not stored) | CA_OK |
| KEY_READY, CA_OK | CA_CERT rejected | RESULT with the reason; the previous CA stays in force | unchanged |
| CA_OK | DEV_CERT verified, both stored | Store the CA, then the device certificate; delete the CSR | PROVISIONED |
| CA_OK | DEV_CERT verified, storing failed | Remove whatever was stored; RESULT INTERNAL | CA_OK |
| CA_OK | DEV_CERT rejected | RESULT with the reason | CA_OK |
| PROVISIONED | CSR_REQ, CA_CERT, DEV_CERT | RESULT BAD_STATE (one-time provisioning) | PROVISIONED |
| any | DEPROVISION or Button 0 held (default 5 s) | Forget the trust anchor; remove both certificates, the key and the CSR; generate a fresh key and CSR; delete every bond, the pairing peer's ([../Pairing/PROTOCOL.md §4](../Pairing/PROTOCOL.md#4-states)) and the trusted host's ([../HostAuth/PROTOCOL.md §5](../HostAuth/PROTOCOL.md#5-forgetting-the-host)). Over BLE, only the trusted host may send DEPROVISION. Refused (BAD_STATE) while the CSR is being sent, a certificate is being received or verified, or a pairing runs | KEY_READY (NO_KEY if no key could be made) |
| CA_OK | Reset | The CA was in RAM only | KEY_READY |

A disconnect changes no state: a provisioner can send the CA in one connection and the device certificate in the next. The button wipe sends no RESULT.

Nothing is stored before the device certificate verifies against the CA, so a reset or a failure in the middle never leaves a half-provisioned device. The CA is stored before the device certificate and the CSR is deleted last; a reset between those steps leaves a state the next boot recognises (one certificate only: wipe; both and a CSR: the CSR is removed).

## 5. Sequence

1. Connect. Subscribe to the device's CTRL. Host the provisioner's service (§2) before step 3.
2. **GET_STATUS** → STATUS. Stop if `state` is NO_KEY. If it is PROVISIONED, stop, or send **DEPROVISION** → RESULT(`0x27`, OK) to start again from a fresh key (certificates issued for the old key no longer match). The wipe deletes the device's bond with this host, so once this link ends the host removes its own keys for the device ([../HostAuth/PROTOCOL.md §5](../HostAuth/PROTOCOL.md#5-forgetting-the-host)).
3. **CSR_REQ**. The device:
   - attaches its SETU Client to the provisioner's service (discovery, CTRL subscription), unless it is already attached;
   - sends the CSR as a transfer with appType `0x23`;
   - sends RESULT(`0x23`, OK) when the provisioner's END is OK, RESULT(`0x23`, TRANSFER) otherwise.

   If the service is not found, the device sends RESULT(`0x22`, NO_PEER_SVC) and no transfer. A CSR_REQ while one is being served gets RESULT(`0x22`, BAD_STATE).
4. The provisioner checks the CSR (signature, P-256, the key hash from STATUS, the profile in §7) and issues the device certificate.
5. **CA_CERT** transfer → RESULT(`0x24`, status).
6. **DEV_CERT** transfer → RESULT(`0x25`, status). OK means both certificates are stored, the CSR is deleted and the device is provisioned.

```
Provisioner (central)                                    Device (peripheral)
   |-- GET_STATUS (DATA) ------------------------------------->|
   |<------------------------------ STATUS (CTRL notify) ------|
   |-- CSR_REQ (DATA) ---------------------------------------->|
   |<== discovery of the provisioner's service, CCCD write ====|  device = GATT client
   |<-- START / DATA … (writes to the provisioner's DATA) -----|
   |-- ACK … END(OK) (notify on the provisioner's CTRL) ------>|
   |<------------------------------ RESULT(0x23, OK) ----------|
   |   (sign the CSR)                                          |
   |-- START / DATA … CA_CERT --------------------------------->|
   |<------------------------------ END(OK), RESULT(0x24, 00) -|  verified
   |-- START / DATA … DEV_CERT -------------------------------->|
   |<------------------------------ END(OK), RESULT(0x25, 00) -|  stored, CSR deleted
   |                                                           |
   |-- DEPROVISION (DATA), only to provision again ------------>|
   |<------------------------------ RESULT(0x27, 00) ----------|  new key and CSR
```

END only says the bytes arrived intact. **RESULT** says whether the certificate was accepted.

## 6. Rejections at START

The device refuses a certificate transfer at START (SETU ABORT, direction *by receiver*, reason REJECTED) and then sends RESULT with the reason, when:

| Cause | RESULT status |
|---|---|
| appType in the range but not `0x24` or `0x25` | BAD_STATE |
| State NO_KEY | BAD_STATE |
| State PROVISIONED (one-time provisioning) | BAD_STATE |
| DEV_CERT before a verified CA (state KEY_READY) | BAD_STATE |
| Length 0 or above 1024 | TOO_LARGE |
| Another certificate is still being received or verified | BAD_STATE |

A certificate transfer that fails after START (CRC error, timeout, abort, disconnect) gets no RESULT: its END or ABORT already says so. The device discards it and the provisioner may send it again.

## 7. Certificate profile

All certificates are X.509 v3 in DER, P-256 keys, signed with ecdsa-with-SHA256.

**CSR** (built by the device, [_ASW/_CSR/DER.c](../../_ASW/_CSR/DER.c)):

- Subject: C, ST, L, O, OU from Kconfig `CONFIG_CSR_SUBJ_*`, all UTF8String. CN is an RFC 4122 version-5 UUID (SHA-1 of a fixed namespace and the hardware device ID), lowercase, for example `6f1c0d3a-5b2e-5c4d-8e9f-0a1b2c3d4e5f`: the third group starts with `5`. Devices that generated their CSR before this was corrected may still carry a CN with another digit there until their next wipe.
- Requested extensions, all non-critical: BasicConstraints CA:FALSE; KeyUsage digitalSignature + keyAgreement (pairing signs its OOB data with the key, [../Pairing/PROTOCOL.md](../Pairing/PROTOCOL.md)); SubjectKeyIdentifier = SHA-1 over `X ‖ Y` (without the `04` prefix).
- Signed with the device key, which never leaves the device.

**CA certificate**, checked by the device:

- Self-issued (subject = issuer) and self-signed (the signature verifies with its own key).
- BasicConstraints CA:TRUE.
- If KeyUsage is present, it includes keyCertSign.

**Device certificate**, checked by the device:

- Signed by the CA certificate in force.
- Subject byte-identical to the CSR subject.
- Public key equal to the device's own key.
- BasicConstraints absent or CA:FALSE.
- KeyUsage present and including digitalSignature and keyAgreement.

The device does not check validity dates: it has no wall clock. The provisioner issues certificates that are valid now. The GUI CA copies the CSR's extensions, adds CA:FALSE (critical) and AuthorityKeyIdentifier, and caps the validity at its own.

## 8. Serial output

Each verified certificate is logged as a title line and a standard PEM block (deferred log, paced so no line is dropped). The device certificate's block follows the storage lines:

```
<inf> APP_LOG: CA certificate (412 bytes):
<inf> APP_LOG: -----BEGIN CERTIFICATE-----
<inf> APP_LOG: MIIBmDCCAT2gAwIBAgIU…
…
<inf> APP_LOG: -----END CERTIFICATE-----
<inf> APP_LOG: st_StoreRecord: CA certificate stored in trusted storage (412 bytes)
<inf> APP_LOG: st_StoreRecord: Device certificate stored in trusted storage (501 bytes)
<inf> APP_LOG: Device certificate (501 bytes):
<inf> APP_LOG: -----BEGIN CERTIFICATE-----
…
<inf> APP_LOG: -----END CERTIFICATE-----
<inf> APP_LOG: sv_HandleCertReceived: device provisioned
```

Copy a block from `-----BEGIN` to `-----END` without the `<inf> APP_LOG: ` prefixes to get a file that `openssl x509 -in file.pem -text` reads.

At boot the device logs whether it generated a new key and CSR (first boot), restored them, or restored and re-verified its certificates (`… restored from trusted storage`, `provisioned: stored certificates verified`). A wipe logs `wiping provisioning credentials`, then the new key and CSR; a wipe from the button first logs `button held 5000 ms: wiping provisioning`. Invalid stored certificates at boot log `stored provisioning is invalid` before the wipe.

## 9. Timing

| Step | Provisioner timeout (reference) | Why |
|---|---|---|
| STATUS after GET_STATUS | 3 s | |
| CSR after CSR_REQ | 30 s | Includes the device's discovery of the provisioner's service |
| RESULT after a certificate's END | 10 s | ECDSA verification on the device; for DEV_CERT also two ITS writes |
| RESULT after DEPROVISION | 10 s | ITS erase, key generation and the CSR build |

## 10. Examples

Golden frames from [_TEST/vectors/wire.json](../../_TEST/vectors/wire.json) (`provisioning.shorts`), `[len][type][payload]`:

| Frame | Bytes |
|---|---|
| GET_STATUS | `00 20` |
| CSR_REQ | `00 22` |
| DEPROVISION | `00 27` |
| STATUS, KEY_READY, CSR 420 B | `24 21 01 00 a4 01 52 11 a2 ee … 66 cc` (36-byte payload) |
| RESULT CA_CERT OK | `02 26 24 00` |
| RESULT DEV_CERT BAD_SIG | `02 26 25 05` |
| RESULT CSR_REQ NO_PEER_SVC | `02 26 22 09` |
| RESULT CSR delivered | `02 26 23 00` |
| STATUS, PROVISIONED (no CSR) | `24 21 03 00 00 00 52 11 a2 ee … 66 cc` |
| RESULT CSR_REQ BAD_STATE (provisioned) | `02 26 22 01` |
| RESULT DEPROVISION OK | `02 26 27 00` |

`provisioning.csr` in the same file is a CSR built by the device's encoder, with a real signature (420 bytes).
