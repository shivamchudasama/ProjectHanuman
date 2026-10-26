# Host Authentication — Protocol

This is the contract for **host authentication**: how a PC becomes a device's one **trusted host**, the only party that may operate the device. The firmware side is module [`_HOST_AUTH`](../../_ASW/_HOST_AUTH/HostAuth.c). The PC side is the **Host access** page of the GUI in [_TOOLS/BleHostGUI](../../_TOOLS/BleHostGUI/README.md), and the `hostcert` / `auth` / `authstatus` commands of [setu_client.py](../../_TOOLS/BleHostGUI/setu_client.py). Both use [blehost/protocols/host_auth.py](../../_TOOLS/BleHostGUI/blehost/protocols/host_auth.py). Design, security notes and limitations are in [README.md](README.md).

The PC holds a **host certificate** issued by the same CA that provisioned the device ([../Provisioning/PROTOCOL.md](../Provisioning/PROTOCOL.md)). In a short handshake over SETU ([../SETU/PROTOCOL.md](../SETU/PROTOCOL.md)):
- each side proves that it holds its certificate's key, by signing a transcript of the handshake;
- both sides derive the same six-digit passkey from an ECDH exchange of fresh keys.

The PC then pairs with **LE Secure Connections passkey entry**, using that passkey. The result is a bonded link at security level 4 (encrypted, authenticated). From then on, the device lets that bonded host reach everything. Any other link reaches only this handshake and two status reads.

## 1. Roles and links

| Party | Role |
|---|---|
| Device | Peripheral. GATT server of the SETU service; its SETU Client sends CHALLENGE to the host's SETU service. Holds **at most one** host bond |
| Host (PC) | Central. SETU Client of the device's service, and host of its own SETU service (the GUI publishes it at start-up), where CHALLENGE arrives |

**Discovery.** The device advertises for a host only while its **host window** is open:
- A short press of DK **Button 3** (SW3) opens the window for `CONFIG_HOST_AUTH_WINDOW_MS` (120 s).
- Holding Button 3 for `CONFIG_HOST_AUTH_FORGET_HOLD_MS` (3 s) first **forgets the bonded host**: its bond, its record and its link. It then opens the window for a new host.
- When the trusted host's link drops, the window opens by itself for `CONFIG_HOST_AUTH_GRACE_MS` (60 s), so the host can reconnect.
- The window closes when a host connects, or when its time runs out.
- When a host that is not trusted disconnects (a failed attempt: Windows drops the link when pairing fails), the window reopens for the time it had left, so the host can reconnect and try again. It never extends the window: once its time has run out, it stays closed.
- LED1 (`DK_LED2`) blinks while the window is open, and is lit while the trusted host is connected.

While the window is open, the device advertises connectable and undirected. The data is as before: the Pairing service UUID once provisioned, the SETU UUID before ([../Pairing/PROTOCOL.md §2](../Pairing/PROTOCOL.md#2-gatt-the-pairing-service)).

Outside the window, a device does not advertise for hosts. The one exception is a bonded pair peripheral whose central is away: it advertises **directed** to that central only.

Bench and HIL images can set `CONFIG_HOST_AUTH_BOOT_WINDOW=y` to open the window once at boot.

## 2. The gate

The device's SETU router gives the host link limited access until the host is trusted. A link is **trusted** when two things hold:
- its identity address is the bonded host's;
- it is at security level 4.

| appTypes | Reachable |
|---|---|
| `0x60`–`0x6F` (this protocol) | Always |
| `0x20` GET_STATUS (provisioning) | Always |
| `0x20`–`0x2F` (provisioning) | While the device is **not provisioned**: it has no certificate yet, so no host can authenticate. Provisioning is the bootstrap |
| Everything else: hex upload `0x01`, `0x10`–`0x1F`, file commands `0x40`–`0x4F`, UDS `0x50`–`0x5F`, provisioning (incl. DEPROVISION `0x27`) on a provisioned device | **Trusted host only** |

How a refusal looks to the host:
- A refused **transfer** is rejected at START, as an unknown type. The host's SETU Client ends with REJECTED.
- A refused **short message** is dropped, and the device answers REFUSED (§3). Each refusal is reported.
- The **Pairing service's** CONTROL characteristic answers ATT error `0x08` Insufficient Authorization to any link but the trusted host's ([../Pairing/PROTOCOL.md §3.1](../Pairing/PROTOCOL.md#31-control)). Its STATUS stays readable.

While a pairing run holds the SETU Server on the peer link, the run's own filter applies there instead ([../HexUpload/PROTOCOL.md §2](../HexUpload/PROTOCOL.md)).

## 3. Messages

All messages are SETU short messages `[len][appType][payload]` or SETU transfers, in the appType range `0x60`–`0x6F`.

| appType | Name | Direction | Kind | Payload |
|---|---|---|---|---|
| `0x60` | STATUS_REQ | host → device | short | none |
| `0x61` | STATUS | device → host | short | `[u8 state][u8 flags]` |
| `0x62` | HELLO | host → device | transfer | `[u8 version = 1][Nh 16][Qh 65][host certificate DER, 1..1024 B]` |
| `0x63` | CHALLENGE | device → host (to the host's SETU service) | transfer | `[u8 version = 1][Nd 16][Qd 65][SigD 64][device certificate DER]` |
| `0x64` | FINISH | host → device | short | `[SigH 64]` |
| `0x65` | RESULT | device → host | short | `[u8 refAppType][u8 status][u8 detail]` |
| `0x66` | REFUSED | device → host | short | `[u8 appType]`: the gate refused a message of this type |

`Nh`, `Nd` are 16-byte random nonces. `Qh`, `Qd` are fresh P-256 public keys, as uncompressed X9.62 points (`04 ‖ X ‖ Y`). Signatures are raw `r ‖ s`, 64 bytes.

**STATUS** is sent on STATUS_REQ, and also whenever the state or the window changes while a host is connected.

| state | Name | Meaning |
|---|---|---|
| 0 | UNPROVISIONED | The device has no certificate: no handshake; only provisioning is reachable |
| 1 | OPEN | No host is bonded: HELLO is accepted |
| 2 | HOST_BONDED | A host is bonded and this link is not it (or not encrypted yet). HELLO from another address is refused |
| 3 | AWAIT_FINISH | CHALLENGE sent; FINISH expected |
| 4 | AWAIT_PAIRING | FINISH verified; exactly one pairing is allowed on this link |
| 5 | TRUSTED | This link is the bonded host at level 4 |

| flags bit | Meaning |
|---|---|
| `0x01` WINDOW_OPEN | The host window is open |
| `0x02` HOST_BOND | A host is bonded |

**RESULT** refers to HELLO (`0x62`) or FINISH (`0x64`). A HELLO that succeeds gets no RESULT: its answer is the CHALLENGE transfer. A FINISH that succeeds gets RESULT OK.

| status | Name | When |
|---|---|---|
| `0x00` | OK | FINISH verified: pairing is allowed |
| `0x01` | BAD_STATE | No host link, the device is unprovisioned or the host is trusted already (HELLO); FINISH without a CHALLENGE |
| `0x02` | PARSE | HELLO of 82 bytes or less (no certificate), longer than 1106 bytes, or with another version (detail: the version); FINISH not 64 bytes |
| `0x03` | BAD_CERT | The host certificate fails (detail: the [DeviceCertStatus](../../_ASW/_DEVICE_CERT/DeviceCert_Types.h) value: `0x03` PARSE, `0x04` NOT_CA (no CA), `0x05` BAD_SIG (another CA, or forged), `0x08` BAD_PROFILE (no host role, a CA, no digitalSignature, not P-256 / SHA-256), `0x0A` INTERNAL) |
| `0x04` | BAD_SIG | SigH does not verify: the host does not hold its certificate's key, or someone sits in between |
| `0x05` | HOST_BONDED | Another host is bonded: hold Button 3 to forget it |
| `0x06` | NO_PC_SVC | The device could not attach its SETU Client to the host's SETU service |
| `0x07` | BUSY | A handshake runs on this link (or its CHALLENGE transfer still does) |
| `0x08` | TIMEOUT | The handshake and its pairing took longer than `CONFIG_HOST_AUTH_TIMEOUT_MS` (30 s); the device then drops the link |
| `0x09` | PAIRING | The pairing after FINISH failed (detail: the SMP reason, `bt_security_err`), or ended without a bond (detail `0xFF`) |
| `0x0A` | INTERNAL | A cryptographic step failed on the device |
| `0x0B` | TRANSFER | CHALLENGE could not be sent, or its transfer failed (detail: the SETU status) |

After any failure, the link is a plain untrusted link again, and a new HELLO may follow.

## 4. The handshake

```
host                                                    device
 | STATUS_REQ ---------------------------------------->  |
 | <---------------------------------------- STATUS 1 0  |  OPEN
 | HELLO [1][Nh][Qh][host cert] ======================>  |  verify host cert (CA, host role)
 |                                                        |  Nd, ephemeral key, Z, T, SigD, passkey
 | <====================== CHALLENGE [1][Nd][Qd][SigD][device cert]   (to the host's service)
 | verify device cert (CA, device role), SigD;            |
 | Z, T, passkey                                          |
 | FINISH [SigH] ------------------------------------->  |  verify SigH
 | <----------------------------------- RESULT 64 00 00  |  AWAIT_PAIRING
 | LE SC pairing, passkey entry with the passkey <=====>  |  pairing_accept: this link only
 |                                                        |  bonded, level 4: one host bond
 | <---------------------------------------- STATUS 5 2  |  TRUSTED
```

The values:

```
T       = SHA-256("PH-HOSTAUTH-1" || Nh || Nd || Qh || Qd ||
                  SHA-256(host certificate) || SHA-256(device certificate))
SigD    = ECDSA-P256-SHA256(device key, "dev"  || T)
SigH    = ECDSA-P256-SHA256(host key,   "host" || T)
Z       = ECDH(ephemeral private key, peer's ephemeral point)       32 bytes, the X coordinate
passkey = u32be(HKDF-SHA256(IKM = Z, salt = Nh || Nd,
                            info = "PH-HOSTAUTH-1 passkey" || T, L = 4)) mod 1 000 000
```

The labels are ASCII, without terminators. The role labels "dev" and "host" keep one side's signature from passing as the other's. `_TEST/vectors/wire.json` section `host_auth` holds one whole handshake (keys, nonces, certificates, T, Z, the passkey, both signatures, HELLO, CHALLENGE and FINISH). Both the C and the Python tests check it.

**The device on HELLO** (§3 RESULT on each failure):
1. Checks the version.
2. Verifies the certificate with `ge_VerifyHostCertificate()`:
   - X.509 v3, P-256, ecdsa-with-SHA256;
   - signed by the device's CA;
   - CA:FALSE;
   - KeyUsage present, with digitalSignature;
   - **extendedKeyUsage clientAuth**, which is the host role.

   It imports the certificate's public key.
3. Makes Nd and a volatile ephemeral key, computes Z, destroys the ephemeral key, and computes T, SigD (with its device key) and the passkey.
4. Attaches its SETU Client to the host link and sends CHALLENGE.

**The host on CHALLENGE:**
1. Checks the device certificate:
   - issued by the CA in its credential;
   - P-256, CA:FALSE;
   - KeyUsage digitalSignature and keyAgreement;
   - **no** clientAuth.
2. Verifies SigD.
3. Computes Z, T and the passkey, then sends FINISH.

**Pairing.** The host link's SMP callbacks are the module's own (`bt_conn_auth_cb_overlay()`):
- `pairing_accept` allows a pairing only in AWAIT_PAIRING, and only on this link.
- `app_passkey` supplies the derived passkey. Its only callback makes the device **DisplayOnly** (`CONFIG_BT_APP_PASSKEY`), so the host enters the passkey. On Windows that is `DevicePairingKinds.ProvidePin`, answered with the passkey as six digits ([core/winrt_pairing.py](../../_TOOLS/BleHostGUI/blehost/core/winrt_pairing.py)).

The pairing must end bonded at level 4. The device then:
- deletes any other host's bond, so it keeps one host only;
- saves the record `hauth/host` = `[u8 address type][6 B address]` in settings;
- trusts the link.

**Reconnection.** When the bonded host's address connects again, the device asks for security (`bt_conn_set_security(L4)`, an SMP Security Request). Windows encrypts with the stored keys, and the device trusts the link once it is at level 4. No handshake is needed.

If the PC has lost its keys, the encryption fails and the link stays HOST_BONDED. The PC can run the handshake again from the same address: its new pairing replaces the bond. A different PC must wait until the device forgets the host (Button 3 held).

## 5. Forgetting the host

| What | Effect on the host bond |
|---|---|
| Button 3 held 3 s | Bond and record deleted, the host link dropped; window opens |
| A new host's pairing | Not reachable while another host is bonded (HELLO refused HOST_BONDED) |
| Provisioning wipe (DEPROVISION from the trusted host, or Button 0 held 5 s) | Every bond deleted, and the record; the host link stays, untrusted. The device is unprovisioned now: only provisioning is reachable |
| Boot on an unprovisioned device, or a record whose bond is gone | Record deleted |

The device's bond with its pairing peer is separate (`pair/peer`, [../Pairing/PROTOCOL.md §4.1](../Pairing/PROTOCOL.md)); forgetting the host leaves it alone, and the peer's bond restore at boot skips the host's bond.

## 6. Timing

| Limit | Value |
|---|---|
| Host window (Button 3) | `CONFIG_HOST_AUTH_WINDOW_MS`, 120 s |
| Grace window after the trusted host's link loss | `CONFIG_HOST_AUTH_GRACE_MS`, 60 s |
| Button 3 hold that forgets the host | `CONFIG_HOST_AUTH_FORGET_HOLD_MS`, 3 s |
| HELLO to trusted (handshake + pairing) | `CONFIG_HOST_AUTH_TIMEOUT_MS`, 30 s; then RESULT TIMEOUT and the link is dropped |
| PC: STATUS after STATUS_REQ / CHALLENGE / RESULT for FINISH / trusted after pairing | 3 s / 20 s / 10 s / 10 s |

## 7. Examples

From `_TEST/vectors/wire.json` (`host_auth.shorts`):

| Frame | Bytes |
|---|---|
| STATUS_REQ | `00 60` |
| STATUS OPEN, window open | `02 61 01 01` |
| STATUS TRUSTED, host bonded | `02 61 05 02` |
| RESULT FINISH OK | `03 65 64 00 00` |
| RESULT HELLO BAD_CERT (BAD_PROFILE) | `03 65 62 03 08` |
| REFUSED file command | `01 66 40` |
