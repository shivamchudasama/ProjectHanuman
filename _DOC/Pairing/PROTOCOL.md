# Device Pairing — Protocol

This is the contract for **certificate-based OOB pairing** of two provisioned devices (phase 2 of [`_DOC/CBAP`](../CBAP/), AN1396 §4.2). The firmware side is module [`_PAIR`](../../_ASW/_PAIR/Pair.c). A **host** orchestrates: the **Pairing** page of the PC GUI in [_TOOLS/BleHostGUI](../../_TOOLS/BleHostGUI/README.md), or the `pair` command of [setu_client.py](../../_TOOLS/BleHostGUI/setu_client.py). Both use [blehost/protocols/pairing.py](../../_TOOLS/BleHostGUI/blehost/protocols/pairing.py). Design, security and limitations are in [README.md](README.md).

The host tells each device its role and its peer. The two devices connect to each other and exchange their device certificates over SETU ([../SETU/PROTOCOL.md](../SETU/PROTOCOL.md)). Each verifies the other's certificate against the CA it was provisioned with ([../Provisioning/PROTOCOL.md](../Provisioning/PROTOCOL.md)). They then exchange their LE Secure Connections OOB data, each signed with the sender's device key, verify the signatures, and pair with the OOB method. The result is an authenticated, encrypted and bonded link at security level 4. From then on the two devices reconnect by themselves whenever the link is down, and encrypt it with the stored keys (§4.1).

## 1. Roles and links

| Party | Links | Role on each link |
|---|---|---|
| Host | One to each device | Central, GATT client of the Pairing service. Must be each device's **trusted host** ([../HostAuth/PROTOCOL.md](../HostAuth/PROTOCOL.md)): its bonded, level-4 link. CONTROL refuses anyone else |
| Device chosen as **central** | Host link and peer link | Peripheral to the host; central to the peer: scans for it, connects, starts pairing, writes SECURED; once bonded, reconnects and encrypts |
| Device chosen as **peripheral** | Host link and peer link | Peripheral to both; advertises **directed** to the central during a run, and while its bonded central is away |

Both devices are GATT client and server on the peer link: each sends with its SETU Client to the other's SETU Server.

A device holds at most one host link and one peer link. A second host connection is refused. Undirected advertising runs only while the device's host window is open and no host is connected ([../HostAuth/PROTOCOL.md §1](../HostAuth/PROTOCOL.md#1-roles-and-links)). A bonded peripheral whose central is not connected advertises directed to it (§4.1).

## 2. GATT: the Pairing service

UUIDs are `B1C1xxxx` followed by the project base `-16A1-4812-AF35-F3F29A92F6CA`.

| Attribute | UUID | Properties | Permissions | Value |
|---|---|---|---|---|
| Primary service | `B1C10000-…` | — | — | — |
| CONTROL | `B1C10001-…` | Write | Write | A command (§3.1) |
| STATUS | `B1C10002-…` | Read, Notify | Read | 19 bytes (§3.2), notified on every change |
| STATUS CCCD | `0x2902` | — | Read, Write | Write `01 00` to get notifications |
| SECURED | `B1C10003-…` | Write | Write, **LE Secure Connections encryption** | `01`, written by the central over the paired peer link (§5 step 9) |

**Advertising.** A provisioned device advertises the Pairing service UUID: flags, plus the incomplete list of 128-bit UUIDs. The device name is in the scan response. A device that is not provisioned advertises the SETU service instead ([../HexUpload/PROTOCOL.md §1](../HexUpload/PROTOCOL.md#1-discovery)). Both services are always in the GATT table.

**Addresses.** An address is 7 bytes on the wire: `[u8 type][6 B address, least significant byte first]`, the layout of Zephyr's `bt_addr_le_t`. `type` is `0` public or `1` random. An nRF54L15 uses a random static address, so `C4:5E:2A:11:9F:03` (random) is `01 03 9f 11 2a 5e c4`. STATUS gives each device's own address, so the host never has to guess the type.

## 3. Host ↔ device

### 3.1 CONTROL

| Opcode | Command | Bytes | Effect |
|---|---|---|---|
| `0x01` | START | `[01][u8 role][7 B peer address]`, 9 bytes | Start a run. role: `1` central, `2` peripheral |
| `0x02` | CANCEL | `[02]` | End a running run with error CANCELLED. No effect outside a run |
| `0x03` | UNPAIR | `[03]` | End any run, stop reconnecting, drop the peer link, delete the bond with the peer and its record, turn the LED off. State IDLE |

The write itself is refused with an ATT error when the command is malformed or cannot be queued. Every other outcome is reported in STATUS.

| ATT error | When |
|---|---|
| `0x03` Write Not Permitted | Written over the peer link: a peer device cannot drive this device |
| `0x08` Insufficient Authorization | Written over any link but the trusted host's ([../HostAuth/PROTOCOL.md §2](../HostAuth/PROTOCOL.md#2-the-gate)). Right after the bonded host connects, until its link is encrypted, CONTROL is refused too: the reference host retries for 3 s |
| `0x0D` Invalid Attribute Value Length | No opcode, START not 9 bytes, CANCEL or UNPAIR with a payload |
| `0x13` Value Not Allowed | Unknown opcode, role not 1 or 2, address type not 0 or 1 |
| `0xFE` Procedure Already in Progress | START while a run is in progress |
| `0x11` Insufficient Resources | The command queue is full |

### 3.2 STATUS

`[u8 state][u8 error][u8 detail][u8 provState][u8 role][7 B own address][7 B peer address]`, 19 bytes.

| Field | Meaning |
|---|---|
| `state` | §4 |
| `error` | Why the last run failed, `0` otherwise (table below) |
| `detail` | A code that goes with `error` (its low byte) |
| `provState` | The provisioning state ([../Provisioning/PROTOCOL.md §3.1](../Provisioning/PROTOCOL.md#31-status)): `3` PROVISIONED is required for START |
| `role` | Role of the current or last run, or after a reset the role saved with the bond: `0` none, `1` central, `2` peripheral |
| own address | This device's identity address |
| peer address | The peer of the current or last run, or of the stored bond. All zero if none |

| `error` | Name | `detail` | Cause |
|---|---|---|---|
| `0` | NONE | — | — |
| `1` | NOT_PROVISIONED | — | This device is not provisioned, or has no CA |
| `2` | BAD_ARG | — | The peer address is this device's own |
| `3` | BUSY | errno | A SETU transfer with the host was running at START, or the Server could not move to the peer link |
| `4` | TIMEOUT | state at expiry | The peer link was not up within 30 s (`CONFIG_PAIR_CONNECT_TIMEOUT_MS`), or the run did not end within 60 s (`CONFIG_PAIR_TIMEOUT_MS`) |
| `5` | CONNECT | HCI error or errno | The connection to the peer failed |
| `6` | NO_PEER_SVC | errno | The peer has no SETU service (Client attach failed) |
| `7` | PEER_CERT | certificate status | The peer certificate failed verification. Codes as provisioning RESULT: `3` PARSE, `4` NOT_CA (no CA on this device), `5` BAD_SIG (another CA, or tampered), `8` BAD_PROFILE (not P-256 / ecdsa-with-SHA256, CA:TRUE, or KeyUsage without digitalSignature and keyAgreement), `10` INTERNAL |
| `8` | OOB_SIG | PSA status | The peer's OOB signature does not verify with the key of its certificate |
| `9` | SMP | reason | Pairing failed. `bt_security_err` from the stack, an errno from a stack call, the security level reached if below 4, `0xFF` if not bonded, or `0x80`+config if the stack did not ask for both devices' OOB data |
| `10` | TRANSFER | SETU status | A certificate or OOB transfer failed (CRC, timeout, abort) |
| `11` | SECURED | ATT error or errno | Central: the peer refused, or SECURED could not be found or written |
| `12` | LINK_LOST | HCI reason | The peer link dropped during the run |
| `13` | CANCELLED | — | CANCEL from the host |
| `14` | INTERNAL | errno or PSA status | OOB data could not be made or signed, or advertising or scanning could not start |

A host MUST treat an unknown `error` as a failure.

## 4. States

| `state` | Name | Meaning |
|---|---|---|
| `0` | IDLE | Nothing running, no bond |
| `1` | ARMED | Peripheral: advertising directed to the peer. Central: scanning for it |
| `2` | CONNECTED | Peer link up; SETU moved to it; attaching to the peer's service |
| `3` | CERT_EXCHANGE | Device certificates being exchanged |
| `4` | CERT_VERIFIED | The peer certificate verified |
| `5` | OOB_EXCHANGE | Signed OOB data being exchanged |
| `6` | PAIRING | The peer's OOB data verified; SMP running (central: also writes SECURED) |
| `7` | PAIRED | Bonded at level 4, and the link was proven (SECURED written). The peer link stays up; when it is down, the devices reconnect (§4.1) |
| `8` | FAILED | The run ended; see `error`, `detail`. The peer link is dropped |

ARMED to PAIRING is a **run**. START is refused during a run and accepted in IDLE, PAIRED and FAILED. In PAIRED, the old peer link is dropped first and the new run pairs afresh. The reference host (GUI and `setu_client.py pair`) does not send START to two devices that are PAIRED with each other (each one's peer address is the other's own address): UNPAIR one of them first.

A bond survives a reset: a provisioned device with a bond starts in PAIRED, with the bonded peer as peer address and its saved role. A device that is not provisioned deletes its bonds at boot. A provisioning wipe (DEPROVISION or the button) deletes every bond and its record, returns to IDLE, and is refused during a run.

### 4.1 Reconnection

A device that has paired saves a **bond record**, `[u8 role][7 B peer address]`, in settings (key `pair/peer`) next to the stack's bond. While it is PAIRED with a record and the peer link is down (after a reset, or after the link dropped), it reconnects by itself:

- **Peripheral:** advertises connectable and **directed** to the bonded central (low duty cycle), also while a host is connected, and takes a connection from the bonded central as the peer link. While its host window is open and no host is connected, it advertises undirected instead, which the central accepts too. A connection from any other device is a host connection, as usual.
- **Central:** scans passively for the peer's address, connects (interval 15 ms, supervision timeout 4 s) and requests security level 4. The stack encrypts with the stored keys; there is no new pairing (pairing outside a run is refused anyway, §5 step 8).
- Once the link is encrypted at **level 4** with the bonded keys, both devices **blink their LED** (`DK_LED1`, LED0 on the nRF54L15 DK; 500 ms on, 500 ms off) for as long as the link stays up, and turn it off when it drops.
- A link that does not reach level 4 within 10 s, whose encryption fails (for example, the peer has lost its keys), or that comes up below level 4, is dropped. The central scans again 1 s after the link drops or an attempt fails, for as long as it stays PAIRED.
- SETU stays with the host on a reconnected link: nothing is exchanged over it here. STATUS stays PAIRED throughout, and is not notified for a reconnection.
- START, UNPAIR and a wipe stop reconnecting and delete the record. A bond without a record (from older firmware) restores PAIRED with role `0` and is not reconnected; a record without its bond is deleted at boot. The trusted host's bond (record `hauth/host`, [../HostAuth/PROTOCOL.md §5](../HostAuth/PROTOCOL.md#5-forgetting-the-host)) is never taken for the peer's; UNPAIR leaves it alone.

The LED after the first pairing stays as it was: steady on the peripheral (§5 step 9), off on the central. It turns off when that link drops, and blinks once the pair has reconnected.

## 5. Sequence

The host connects to both devices, subscribes to STATUS and reads it (provState must be 3, neither may be in a run, and they must not be PAIRED with each other; the own addresses give it the two peer addresses). Then:

1. **START** to the peripheral, `[01][02][central's address]`, then to the central, `[01][01][peripheral's address]`. Each device deletes any old bond with the peer.
2. **Peripheral:** low-duty directed connectable advertising to the central. **Central:** passive scan from its identity address (the target of the directed advertising; a scanner on a private address would not receive it). On a connectable advertisement from the peer it stops scanning and connects (interval 15 ms, supervision timeout 4 s). → ARMED.
3. **Link up.** On both: the SETU router admits only appTypes `0x30`–`0x3F` (§6). The SETU Server moves from the host link to the peer link, and the Client attaches to the peer's SETU service. → CONNECTED.
4. **Certificates.** Each sends its device certificate, appType `0x30`. → CERT_EXCHANGE.
5. **Verification.** Each verifies the peer's certificate against its CA: chain, profile and KeyUsage digitalSignature + keyAgreement. This also gives the peer's public key. → CERT_VERIFIED.
6. **OOB data.** Each makes fresh LE Secure Connections OOB data (`r`, `c`) and signs it (§7). It sets its SMP OOB flag, then sends `[r][c][signature]` with appType `0x31`, after its own certificate has been acknowledged. → OOB_EXCHANGE.
7. **OOB verification.** Each verifies the peer's signature with the peer's certificate key, over the peer's address as sender and its own as receiver. → PAIRING.
8. **Pairing.** The central requests security level 4. SMP uses the OOB method (both OOB flags set), and asks each device for both OOB data sets. Each answers once the peer's data has verified, and refuses any other link. The result must be level 4 and bonded.
9. **Proof.** The central writes `01` to the peer's SECURED, which the stack allows only on a level-4 encrypted link. The peripheral lights its LED (`DK_LED1`, LED0 on the board), steady → PAIRED. The central → PAIRED when the write is acknowledged.
10. Each device moves SETU back to its host link, clears the OOB flag and saves the bond record (§4.1). The host may disconnect: the peer link stays up.

```
Host            Device P (peripheral)                     Device C (central)
 |-- START(2,C) ->|                                              |
 |-- START(1,P) ------------------------------------------------>|
 |                |~~ directed adv to C ~~>          scan, connect|
 |                |<=========== peer link (open) ===============>|
 |                |-- 0x30 own certificate ---------------------->|  verify P
 |                |<- 0x30 own certificate -----------------------|  verify C
 |                |-- 0x31 [rP][cP][sig P] ---------------------->|  verify sig
 |                |<- 0x31 [rC][cC][sig C] -----------------------|  verify sig
 |                |<-------- SMP: LE SC, OOB, level 4, bond ----->|
 |                |<-- write SECURED = 01 (encrypted) ------------|
 |<- STATUS PAIRED (LED0 on)                                      |
 |<- STATUS PAIRED ----------------------------------------------|
```

STATUS is notified to the host at every state change, so the host follows both devices until both are PAIRED or one is FAILED. When one device fails, it drops the peer link and the other then fails with LINK_LOST, or with its own error.

## 6. Objects between the devices

Transfers go from each device's SETU Client to the other's Server, over the peer link. There are no short messages between devices.

| appType | Object | Length |
|---|---|---|
| `0x30` PEER_CERT | The sender's DER device certificate | 1–1024 |
| `0x31` OOB | `[16 B r][16 B c][64 B signature]` | exactly 96 |

The receiver refuses a transfer at START (SETU ABORT by receiver, REJECTED) when:

- no run holds the peer link (state below CONNECTED or above OOB_EXCHANGE);
- the appType is not `0x30` or `0x31`, or its length is out of range;
- that object was already received in this run;
- the other object is being received at the same time.

While a run holds the peer link, the router admits only `0x30`–`0x3F`. Any other transfer, such as hex upload or a certificate for provisioning, is refused at START, and any other short message is dropped. A peer device therefore cannot upload hex, provision or wipe this device. CONTROL refuses writes from the peer link (§3.1).

## 7. Signed OOB data

```
message   = r (16) ‖ c (16) ‖ sender address (7) ‖ receiver address (7)      46 bytes
signature = ECDSA P-256 over SHA-256(message), raw r ‖ s                     64 bytes
frame     = r ‖ c ‖ signature                                                 96 bytes
```

- `r`, `c`: the sender's LE Secure Connections OOB random and confirm values (`bt_le_oob_get_local()`). `c` = f4(PKx, PKx, r, 0) with the sender's SMP public key, so it ties `r` to that pairing key.
- Signed with the sender's device key (PSA key `0x0001`, the key its certificate carries). It is verified with the public key taken from the sender's verified certificate.
- The addresses are not sent: each side knows both. Binding them means a frame made for one peer does not verify for another, or in the other direction.

## 8. Serial output

A run logs its steps on the device's UART (`<inf> APP_LOG: …`): `pairing as central|peripheral`, `state N` at each change, `peer link up`, `peer certificate verified`, `peer OOB data verified`, `SMP done, level 4`, `paired at level 4, bonded`. A failure logs `pairing failed: error E, detail D`. At boot, a restored bond logs `bonded peer restored` (with ` (no record: not reconnected)` without a bond record), and UNPAIR or a wipe logs `bond deleted` or `bonds deleted`. A reconnection logs `looking for the bonded peer` (central), `bonded peer link up`, `bonded peer reconnected at level 4`, and on a drop `peer link down (reason 0xRR)`; a refused link logs `bonded link not secured: level L, error E` or `bonded link not secured in time`, and a failed attempt `bonded peer not reached (0xRR)`.

## 9. Timing

| Step | Limit | Where |
|---|---|---|
| START to peer link up | 30 s | Device, `CONFIG_PAIR_CONNECT_TIMEOUT_MS` |
| START to PAIRED | 60 s | Device, `CONFIG_PAIR_TIMEOUT_MS` |
| Reconnected link to level 4 | 10 s | Device, `PAIR_RECONNECT_SECURE_MS` in `Pair.c` |
| Central: next reconnection attempt | 1 s after a drop or failure | Device, `PAIR_RECONNECT_DELAY_MS` in `Pair.c` |
| LED blink | 500 ms on, 500 ms off | Device, `PAIR_LED_BLINK_MS` in `Pair.c` |
| Host waiting for both PAIRED or a FAILED | 75 s (reference) | Host: above the device limit, so the device reports the timeout itself |
| Each transfer | SETU's own timeouts | [../SETU/PROTOCOL.md](../SETU/PROTOCOL.md) |

## 10. Examples

Golden values from [_TEST/vectors/wire.json](../../_TEST/vectors/wire.json) (`pairing`). Device A is `C4:5E:2A:11:9F:03` and device B is `E1:02:03:04:05:06`, both random.

| Value | Bytes |
|---|---|
| START, central, peer B | `01 01 01 06 05 04 03 02 e1` |
| START, peripheral, peer A | `01 02 01 03 9f 11 2a 5e c4` |
| CANCEL | `02` |
| UNPAIR | `03` |
| STATUS A, IDLE, provisioned | `00 00 00 03 00 01 03 9f 11 2a 5e c4 00 00 00 00 00 00 00` |
| STATUS A, ARMED as central, peer B | `01 00 00 03 01 01 03 9f 11 2a 5e c4 01 06 05 04 03 02 e1` |
| STATUS B, PAIRED as peripheral, peer A | `07 00 00 03 02 01 06 05 04 03 02 e1 01 03 9f 11 2a 5e c4` |
| STATUS A, FAILED, PEER_CERT BAD_SIG | `08 07 05 03 01 01 03 9f 11 2a 5e c4 01 06 05 04 03 02 e1` |

`pairing.oob` in the same file is an OOB frame from A to B, with a real signature by the key it lists. Both the C test (TF-PSA-Crypto) and the Python test verify it.
