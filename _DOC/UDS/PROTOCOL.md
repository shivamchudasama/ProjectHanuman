# UDS over BLE — Protocol

This is the contract between the firmware's UDS front-end ([`_ASW/_UDS/UdsCmd.c`](../../_ASW/_UDS/UdsCmd.c),
on top of the job engine described in [README.md](README.md)) and a host that drives UDS on the
device: `setu_client.py uds` and `flash`, and the BLE Host GUI's ECU page, both on
[`blehost/protocols/uds.py`](../../_TOOLS/BleHostGUI/blehost/protocols/uds.py).

The device itself talks UDS (ISO 14229) over ISO-TP (ISO 15765-2) on its CAN bus. The host only
says what to do: which ECU, which request, which file to flash with which sequence. ISO-TP is
never tunnelled over BLE.

Everything travels as SETU **short messages** on the host link. The host writes them to the
device's DATA characteristic, and the device notifies on CTRL. The SETU service, the frame format
and link setup are in [../SETU/PROTOCOL.md](../SETU/PROTOCOL.md) and
[../HexUpload/PROTOCOL.md §1–2](../HexUpload/PROTOCOL.md#1-discovery). A short frame is
`[u8 payload length][u8 appType][payload]`, with a payload of at most 242 bytes. Numbers in the
payloads below are **little-endian**; UDS bytes inside them are as on the CAN bus (big-endian).

## 1. Messages

| appType | Direction | Payload |
|---|---|---|
| `0x50` TARGET | host → device | `[seq][flags][u32 bitrate][u32 data bitrate][u32 tx id][u32 rx id][u32 func id][ext addr][tx dl][pad byte][u16 P2 ms][u16 P2* ms]` (29 bytes) |
| `0x51` RESULT | device → host | `[seq][ref appType][status][data]` |
| `0x52` DIAG_REQ | host → device | `[seq][flags][UDS request, 1..240 bytes]` |
| `0x53` DIAG_RSP | device → host | `[seq][status][u16 total][u16 offset][part, ≤ 236 bytes]` |
| `0x54` UNLOCK | host → device | `[seq][level][algo]` |
| `0x55` FLASH | host → device | `[seq][parameters, 34 bytes][u8 name length][name]` |
| `0x56` STATUS | device → host | `[state][step][rec idx][rec cnt][u32 done][u32 total][last SID][last NRC][status]` (15 bytes) |
| `0x57` ABORT | host → device | `[seq]` |
| `0x58` STATUS_REQ | host → device | `[seq]` |

- **`seq`** is chosen by the host and echoed in the answer (RESULT, DIAG_RSP).
- **Ignored messages:** an empty message, a RESULT/DIAG_RSP/STATUS sent by the host, and
  `0x59`–`0x5F` (reserved) are ignored.
- **No transfers:** a transfer (START) with an appType of the range is refused.
- **Peer links:** while the SETU Server is bound to a peer device for pairing, the router admits
  only `0x30`–`0x3F`.

### TARGET

The ECU the device talks to: the CAN configuration (applied to the controller, `gi_CanIf_Configure()`)
and the UDS addressing. Answered by RESULT once applied.

| Field | Meaning |
|---|---|
| flags | `0x01` 29-bit IDs, `0x02` CAN FD, `0x04` BRS, `0x08` padding, `0x10` extended addressing (refused: NOT_SUPPORTED), `0x20` functional ID valid |
| bitrate / data bitrate | Nominal and (CAN FD) data-phase bitrate, bit/s |
| tx id / rx id / func id | Physical request, response, functional request identifiers |
| ext addr | Must be 0 |
| tx dl | ISO-TP frame length: 0 (8, or 64 with CAN FD), 8, or with CAN FD 12…64 |
| pad byte | 0 or `0xCC`, the byte Zephyr's ISO-TP pads with. The padding flag must match the firmware's build (`CONFIG_ISOTP_ENABLE_TX_PADDING`, on), else NOT_SUPPORTED |
| P2 / P2* | Fixed timing in ms. 0 means the defaults (150 ms / 5 s), then the ECU's own from each DiagnosticSessionControl response (+ 50 ms) |

The target stays until the next TARGET (or a reset). A refused TARGET leaves no target.

### DIAG_REQ / DIAG_RSP

The request, SID first, is sent to the physical ID, or to the functional ID with flag `0x01`. A
functional request is at most 7 bytes. The device waits for the matching response:
- After NRC 0x78 it waits P2* again.
- After NRC 0x21 it repeats the request up to 3 times.
- Unrelated frames are skipped.

DIAG_RSP carries the ECU's response as it came, positive or `7F SID NRC`. A response longer than
236 bytes comes in several DIAG_RSPs with the same `seq`, `total` = its length and `offset` = where
the part goes. With no response (none came, or a suppressed positive response), one DIAG_RSP has
`total` 0. Responses are at most 1024 bytes (`CONFIG_UDS_RESPONSE_MAX`).

### UNLOCK

SecurityAccess with an on-device seed→key algorithm (`algo`): `27 <level>`, then
`27 <level + 1> <key>`. `level` is odd, 0x01…0x7D. An all-zero seed means the level is unlocked
already. RESULT `data` is the NRC when the status is NRC. The algorithms are in
[README.md §4](README.md#4-seed--key): `0x01` BENCH_XOR; `0x80`–`0xFF` OEM, only in builds that
have them.

### FLASH / STATUS / ABORT

FLASH starts a flash job on the stored file `/FLASH_DISK:/FW/<name>`: a hex upload stored with
BEGIN/COMMIT ([../HexUpload/PROTOCOL.md §7](../HexUpload/PROTOCOL.md#7-storing-the-upload-as-a-file)).
The name is 1–32 characters from `A-Z a-z 0-9 . _ -`. The device answers **at once** with RESULT:
OK (accepted) or the refusal. Then it sends STATUS:
- at every step;
- at most every 250 ms during a transfer;
- once at the end (state DONE, FAILED or ABORTED, with the final status).

STATUS_REQ is answered with STATUS at any time (the last job's outcome when none runs).

The parameters (34 bytes):

| Offset | Field | Meaning |
|---|---|---|
| 0 | u16 flags | `0x0001` 10 03 first, `0x0002` 85 02, `0x0004` 28 control type, `0x0008` SecurityAccess, `0x0010` fingerprint 2E, `0x0020` erase routine, `0x0040` erase per record (with address and size), `0x0080` check routine, `0x0100` check with the image's CRC-32, `0x0200` 11 reset at the end |
| 2 | u8 security level | requestSeed level (odd) |
| 3 | u8 key algo | As UNLOCK |
| 4 | u8 comm control | 0x28 controlType (e.g. 0x03 disable RX and TX) |
| 5 | u8 comm type | 0x28 communicationType (e.g. 0x01 normal messages) |
| 6 | u8 reset type | 0x11 resetType |
| 7 | u8 ALFID | addressAndLengthFormatIdentifier: high nibble size bytes, low nibble address bytes, 1..4 each |
| 8 | u8 DFI | dataFormatIdentifier |
| 9 | u16 erase RID | Erase routine identifier (e.g. 0xFF00) |
| 11 | u16 check RID | Check routine identifier (e.g. 0xFF01) |
| 13 | u16 max block | Cap on a TransferData request's length (0: the ECU's maxNumberOfBlockLength). The device's own cap is 2048 bytes |
| 15 | u16 fingerprint DID | |
| 17 | u8 fingerprint length | 1..16 with the fingerprint flag |
| 18 | 16 bytes | Fingerprint record, zero-padded |

The sequence these build is in [README.md §3](README.md#3-the-programming-sequence).

| STATUS field | Meaning |
|---|---|
| state | 0 IDLE, 1 RUNNING, 2 DONE, 3 FAILED, 4 ABORTED |
| step | 0 NONE, 1 EXT_SESSION, 2 DTC_OFF, 3 COMM_OFF, 4 PROG_SESSION, 5 SECURITY, 6 FINGERPRINT, 7 ERASE, 8 DOWNLOAD, 9 TRANSFER, 10 EXIT, 11 CHECK, 12 RESET, 13 DONE (the last step started) |
| rec idx / rec cnt | Record being written (0-based) / records in the file |
| done / total | Data bytes transferred / in the file |
| last SID / last NRC | The last request's SID and the ECU's NRC (0: none) |
| status | The outcome (§2); OK while running |

ABORT stops the running job at its next request, answered with RESULT OK, or BAD_STATE when no
job runs. The final STATUS then says ABORTED.

## 2. Status codes

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | Done, or accepted |
| 1 | BUSY | Another request or job runs, a hex upload is being stored, a file is open through the file commands, or a session locked the bus |
| 2 | BAD_ARG | A malformed message, or invalid parameters (name, flags, ALFID, fingerprint length, level, IDs) |
| 3 | BAD_STATE | ABORT without a running job |
| 4 | NOT_READY | No CAN controller (no click), or no target set |
| 5 | NRC | The ECU answered negatively: DIAG_RSP carries `7F SID NRC`, UNLOCK's RESULT the NRC, STATUS the last SID and NRC |
| 6 | TIMEOUT | The ECU did not answer within P2 (P2* after NRC 0x78) |
| 7 | TRANSPORT | ISO-TP or CAN error |
| 8 | BUS_OFF | The CAN controller went bus-off |
| 9 | FILE | The flash file is missing, unreadable, or not a sequence of records |
| 10 | ABORTED | The host aborted the flash job |
| 11 | NOT_SUPPORTED | A key algorithm the build lacks, extended addressing, a pad byte other than 0xCC, padding that differs from the build's, a mode the controller lacks |

## 3. Rules

1. Connect and subscribe to CTRL, as for an upload. Send TARGET first; until a target is
   applied, DIAG_REQ, UNLOCK and FLASH get NOT_READY.
2. One request at a time: send the next once the previous one's RESULT or DIAG_RSP is in. A
   request while another runs or a flash job runs is answered BUSY (TARGET, DIAG_REQ, UNLOCK,
   FLASH). Allow several seconds: the ECU may answer NRC 0x78 repeatedly.
3. A flash job runs to its end without the host. While it runs, its file commands and a hex
   upload's BEGIN answer BUSY. If the host disconnects, the job goes on; reconnect and send
   STATUS_REQ.
4. Between requests, the device keeps a non-default session alive with TesterPresent (`3E 80`)
   every 2 s. Send `10 01` (or reset the ECU) to end it.
5. Before the first request the device discards stale responses. A request whose answer would
   not fit is answered TRANSPORT.

## 4. Examples

The golden frames are in [`_TEST/vectors/wire.json`](../../_TEST/vectors/wire.json), section
`uds_cmd`. The C tests (`uds_cmd`) and the Python tests (`test_uds_protocol.py`) both check them.
Frames as on the air:

```
TARGET     1d 50 01 28 20 a1 07 00 00 00 00 00 e0 07 00 00 e8 07 00 00 df 07 00 00 00 08 cc 00 00 00 00
                                                        seq 1, padded, functional 0x7DF, 500 kbit/s, 0x7E0 / 0x7E8
RESULT     03 51 01 50 00                               seq 1 TARGET OK
DIAG_REQ   05 52 03 00 22 f1 90                         seq 3 ReadDataByIdentifier F190
DIAG_RSP   1a 53 03 00 14 00 00 00 62 f1 90 57 4d …     seq 3 OK, 20 bytes at 0: 62 F1 90 "WMI0HANUMAN000001"
DIAG_RSP   09 53 05 05 03 00 00 00 7f 22 31             seq 5 NRC: 7F 22 31 requestOutOfRange
UNLOCK     03 54 08 01 01                               seq 8 level 1, BENCH_XOR
RESULT     04 51 09 54 05 35                            seq 9 UNLOCK NRC 0x35 invalidKey
FLASH      2c 55 0b ff 03 01 01 03 01 01 44 00 00 ff 01 ff 00 00 5a f1 07 20 26 10 12 01 02 03 00 … 08 41 50 50 31 2e 42 49 4e
                                                        seq 11, every step, file "APP1.BIN"
RESULT     03 51 0b 55 00                               seq 11 FLASH accepted
STATUS     0f 56 01 09 00 02 10 00 00 00 1e 00 00 00 36 00 00   RUNNING TRANSFER, record 1/2, 16/30 bytes
STATUS     0f 56 03 09 01 02 14 00 00 00 1e 00 00 00 36 72 05   FAILED: NRC 0x72 to TransferData
```

## 5. Security

Like the file commands, UDS reaches a provisioned device only from its **trusted host**
([../HostAuth/PROTOCOL.md §2](../HostAuth/PROTOCOL.md#2-the-gate)): the PC that proved a host
certificate of the device's CA and bonded with the derived passkey. Every UDS message from another
link is dropped and answered with REFUSED (`0x66`). An unprovisioned device takes none. Whoever holds a
trusted host's credential and bond can still set a target, send any UDS request (including ones
that change ECU memory) and flash a connected ECU. `CONFIG_UDS_CMD=n` leaves the range
unregistered, for images without UDS over BLE.
