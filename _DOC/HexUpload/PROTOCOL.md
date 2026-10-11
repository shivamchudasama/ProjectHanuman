# Hex Upload — Protocol

This is the contract between the firmware in `_ASW` (the BLE peripheral and GATT server that receives data) and a client that uploads an Intel HEX file. Everything runs on top of the SETU library, so the client implements the SETU **Client** role. The SETU protocol itself (GATT service, frame formats, sequences, timing, errors) is specified in [../SETU/PROTOCOL.md](../SETU/PROTOCOL.md). There are two clients: the PC GUI in [_TOOLS/BleHostGUI](../../_TOOLS/BleHostGUI/README.md) (Hex Upload tab), and the `hex` command in the reference client [setu_client.py](../../_TOOLS/BleHostGUI/setu_client.py), whose protocol code the GUI reuses.

The server does not program its own flash. It buffers each segment in RAM and logs it on the serial terminal (UART, 921600 baud, RTS/CTS flow control): by default one summary line per segment, or every byte as `0xAAAAAAAA: xx xx …` lines when the firmware is built with `CONFIG_DS_HEX_DUMP=y` (see §6). When the client frames the upload with BEGIN and COMMIT, the server also stores it as a file on the external flash, one record per segment (§7), for an ECU update to use later.

## 1. Discovery

| Item | Value |
|---|---|
| Device name (scan response) | `ProjectHanuman` (`CONFIG_BT_DEVICE_NAME`) |
| Advertised service (adv data, 128-bit list) | `B1C00000-16A1-4812-AF35-F3F29A92F6CA` until the device is provisioned; then the Pairing service `B1C10000-…` ([../Pairing/PROTOCOL.md §2](../Pairing/PROTOCOL.md#2-gatt-the-pairing-service)). The SETU service is in the GATT table either way |
| Connections | One host at a time (a second is refused); while pairing, a peer device on a second link |
| Security | None (open link) |

## 2. GATT table

The UUIDs are `B1C0xxxx` followed by the project base `-16A1-4812-AF35-F3F29A92F6CA` (`_ASW/_BLE_GENERIX/BaseUUIDs.h`).

| Attribute | UUID | Properties | Permissions | Value |
|---|---|---|---|---|
| Primary service | `B1C00000-…` | — | — | — |
| DATA | `B1C00001-…` | Write Without Response, Write | Write | One SETU frame per write, 2…244 B. **Use Write Without Response.** Long (prepared) writes are refused |
| CTRL | `B1C00002-…` | Notify | — | Server → client frames (ACK / NACK / END / ABORT and short messages) |
| CTRL CCCD | `0x2902` | — | Read, Write | Write `01 00` to subscribe. The server ignores START until the client is subscribed |
| CAPS | `B1C00003-…` | Read | Read | 4 B: protocol version `2`, max frame `244`, window `16`, reserved `0` |

The device also exposes Zephyr's GAP service and the Device Information service.

Link setup: the server itself requests 2M PHY, data length 251 and MTU 247 about 2 s after connecting, then a connection interval of 7.5–15 ms (latency 0, supervision timeout 4 s), which Zephyr sends 5 s after connecting (`CONFIG_BT_CONN_PARAM_UPDATE_TIMEOUT`). The interval sets the throughput, so a client that uploads right after connecting runs at the central's default interval until then. The central may refuse the request. A client should also request MTU 247. SETU's chunk size is `min(ATT_MTU − 3, 244) − 4`, fixed when each transfer starts.

## 3. Application messages

| appType | Direction | Kind | Payload |
|---|---|---|---|
| `0x10` SEGMENT | client → server | SETU transfer (START / DATA …) | `[u32 LE start address][data]` |
| `0x01` RESULT | server → client | short message on CTRL | `[u8 status][u32 LE address][u32 LE data length]` |
| `0x11` STORED | server → client | short message on CTRL | `[u8 status][u32 LE address][u32 LE data length]` |
| `0x12` BEGIN | client → server | short message | File name, 1..32 characters (§7) |
| `0x13` COMMIT | client → server | short message | empty |
| `0x14` FILE | server → client | short message on CTRL | `[u8 op][u8 status][u32 LE file size][u32 LE file CRC-32]`, answering BEGIN (`op` `0x12`) and COMMIT (`op` `0x13`) |

In RESULT and STORED, `status` is a `SETUStatus_E` value (`0` = OK). On failure, RESULT carries address and length `0`. STORED is `0` unless the upload is being stored in a file and writing it failed: then `8` (SINK_ERROR), and the client should stop. In FILE, `status` is the file system's code ([../FileSysManager/PROTOCOL.md §3](../FileSysManager/PROTOCOL.md#3-status-codes): `0` OK, `5` BAD_ARG, `6` BAD_STATE, `7` BUSY, `8` NOT_MOUNTED, `9` IO, …).

The START frame's length and CRC-32 cover the whole object, **address header included**.

The device's SETU Server is shared by appType range ([_ASW/_SETU_SVC/SETURouter.c](../../_ASW/_SETU_SVC/SETURouter.c)). This is the whole registry:

| appTypes | Owner | Contract |
|---|---|---|
| `0x01`, `0x10`–`0x1F` | Hex upload (`_DATA_STORE`); `0x15`–`0x1F` reserved | This document |
| `0x20`–`0x2F` | Device provisioning (`_PROV`) | [../Provisioning/PROTOCOL.md](../Provisioning/PROTOCOL.md) |
| `0x30`–`0x3F` | Device pairing (`_PAIR`), between two devices | [../Pairing/PROTOCOL.md](../Pairing/PROTOCOL.md) |
| `0x40`–`0x4F` | File commands (`_FS_CMD`), when built with `CONFIG_FS_CMD` | [../FileSysManager/PROTOCOL.md](../FileSysManager/PROTOCOL.md) |
| `0x50`–`0x5F` | UDS over BLE (`_ASW/_UDS`): target, diagnostic requests, unlock, flash jobs; when built with `CONFIG_UDS_CMD` | [../UDS/PROTOCOL.md](../UDS/PROTOCOL.md) |
| others up to `0xEF` | Free | A transfer is refused (§5), a short message is logged and ignored |

A new user of the Server registers a free range with `gi_SETURouter_Register()` before `gi_SETURouter_Start()` and adds it here. The router holds `SETU_ROUTER_MAX_ROUTES` (5) ranges, all used now: a sixth user raises it.

While the Server is bound to a peer device for pairing, the router's filter (`gv_SETURouter_SetFilter()`) admits only `0x30`–`0x3F`: any other transfer is refused at START as an unknown type and any other short message is dropped, so a peer device cannot upload hex or reach provisioning.

## 4. Upload sequence

1. Parse the hex file. Apply record types `02`/`04` (extended address) to data records (`00`), ignore `03`/`05`, and stop at `01`.
2. Merge the bytes into contiguous runs. Split any run longer than **65536** data bytes (the server's `DS_BUF_SIZE`).
3. Connect, subscribe to CTRL, and optionally read CAPS.
4. To store the upload as a file: send BEGIN with the file name and wait for FILE (§7). Only status `0` goes on.
5. For each segment:
   1. Send a SETU transfer with appType `0x10` and object `pack('<I', address) + data`.
   2. Wait for END. Only status `OK` means the segment arrived intact.
   3. RESULT follows right away.
   4. **Wait for STORED** before sending the next segment. The server keeps the segment in its only buffer until it has been logged, and written to the file when one is open. By default the log is one line and STORED follows almost at once; writing a 64 KiB segment to the external flash takes about a second or two more. With `CONFIG_DS_HEX_DUMP=y` the full dump takes several seconds per 64 KiB segment (10–15 s has been observed at 921600 baud), and a slower terminal or UART setting stretches it further, so use a generous timeout. A STORED status other than `0` means the file write failed.
6. If BEGIN was sent: send COMMIT and wait for FILE. Status `0` with the size and CRC-32 of the records the client sent (§7) means the file is stored under its name.

## 5. Rejections

The server rejects a START by answering it with **ABORT** (direction *by receiver*, reason `REJECTED` = `0x05`) instead of the first ACK. No END follows (`setu_client.py` reports this as `ABORTED_BY_SERVER:REJECTED`). This happens when:

| Cause | Fix |
|---|---|
| appType is not `0x10` (no other range takes segments; provisioning refuses non-certificates and also answers RESULT `0x26`, see its protocol) | Use `0x10` |
| Object ≤ 4 bytes (no data) | Send at least one data byte |
| Object > 4 + 65536 bytes | Split the segment |
| The previous segment is still being dumped (or written to the upload file) | Wait for STORED |

A transfer that fails (link lost, timeout, CRC error, abort) is discarded whole, and the client resends the segment.

## 6. Serial output

Default (`CONFIG_DS_HEX_DUMP=n`), one line per segment:

```
<inf> APP_LOG: SEG addr=0x00010000 len=1148 crc=0x1a2b3c4d
```

With `CONFIG_DS_HEX_DUMP=y` in `_DI/prj.conf` (debugging), every byte:

```
<inf> APP_LOG: SEG start addr=0x00010000 len=1148 crc=0x1a2b3c4d
<inf> APP_LOG: 0x00010000: 00 10 00 20 d5 1c 00 00 ...
...
<inf> APP_LOG: SEG end addr=0x00010000 len=1148
```

`crc` equals the CRC-32 in the client's START frame, so a segment on the terminal can be matched to the transfer that carried it.

A stored upload adds one line at COMMIT, with the file's size and CRC-32 as FILE reports them:

```
<inf> APP_LOG: FILE /FLASH_DISK:/FW/FW1 size=6568 crc=0x505c6f84
```

## 7. Storing the upload as a file

Between BEGIN and COMMIT the server writes each verified segment to the FAT volume on its external flash ([../FileSysManager/README.md](../FileSysManager/README.md)) before it sends STORED.

**File.** `/FLASH_DISK:/FW/<name>`. It holds one record per segment, in the order received:

```
[u32 LE start address][u32 LE data length][data] [u32 LE start address][u32 LE data length][data] …
```

so a sparse hex image keeps its addresses, and the file is `Σ (8 + length)` bytes. The CRC-32 in FILE is the IEEE CRC-32 (as zlib's `crc32`) over the whole file.

**Name.** 1..32 characters from `A-Z a-z 0-9 . _ -`, not `.` or `..`, and not `UPLOAD.TMP` (any case). A COMMIT replaces an older file of the same name.

**BEGIN** creates `/FLASH_DISK:/FW` if needed, deletes a temporary file left by a lost upload, and opens `/FLASH_DISK:/FW/UPLOAD.TMP`. FILE answers:

| status | When |
|---|---|
| 0 OK | Segments are written from now on |
| 5 BAD_ARG | The name is empty, longer than 32, or not a plain name |
| 7 BUSY | A file is open through the file commands, a UDS flash job runs ([../UDS/PROTOCOL.md](../UDS/PROTOCOL.md)), or BEGIN / COMMIT came faster than the server works them off |
| 8 NOT_MOUNTED, 9 IO, … | The volume is not mounted, or a flash error |

A BEGIN while an upload is open discards that upload (its COMMIT never came, e.g. the link was lost) and starts the new one.

**COMMIT** closes the temporary file, deletes an older file of the name, and renames the temporary file. FILE answers `0` with the file's size and CRC-32, or:

| status | When |
|---|---|
| 6 BAD_STATE | No BEGIN before (or it failed) |
| the first write error (`4` NO_SPACE, `9` IO, …) | A segment could not be written (its STORED said SINK_ERROR); the file is deleted |
| `9` IO, … | Closing or renaming failed; the file is deleted |

Segments sent without BEGIN are only logged, as before. Between BEGIN and COMMIT the file commands answer BUSY ([../FileSysManager/PROTOCOL.md §4](../FileSysManager/PROTOCOL.md#4-sequence-and-rules)). The stored file can be listed and read back with them (`setu_client.py fs get /FW/<name> <local file>`).

The golden BEGIN, COMMIT and FILE frames, and the first segment's record with its file size and CRC-32, are in [`_TEST/vectors/wire.json`](../../_TEST/vectors/wire.json), section `hex_file`.
