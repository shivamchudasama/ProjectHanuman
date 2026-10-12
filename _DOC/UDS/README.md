# UDS — ECU diagnostics and flashing over CAN, triggered over BLE

The device flashes and diagnoses ECUs on its CAN / CAN FD bus ([../CAN/README.md](../CAN/README.md))
with UDS (ISO 14229) over ISO-TP (ISO 15765-2). A host on BLE (`setu_client.py`, later a GUI or a
touchscreen) only tells it what to do. The device runs the whole flash itself, from the image
stored on its external flash, so a flash never depends on the BLE link staying up.

```
host ──BLE: SETU 0x50–0x5F──► UdsCmd ──► UdsJob (one thread, one job) ──► UdsClient ──► ISO-TP ──► CanIf ──► ECU
                                           │ reads /FLASH_DISK:/FW/<name>           (_LIB/UdsClient)  (Zephyr)  (_ASW/_CAN)
                                           └ UdsKey (seed → key)
```

- **The image** arrives first, as an ordinary hex upload stored as a file:
  `setu_client.py hex app.hex --store APP1.BIN` writes `/FLASH_DISK:/FW/APP1.BIN`
  ([../HexUpload/PROTOCOL.md §7](../HexUpload/PROTOCOL.md#7-storing-the-upload-as-a-file)). Its
  records `[u32 address][u32 length][data]` are exactly what RequestDownload / TransferData need.
- **The trigger** is a FLASH message with the file name and the sequence's parameters
  ([PROTOCOL.md](PROTOCOL.md)). The parameters usually come from a JSON profile per ECU type (§6).
- **The UDS client** is a library, [`_LIB/UdsClient`](../../_LIB/UdsClient)
  ([../UdsClient/README.md](../UdsClient/README.md)). Zephyr has ISO-TP but no UDS.

## 1. Files

| File | Role |
|---|---|
| [`_ASW/_UDS/UdsCmd.c/.h`](../../_ASW/_UDS/UdsCmd.c) | The BLE front-end: decodes appTypes 0x50–0x5F on the SETU engine thread, hands them to UdsJob, sends RESULT / DIAG_RSP / STATUS ([PROTOCOL.md](PROTOCOL.md)) |
| [`_ASW/_UDS/UdsJob.c/.h`](../../_ASW/_UDS/UdsJob.c) | The job engine: one thread that applies a target, sends a diagnostic request, unlocks, or runs a flash job; BLE-independent API (`gu8_UdsJob_*`) |
| [`_ASW/_UDS/UdsKey.c/.h`](../../_ASW/_UDS/UdsKey.c) | Seed → key algorithms by number; the OEM hook |
| [`_ASW/_UDS/CMakeLists.txt`](../../_ASW/_UDS/CMakeLists.txt) | Built with `CONFIG_UDS`; adds `oem/*.c` and `UDS_KEY_OEM` when that folder exists |
| [`_LIB/UdsClient`](../../_LIB/UdsClient) | UDS client and its ISO-TP transport |

## 2. The job engine

**One thread, one job.** `UdsJob` owns a thread (3 KiB, priority 7: below CanIf's 6, above the
File System Manager's 10) and a queue of two. A request is accepted only while nothing runs (else
BUSY). Callbacks deliver the result on that thread. The `gu8_UdsJob_*` functions only check and
queue, so they are safe from the SETU engine thread. A future GUI or touchscreen front-end calls
the same API.

| Function | Job |
|---|---|
| `gu8_UdsJob_SetTarget(target, done, user)` | `gi_CanIf_Configure()` (bitrate, CAN FD), then `gi_UdsClient_SetTarget()` (IDs, frame length, timing). The ISO-TP transport is created on the first target, on `gstpt_CanIf_GetDevice()` |
| `gu8_UdsJob_Diag(req, len, functional, done, user)` | One request; the result carries the ECU's response |
| `gu8_UdsJob_Unlock(level, algo, done, user)` | SecurityAccess with `UdsKey` |
| `gu8_UdsJob_Flash(name, len, params, status, user)` | A flash job (§3); progress through `status` |
| `gu8_UdsJob_Abort()`, `gv_UdsJob_GetStatus()` | Stop at the next request; the progress |
| `gb_UdsJob_FlashRunning()` | True from a flash job's acceptance to its end |

Results are `UdsResult_E`, the status codes of [PROTOCOL.md §2](PROTOCOL.md#2-status-codes).

**Keep-alive.** Between jobs the thread waits for the next request no longer than the client's
keep-alive allows, and sends TesterPresent (`3E 80`) when a non-default session would otherwise
time out (S3). There is no timer: Zephyr's ISO-TP runs on the system work queue, and a blocking
send from there would wait for itself.

**The bus during a flash job.**
1. `gi_CanIf_Lock()`: nobody else can reconfigure the bus.
2. The traffic log is turned off (it costs an SPI read and a log line per frame), and back on
   afterwards.
3. A CanIf state listener stops the job on bus-off: the request in progress fails, and the
   result is BUS_OFF.
4. The bus is unlocked at the end, whatever the outcome.

**The file.** The job opens the file twice, so a bad file never reaches the ECU:
1. It reads the whole file and checks its records: no empty or cut record, at most 255. It
   counts the bytes and computes the CRC-32 of the data.
2. It reads the file again, block by block, while sending.

Reads go through the File System Manager (242 bytes per call) into the TransferData buffer. From
acceptance to the end, `gb_UdsJob_FlashRunning()` makes the file commands and a hex upload's
BEGIN answer BUSY. A flash is refused while a hex upload is being stored, and ends BUSY if a
file is open through the file commands.

**After a failure** the job stops keeping the session alive (`gv_UdsClient_EndSession()`): the
ECU falls back to its default session once S3 runs out, instead of being held in a
half-programmed programming session. The job does not try to undo anything else. Reflash.

## 3. The programming sequence

One generic ISO 14229 sequence; each optional step is a flag of the parameters
([PROTOCOL.md §1](PROTOCOL.md#flash--status--abort)):

| # | Step | Request | Flag |
|---|---|---|---|
| 1 | EXT_SESSION | `10 03` | `0x0001` |
| 2 | DTC_OFF | `85 02` | `0x0002` |
| 3 | COMM_OFF | `28 <control> <type>` | `0x0004` |
| 4 | PROG_SESSION | `10 02` | always |
| 5 | SECURITY | `27 <level>`, `27 <level+1> <key>` | `0x0008` |
| 6 | FINGERPRINT | `2E <DID> <record>` | `0x0010` |
| 7 | ERASE (once) | `31 01 <erase RID>` | `0x0020` without `0x0040` |
| per record | ERASE | `31 01 <erase RID> <ALFID> <address> <size>` | `0x0020` + `0x0040` |
| per record | DOWNLOAD | `34 <DFI> <ALFID> <address> <size>` | always |
| per record | TRANSFER | `36 <counter> <data>` … | always |
| per record | EXIT | `37` | always |
| 8 | CHECK | `31 01 <check RID> [CRC-32]` | `0x0080` (+ `0x0100` for the CRC) |
| 9 | RESET | `11 <type>` | `0x0200` |

Details:
- **Addresses and sizes** use the ALFID's byte counts, big-endian. A record whose address or size
  does not fit them is BAD_ARG.
- **Block size.** A TransferData request is at most the ECU's maxNumberOfBlockLength (from its
  RequestDownload answer, SID and counter included). It is also capped by the parameters'
  `max block` (if not 0) and by `CONFIG_UDS_FLASH_BLOCK_MAX` (2048). Data per block = that − 2.
- **Block sequence counter.** It starts at 1 after each RequestDownload and wraps from 0xFF to
  0x00.
- **The CRC-32** is IEEE (zlib's `crc32`) over the records' data in file order, headers
  excluded. It is sent big-endian.
- **Routine status records** (erase, check) are not interpreted. OEMs differ. An ECU that rejects
  a check answers with an NRC, and that fails the job.

The conversation for a two-record image with the simulator's parameters is the `uds_flash`
section of [`_TEST/vectors/wire.json`](../../_TEST/vectors/wire.json): every request and every
response, one NRC 0x78 included.

## 4. Seed → key

SecurityAccess keys are computed **on the device** (`UdsKey.c`), selected by number:

| Algorithm | Number | Notes |
|---|---|---|
| NONE | `0x00` | Every seed refused (NOT_SUPPORTED) |
| BENCH_XOR | `0x01` | `key[i] = rotl8(seed[i] ^ mask[i % 4] ^ level, 1)`, mask `5A A5 3C C3`; the key is as long as the seed. **Not secure**: for the bench and `_TOOLS/EcuSim` only. Vectors: `uds_key` in `wire.json` |
| OEM | `0x80`–`0xFF` | Your algorithms, kept out of the repository (below) |

**OEM algorithms.** Create `_ASW/_UDS/oem/` (git-ignored) with a C file that defines

```c
int gi_UdsKey_Oem(uint8_t u8_algo, uint8_t u8_level, const uint8_t *u8pt_seed, size_t t_seedLen,
   uint8_t *u8pt_key, size_t t_keyMax, size_t *tpt_keyLen);
```

It returns 0 or `-ENOTSUP` for a number it does not know, like `gi_UdsKey_Compute()`. The module's
CMake file then builds every `oem/*.c` and defines `UDS_KEY_OEM`, and `gi_UdsKey_Compute()` passes
`0x80`–`0xFF` to the hook. Without the folder, those numbers are NOT_SUPPORTED. The host learns
that at once, when UNLOCK or FLASH is checked, before anything is sent.

## 5. Configuration

`_DI/prj.conf`, section "UDS"; options in `_DI/Kconfig`, menu "UDS":

| Option | Value | Meaning |
|---|---|---|
| `CONFIG_ISOTP` | y | Zephyr's ISO-TP (marked experimental) |
| `CONFIG_ISOTP_ENABLE_TX_PADDING` | y | Pad with 0xCC; TARGET must ask for padding |
| `CONFIG_ISOTP_RX_BUF_COUNT` | 17 | Receive pool for a whole 1 KiB response (17 × 63 bytes) |
| `CONFIG_ISOTP_ENABLE_CONTEXT_BUFFERS` | n | Sends are blocking from the job thread |
| `CONFIG_UDS` | y | Builds `_LIB/UdsClient` and `_ASW/_UDS` (needs `CANIF`, `ISOTP`) |
| `CONFIG_UDS_CMD` | y | UDS over BLE (appTypes 0x50–0x5F). **n in production** (§8) |
| `CONFIG_UDS_P2_MS`, `CONFIG_UDS_P2STAR_MS` | 150, 5000 | Default P2 / P2* until the ECU gives its own |
| `CONFIG_UDS_TESTER_PRESENT_MS` | 2000 | Keep-alive period |
| `CONFIG_UDS_BUSY_RETRIES` | 3 | Repeats after NRC 0x21 |
| `CONFIG_UDS_RESPONSE_MAX` | 1024 | Longest diagnostic response |
| `CONFIG_UDS_FLASH_BLOCK_MAX` | 2048 | The TransferData buffer |
| `CONFIG_UDS_JOB_STACK_SIZE`, `_PRIORITY` | 3072, 7 | The job thread |

## 6. Profiles

`setu_client.py` and the GUI's ECU page read an ECU's target and flash parameters from a JSON profile
([`_TOOLS/EcuSim/profiles/sim.json`](../../_TOOLS/EcuSim/profiles/sim.json) is the simulator's).
Numbers may be written as `"0x7E0"`:

```json
{
  "can": { "bitrate": 500000, "fd": false, "data_bitrate": 2000000, "brs": false },
  "addressing": { "tx_id": "0x7E0", "rx_id": "0x7E8", "functional_id": "0x7DF",
                  "extended_ids": false, "dl": 8, "padding": true },
  "timing": { "p2_ms": 0, "p2star_ms": 0 },
  "flash": {
    "extended_session": true, "dtc_off": true,
    "comm_control": { "control": "0x03", "type": "0x01" },
    "security": { "level": 1, "algo": "BENCH_XOR" },
    "fingerprint": { "did": "0xF15A", "data": "20261012010203" },
    "erase": { "rid": "0xFF00", "per_record": true },
    "check": { "rid": "0xFF01", "crc": true },
    "reset": "0x01", "alfid": "0x44", "dfi": "0x00", "max_block": 0
  }
}
```

A step whose key is missing (or `null`) is left out. `algo` is a name (`BENCH_XOR`) or a number
(`"0x80"` for an OEM algorithm).

The ECU page edits every field and saves the form back in this format (**Save as…**,
`uds.save_profile()`): IDs and identifiers as hex strings, and only the sections of the steps that
run, so the values of a step that is off are not kept.

## 7. On the bench

The ECU simulator ([`_TOOLS/EcuSim`](../../_TOOLS/EcuSim/README.md)) plays the ECU on a PC with a
USB-CAN adapter.

1. Set the DK's VDD to 3.3 V, then wire the MCP2518FD Click
   ([../CAN/README.md §1](../CAN/README.md#1-hardware)). Put the adapter on the same bus, with
   120 Ω at both ends.
2. Start the simulator:
   `python _TOOLS/EcuSim/ecu_sim.py --interface pcan --bitrate 500000 --out flashed.bin`.
3. Store the image on the device: `setu_client.py hex app.hex --store APP1.BIN`.
4. Check the target answers: `setu_client.py uds target --profile _TOOLS/EcuSim/profiles/sim.json`,
   then `setu_client.py uds req 22F190` (the simulator's VIN).
5. Flash: `setu_client.py flash APP1.BIN --profile _TOOLS/EcuSim/profiles/sim.json`.
   - Progress runs to `DONE`.
   - `flashed.bin` equals the device's file: compare with
     `setu_client.py fs get /FW/APP1.BIN app1.bin`.
6. Try the failures:
   - Simulator options `--pending 3`, `--nrc-at 36:72`, `--drop-at-block 5`.
   - Ctrl+C during the transfer (ABORT).
   - Unplugging the bus (bus-off).

   Each must end cleanly, with the bus restored and the next job possible.

The same from the GUI ([`_TOOLS/BleHostGUI`](../../_TOOLS/BleHostGUI/README.md)): Hex Upload with
**Store as** `APP1.BIN`; on the ECU page **Load…** `sim.json`, **Apply target**; Diagnostics:
`22 F1 90`; Flash: **Refresh**, `APP1.BIN`, **Flash**. The step list and tiles follow the job's
STATUS. Disconnecting during the transfer leaves the job running; on reconnecting the page asks
STATUS_REQ and follows it to its end.

## 8. Security

UDS over BLE runs on the **unauthenticated host link**, like the file commands: whoever can
connect can send any UDS request and flash a connected ECU. The bench build has it on. Build
production firmware with `CONFIG_UDS_CMD=n` until the host is authenticated (a paired or
certificate-authenticated host is a later feature). The job engine stays available to on-device
front-ends.

OEM seed→key algorithms live in the git-ignored `oem/` folder, but they are compiled into the
firmware image. Anyone who can read the image can recover them.

## 9. Memory

On the SPI build, `_ASW/_UDS` takes about 6 KB of flash and 8 KB of RAM: the 2 KiB block buffer,
the 1 KiB response buffer, the thread and the client. `_LIB/UdsClient` adds 3 KB of flash, and
ISO-TP its receive pool. The image uses 85 % of the RAM, and 91 % of the 240 KiB on the sQSPI
build. To save RAM, shrink `CONFIG_UDS_FLASH_BLOCK_MAX` (blocks get smaller, the flash a little
slower) or `CONFIG_UDS_RESPONSE_MAX`.

## 10. Limitations

- **One ECU target at a time; one job at a time.** No parallel flashing.
- **Addressing.** Normal addressing only: 11- or 29-bit IDs, and normal-fixed through 29-bit
  IDs. No extended or mixed addressing.
- **Padding.** Fixed to 0xCC, set at build time.
- **The image** is downloaded as stored. No compression or encryption (`DFI` is passed through).
  No sorting or merging of records: one RequestDownload per record.
- **Not interpreted:** the routines' status records, and the ECU's own boot or flash timings
  beyond NRC 0x78.
- **UDS services not used:** 0x29 Authentication and 0x84 SecuredDataTransmission.
- **A failed job** is not rolled back (§2).
- **Progress reports** are limited to one every 250 ms during a transfer. The BLE link's
  connection interval sets how fast they reach the host.

## 11. Tests

| Test | Covers |
|---|---|
| `uds_key`, `uds_key_oem` | BENCH_XOR against the `uds_key` vectors, refusals, the OEM hook with and without `UDS_KEY_OEM` |
| `uds_job` | The job engine with the real client, keys and File System Manager (on `fs_sim.c`), a scripted ISO-TP transport and a C ECU; CanIf stubbed. See below |
| `uds_cmd`, `uds_cmd_disabled` | Every `uds_cmd` frame decoded into the right UdsJob call and built byte for byte, long responses in parts, refusals, the range unregistered without `CONFIG_UDS_CMD` |
| `fscmd_uds` | The file commands answer BUSY while a flash job runs |
| `test_uds_protocol.py` | The PC codecs against the same frames, the profile loader and writer (the simulator's profile is the vectors' target and parameters, and saves back the same), NRC names, `UdsSession` (also a job followed after a reconnect) and `setu_client.py uds` / `flash` end to end against a fake device that runs the sequence on the simulator |
| `test_feature_ecu.py` | The GUI's ECU page against the same fake device: the form and its errors, profiles loaded and saved, target, requests, unlock, the stored-file list, flash jobs (done, refused, NRC, abort, lost link, picked up on reconnect), the SETU service's appType route, and the real page on Tk |
| `test_ecu_sim.py` | The simulator replays `uds_flash`, its services and faults, and ISO-TP on python-can's virtual bus |

`uds_job` covers:
- the flash request by request against `uds_flash`;
- an NRC at every one of its 18 steps (each fails cleanly, with the bus restored and no session
  kept);
- a silent ECU, abort, bus-off;
- a 301-block transfer (counter wrap) with the data checked;
- the block cap, bad and busy files, refusals, targets, diagnostic requests, unlock, the
  keep-alive.

On hardware: the manual `hil-uds-tests` job in `ci.yml` (a DK with the click and a USB-CAN adapter
running the simulator) is a placeholder for §7.
