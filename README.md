# Project Hanuman

*Crosses the gap, carries the mountain, proves who sent him.*

Zephyr / nRF Connect SDK firmware for a BLE device on the **nRF54L15 DK**. It receives bulk data over GATT, stores uploads as files on the DK's external flash, can be provisioned with a device certificate, and can pair with another provisioned device through certificate-based OOB pairing. Once provisioned, it serves one trusted PC host, which authenticates with a host certificate and bonds with a derived passkey. A MikroE MCP2518FD Click gives it a CAN / CAN FD bus, on which the device itself flashes and diagnoses ECUs with UDS over ISO-TP, triggered over BLE. A PC GUI uploads to the device, browses its files, drives UDS diagnostics and flash jobs on the ECU, provisions the device and orchestrates the pairing; a command-line client does the same without the GUI.

Everything travels over **SETU** (Sliding-window, Error-checked Transfer Utility), the bulk-transfer protocol in [`_LIB/SETU`](_LIB/SETU), meant to be reused by other BLE projects. SETU was called BulkXfer before; only the name changed, and the GATT UUIDs and wire format are the same (SETU v2 = BulkXfer protocol version 2).

## Status

- **Application (`_ASW`)**: advertises as `ProjectHanuman`, only while a press of DK Button 3 has opened its host window, and exposes GAP, Device Information, the SETU service and the Pairing service. An appType router splits SETU between six users, behind a gate that lets only the trusted host through (below):
  - **Hex upload** (`0x10`–`0x1F`): receives an Intel HEX file one contiguous segment at a time, buffers each segment in RAM and logs it on the serial terminal. By default it logs one summary line with the segment's CRC-32; built with `CONFIG_DS_HEX_DUMP=y` (for debugging, much slower) it logs every byte as `0xADDRESS: xx xx …` lines. When the client frames the upload with BEGIN (a file name) and COMMIT, the device also stores it as one file on the external flash, a record `[address][length][data]` per segment, for a later ECU update (FOTA); COMMIT reports the file's size and CRC-32.
  - **File commands** (`0x40`–`0x4F`): the FileSystemPoC's UART test harness over BLE: mkdir, cd, open for reading or writing, write, read, list, delete, close and abort on the external flash's file system, each answered with a result.
  - **Device provisioning** (`0x20`–`0x2F`): phase 1 of certificate-based authentication and pairing (Silicon Labs AN1396/AN1268). The device keeps a persistent P-256 key and a CSR. The PC acts as the Certificate Authority: it fetches the CSR and returns a CA certificate and a device certificate. The device verifies both, stores both in PSA Internal Trusted Storage, deletes its CSR and logs both certificates as PEM. Stored certificates are re-verified at boot. Provisioning is one-time. A wipe (the DEPROVISION message, or holding DK Button 0 for 5 s) destroys the key, the CSR and the certificates, and the device makes a fresh key and CSR.
  - **Device pairing** (`0x30`–`0x3F`, between two devices): phase 2 (AN1396 §4.2). The PC tells two provisioned devices their roles and each other's address. The devices connect to each other and exchange and verify their device certificates against their CA. Each then signs fresh LE Secure Connections OOB data with its device key. Each verifies the other's signature, and they pair with the OOB method at security level 4, bonded. The central proves the link by writing a characteristic that only an encrypted, authenticated link may write, and the peripheral lights LED0. The PC follows both devices step by step. From then on the pair reconnects by itself, after a reset or a lost link, and encrypts with the stored keys; while that reconnected link is up, both devices blink LED0. A device keeps one link to the PC and one to its peer.
  - **UDS** (`0x50`–`0x5F`): the host sets the target ECU (CAN configuration and addressing), sends raw UDS requests, unlocks with an on-device seed→key algorithm, and starts a flash job on a stored upload. The device runs the job itself: it checks the file, locks the bus and runs a parameterised ISO 14229 programming sequence (sessions, DTC and communication control, SecurityAccess, fingerprint, erase, RequestDownload / TransferData / RequestTransferExit per record, a CRC-32 check routine, reset), reporting its progress.
  - **Host authentication** (`0x60`–`0x6F`): the PC proves a host certificate of the device's CA, and the device its device certificate, in a signed ECDH handshake (HELLO, CHALLENGE, FINISH). Both derive a six-digit passkey from it, and the PC pairs with LE Secure Connections passkey entry using it: level 4, bonded. The device keeps that one host bond. On a provisioned device only that host reaches the other users and the pairing commands; an unprovisioned device accepts provisioning only. A short press of Button 3 opens the host window for 2 minutes (LED1 blinks), and a 3-second hold first forgets the bonded host.
- **File system (`_LIB/FileSysManager`)**: ported from the FileSystemPoC. A FAT volume on the first 4 MiB of the DK's MX25R6435F flash, mounted (and formatted if needed) at boot, with every operation run in order on one thread through a Zephyr SMF state machine. The flash is reached over SPI (default) or over sQSPI, the soft QSPI peripheral on the FLPR core (`FLASH_IF=sqspi`).
- **CAN / CAN FD (`_ASW/_CAN`)**: an MCP2518FD Click on SPI, driven by Zephyr's `microchip,mcp251xfd` driver. The `CanIf` module owns the controller. It starts as classic CAN at 500 kbit/s (CAN FD at 500 kbit/s / 2 Mbit/s is one Kconfig line away), and changes mode and bitrates at runtime. It lets other modules send frames and receive filtered frames, reports error states and bus-off to listeners, and logs received traffic on the serial terminal. UDS sits on top of it.
- **UDS client (`_LIB/UdsClient`)**: the tester side of UDS (ISO 14229) on Zephyr's ISO-TP, which Zephyr provides without UDS: requests matched to their responses, NRC 0x78 / P2*, NRC 0x21 retries, the ECU's session timing, TesterPresent, and the services ECU programming needs.
- **Deployment readiness**: not yet. The audit in [_DOC/Audit/FINDINGS.md](_DOC/Audit/FINDINGS.md) lists what must change first: chiefly the open debug port and the missing bootloader, kept on purpose while the BLE stacks are built, to be closed with the application. The unauthenticated host link it found is closed by host authentication (still to be proven on hardware); the watchdog, the reset on a fatal error, the stack margins and the dead storage-init code are fixed, and so is a reset loop with the CAN click fitted (the DK library cut off the controller's interrupt callback; the CAN driver now starts after it). The sQSPI build uses 98 % of its RAM.
- **SETU library (`_LIB/SETU`)**: the transfer protocol itself. The firmware runs both roles: the Server receives uploads, certificates and a peer's pairing data, and the Client sends the CSR to the PC and its own pairing data to the peer. The roles move between live links (`gi_SETUS_Rebind()`, `gi_SETUC_Detach()`).
- **PC GUI** ([`_TOOLS/BleHostGUI`](_TOOLS/BleHostGUI/README.md)): a navigation rail with Device (scan, connect several boards, choose the active device the pages act on, read CAPS), Host Access (the PC's host credential, issued from the CA; authenticate and pair with Windows passkey entry), Hex upload (optionally stored as a file), Files (the UART harness's command line and buttons, a listing, read data, download), ECU (the target and flash sequence from an editable JSON profile, raw UDS requests with NRCs named, SecurityAccess, a flash job on a stored upload followed step by step), Provisioning (the PC is the CA), Pairing (choose two connected devices and their roles, follow both live), Log and a switchable BLE traffic monitor. It hosts the PC's own SETU service so that the device can send its CSR and its CHALLENGE. The command-line client `setu_client.py` does the same host authentication, uploads, file commands, UDS, provisioning and pairing without the GUI.
- **ECU simulator** ([`_TOOLS/EcuSim`](_TOOLS/EcuSim/README.md)): a UDS server over ISO-TP on a PC with a USB-CAN adapter (python-can, can-isotp), the ECU of the bench: it answers the programming sequence, writes the image it received, and injects faults.
- **Memory report** ([`_TOOLS/MemReport`](_TOOLS/MemReport/README.md)): every firmware build prints FLASH and RAM use per module of `_ASW` and `_LIB` below the linker's summary, read from the map file.

## SETU in brief

- The **sender is the GATT client**: it writes frames to the receiver's **DATA** characteristic with Write Without Response.
- The **receiver is the GATT server**: it hosts DATA and **CTRL**, and replies on CTRL with ACK / NACK / END notifications.
- Transfers use windowed cumulative ACKs, Go-Back-N retransmission and a CRC-32 over each object.
- Data streams through source and sink callbacks, so an object never has to fit in RAM.
- Frames are up to 244 bytes (ATT_MTU 247 with Data Length Extension).

The wire protocol is specified in [_DOC/SETU/PROTOCOL.md](_DOC/SETU/PROTOCOL.md), and the design rationale in [_DOC/SETU/README.md](_DOC/SETU/README.md).

## Hex upload in brief

- Service `B1C00000-16A1-4812-AF35-F3F29A92F6CA`, with DATA (`…0001`, Write Without Response), CTRL (`…0002`, Notify) and CAPS (`…0003`, Read).
- Each contiguous segment is one SETU transfer with appType `0x10`, carrying `[u32 little-endian start address][data]`. Segments are at most 64 KiB.
- The server answers with a RESULT message when the transfer ends, and with a STORED message once the segment has been logged (and written to the file). The client waits for STORED before it sends the next segment.
- To store the upload as a file: BEGIN `0x12` with the file name before the segments, COMMIT `0x13` after them; FILE `0x14` answers both. The file is `/FLASH_DISK:/FW/<name>`, written to a temporary file and renamed at COMMIT, so a lost upload never leaves a half-written file under its name.

The full contract for client implementations, including the device's whole appType registry, is in [_DOC/HexUpload/PROTOCOL.md](_DOC/HexUpload/PROTOCOL.md).

## File system in brief

- FAT volume `FLASH_DISK` on the first 4 MiB of the external flash (`zephyr,flash-disk` on a `fixed-partitions` node), mounted at `/FLASH_DISK:` by `_LIB/FileSysManager`'s own thread; users submit commands and get exactly one result each.
- File commands over BLE: CMD `0x40` `[seq][op][arg]` → REPLY `0x41` `[seq][op][status][data]`, with ENTRY `0x42` `[seq][type][size][path]` per listed entry. One command at a time; the hex upload and the file commands share the one open file and refuse each other with BUSY.
- Status codes are portable (`FsmgrStatus_E`: OK, NOT_FOUND, BAD_ARG, BAD_STATE, BUSY, NOT_MOUNTED, IO, …), not errno.

The library's design and its changes from the sample are in [_DOC/FileSysManager/README.md](_DOC/FileSysManager/README.md), its API in [_DOC/FileSysManager/API_REFERENCE.md](_DOC/FileSysManager/API_REFERENCE.md), and the file commands' contract in [_DOC/FileSysManager/PROTOCOL.md](_DOC/FileSysManager/PROTOCOL.md).

## Provisioning in brief

- The PC (the **provisioner**) hosts a SETU service with the same UUIDs as the device's. The CSR travels from device to PC, so the device attaches its SETU Client to the PC's service over the same connection.
- Short messages: GET_STATUS `0x20` → STATUS `0x21` (state, flags, CSR length, SHA-256 of the public key); CSR_REQ `0x22`; RESULT `0x26` (`[refAppType][status]`); DEPROVISION `0x27`.
- Transfers: CSR `0x23` (device → PC, DER PKCS#10), then CA_CERT `0x24` and DEV_CERT `0x25` (PC → device, DER X.509, at most 1024 bytes each).
- Device states: NO_KEY → KEY_READY → CA_OK → PROVISIONED. The device rejects a certificate that does not parse, does not chain, carries another key or subject than its CSR, or falls outside the profile (P-256, ecdsa-with-SHA256, X.509 v3). The RESULT status says which check failed.

The contract is in [_DOC/Provisioning/PROTOCOL.md](_DOC/Provisioning/PROTOCOL.md). Design, the origin of the ported sample code, the trust model and the limitations are in [_DOC/Provisioning/README.md](_DOC/Provisioning/README.md).

## Pairing in brief

- A provisioned device advertises the **Pairing service** `B1C10000-…`: CONTROL (`…0001`, Write: START `[01][role][peer address]`, CANCEL, UNPAIR), STATUS (`…0002`, Read/Notify: state, error, detail, provisioning state, role, own and peer address) and SECURED (`…0003`, writable only over an LE Secure Connections link).
- The PC, the trusted host of both devices, connects to both and sends START to the peripheral, then to the central (CONTROL refuses any other host with ATT `0x08`). The peripheral advertises directed to the central, and the central scans for it and connects.
- Over SETU on that link: each device sends its certificate (`0x30`) and verifies the peer's against its CA. Each then sends `[r][c][signature]` (`0x31`), where `r` and `c` are fresh OOB data and the signature is ECDSA P-256 over `r ‖ c ‖ sender address ‖ receiver address` with the device key. Only the pairing appTypes are reachable from the peer.
- SMP pairs with OOB data from both devices: level 4, bonded. The central writes SECURED, and the peripheral lights LED0. Each saves its role and peer next to the bond.
- A bonded pair reconnects by itself whenever its link is down: the peripheral advertises directed to its central (also with a PC connected), the central scans for it, connects and encrypts with the stored keys. At level 4 both blink LED0 until the link drops; a link that does not reach level 4 within 10 s is dropped and retried. UNPAIR, a new START or a wipe stops it. STATUS states: IDLE, ARMED, CONNECTED, CERT_EXCHANGE, CERT_VERIFIED, OOB_EXCHANGE, PAIRING, PAIRED, FAILED (with an error such as PEER_CERT, OOB_SIG, SMP, TIMEOUT).

The contract is in [_DOC/Pairing/PROTOCOL.md](_DOC/Pairing/PROTOCOL.md). Design, security notes and limitations are in [_DOC/Pairing/README.md](_DOC/Pairing/README.md).

## Host authentication in brief

- **The host window.** A short press of DK **Button 3** makes the device advertise for 2 minutes (LED1 blinks). Holding it 3 s first forgets the bonded host. After the trusted host's link drops, the window reopens for 60 s by itself; after a failed attempt, for what was left of it.
- **Credential.** The PC's host credential is a P-256 key and a host certificate from the provisioning CA: CA:FALSE, digitalSignature, extendedKeyUsage **clientAuth**. It is issued on the GUI's Host Access page or with `setu_client.py hostcert`. Device certificates must not carry clientAuth, and the CA refuses CSRs that ask for it.
- **Handshake.**
  - HELLO `0x62` (PC → device): `[1][Nh][Qh][host cert]`.
  - CHALLENGE `0x63` (device → PC's SETU service): `[1][Nd][Qd][SigD][device cert]`.
  - FINISH `0x64`: `[SigH]`, answered by RESULT `0x65`.
  - Each side signs its role label and `T = SHA-256("PH-HOSTAUTH-1" ‖ Nh ‖ Nd ‖ Qh ‖ Qd ‖ H(host cert) ‖ H(device cert))`. Both derive `passkey = HKDF-SHA256(Z, Nh‖Nd, "…passkey"‖T)` mod 10⁶ from the ECDH secret Z.
- **Pairing.** The PC pairs with LE SC passkey entry, entering the passkey (Windows `ProvidePin`). The device is DisplayOnly on the host link and allows this one pairing. The bond, at level 4, makes the PC the device's one trusted host, and a later connection is trusted once Windows re-encrypts it with the stored keys.
- **The advert.** While the window is open the device advertises its state as manufacturer data, `FF FF 01 <flags>` (provisioned `0x01`, host bonded `0x02`). A PC that holds keys for a device without a host bond knows they are stale (the device was erased, wiped, or forgot its host) and removes them before connecting.
- **The gate.** Only the trusted host reaches hex upload, files, UDS, provisioning (DEPROVISION included) and Pairing CONTROL. Other links get REFUSED `0x66`, a rejected START, or ATT `0x08`. STATUS_REQ `0x60` → STATUS `0x61` (`[state][flags]`) is always open.

The contract is in [_DOC/HostAuth/PROTOCOL.md](_DOC/HostAuth/PROTOCOL.md). Design, security notes and limitations are in [_DOC/HostAuth/README.md](_DOC/HostAuth/README.md).

## CAN in brief

- MCP2518FD Click (MCP2518FD controller, ATA6563 transceiver, 40 MHz oscillator) on `spi21`: SCK P1.11, MOSI P1.14, MISO P1.09, CS P1.08, INT P1.12. The click takes over Button 1, Button 2 and LED3; Button 0 (wipe), Button 3 (host window), LED0 (pairing) and LED1 (host window) keep their roles. **The DK's VDD must be set to 3.3 V** (Board Configurator) before wiring.
- `CanIf` (`_ASW/_CAN`): `gi_CanIf_Send()` and `gi_CanIf_AddRxFilter()` (callbacks on its own thread), `gi_CanIf_Configure()` (classic/FD, listen-only, bitrates; rolls back on failure), a bus lock for a flash session, state listeners, a rate-limited traffic log and `gi_CanIf_GetStatus()`.
- Boot configuration in Kconfig (`CONFIG_CANIF_*`). A loopback self-test and periodic test frames exist for the bench; both are off, because both transmit on the bus.

Wiring, configuration, the API contract, limitations and how UDS flashing and diagnostics sit on top are in [_DOC/CAN/README.md](_DOC/CAN/README.md).

## UDS in brief

- The ECU image is an ordinary hex upload stored as a file (`hex --store APP1.BIN`). Its records `[address][length][data]` become RequestDownload / TransferData blocks.
- BLE messages `0x50`–`0x58`: TARGET, DIAG_REQ / DIAG_RSP (responses in 236-byte parts), UNLOCK, FLASH (file name + 34 bytes of sequence parameters) answered by RESULT, then STATUS until DONE / FAILED / ABORTED, ABORT, STATUS_REQ.
- One job at a time on the device's UDS thread. A flash job reads its file twice (check, then send), locks the CAN bus, turns the traffic log off, stops on bus-off or ABORT, and leaves no session alive after a failure. File commands and hex uploads answer BUSY meanwhile.
- Seed→key on the device: BENCH_XOR for the bench, OEM algorithms from a git-ignored `_ASW/_UDS/oem/` folder.
- The GUI's ECU page and `setu_client.py` read the target and sequence of an ECU from a JSON profile (`_TOOLS/EcuSim/profiles/sim.json`); the page also edits and saves them. A flash job goes on without the PC; the page follows it again when it reconnects (within the 60 s grace window, no button needed). Like the file commands, UDS over BLE is for the trusted host only.

The contract is in [_DOC/UDS/PROTOCOL.md](_DOC/UDS/PROTOCOL.md); the sequence, the parameters, seed→key, profiles, the bench setup and the limitations are in [_DOC/UDS/README.md](_DOC/UDS/README.md); the client library in [_DOC/UdsClient/README.md](_DOC/UdsClient/README.md).

## Repository layout

| Path | Contents |
|---|---|
| [`_ASW/`](_ASW) | Application: `main.c` plus modules for BLE init, the host and peer links and advertising (`_BLE`), the Device Information service (`_GAP`), the SETU GATT service and appType router (`_SETU_SVC`), the RAM segment store, its serial log and the upload file (`_DATA_STORE`), the file commands over BLE (`_FS_CMD`), the device key and CSR (`_CSR`), certificate storage and X.509 verification (`_DEVICE_CERT`), the provisioning protocol and wipe button (`_PROV`), certificate-based pairing and the Pairing service (`_PAIR`), host authentication, its gate and the window button (`_HOST_AUTH`), the CAN / CAN FD interface (`_CAN`), UDS diagnostics and flash jobs with their BLE messages (`_UDS`), the watchdog and boot reset cause (`_WDT`), logging and helpers |
| [`_DI/`](_DI) | Build configuration: `prj.conf` (including the FAT file system, PSA crypto on CRACEN with ECDH and HKDF, secure storage, Mbed TLS X.509, the DK library, the central role, SMP, bonds and the app passkey, the host window, CAN FD, ISO-TP and UDS, the watchdog and reset on fatal errors), application Kconfig options (`Kconfig`), the board devicetree overlay (console UART at 921600 baud, the hardware watchdog `wdt31`, the MCP2518FD Click on `spi21`), and per flash interface a Kconfig fragment (`conf/flash_<if>.conf`) and an overlay (`boards/<board>_flash_<if>.overlay`) |
| [`_LIB/GATT_CB/`](_LIB/GATT_CB) | Generic GATT read/write callbacks driven by per-characteristic descriptors |
| [`_LIB/SETU/`](_LIB/SETU) | SETU, the bulk-transfer library (Server and Client roles) |
| [`_LIB/FileSysManager/`](_LIB/FileSysManager) | FAT file system on the external flash: mount, one thread, a state machine, results per command |
| [`_LIB/UdsClient/`](_LIB/UdsClient) | UDS client (ISO 14229, tester side) and its transport on Zephyr's ISO-TP |
| [`_TOOLS/BleHostGUI/`](_TOOLS/BleHostGUI) | PC GUI (Tkinter + `bleak`, flat light/dark theme): Device, Host Access, Hex upload, Files, ECU, Provisioning, Pairing, Log and Traffic pages; the PC's GATT server, CA and host credential; Windows passkey pairing; the pairing orchestrator; the command-line client |
| [`_TOOLS/EcuSim/`](_TOOLS/EcuSim) | UDS ECU simulator for the bench (python-can, can-isotp) and the ECU profiles |
| [`_TOOLS/MemReport/`](_TOOLS/MemReport) | Build-time script that splits the linker's FLASH/RAM figures by module of `_ASW` and `_LIB` |
| [`_TEST/`](_TEST) | Host tests of the libraries, the application modules and the PC tools, with a merged test report; libFuzzer targets (`fuzz/`) and the static analysis gate |
| [`.github/workflows/`](.github/workflows) | CI: host tests, Python tests, static analysis, fuzzing, firmware build and the test report on every push; manual hardware-in-the-loop placeholders (one DK; two DKs for pairing) |
| [`_DOC/`](_DOC) | Coding guidelines, library and protocol documentation, the pre-deployment audit findings (`Audit/`), the CBAP application notes and reference notes |
| [`_LOG/`](_LOG) | Sample logs of one upload (GUI traffic monitor and the board's UART), made with `AA00000100.hex` at the root |
| [`Supporting Scripts/`](Supporting%20Scripts) | Silicon Labs reference scripts for certificate provisioning (third party, not built) |
| `Sample Code/`, `Sample Code Device Cert Verification/`, `Sample Code FS/` | Reference projects that `_CSR`, `_DEVICE_CERT`, the `_PAIR` flow and `_LIB/FileSysManager` were ported from (not built) |

## Building

- **SDK:** nRF Connect SDK v3.4.1 (Zephyr 4.4.2)
- **Board:** `nrf54l15dk/nrf54l15/cpuapp`

Build with the nRF Connect extension for VS Code (sysbuild), or from an NCS shell:

```sh
west build -b nrf54l15dk/nrf54l15/cpuapp --sysbuild -d build .                      # external flash over SPI
west build -b nrf54l15dk/nrf54l15/cpuapp --sysbuild -d build . -- -DFLASH_IF=sqspi  # over sQSPI (FLPR soft peripheral)
```

`FLASH_IF` (root `CMakeLists.txt`) picks the external flash interface: it adds `_DI/conf/flash_<if>.conf` and `_DI/boards/<board>_flash_<if>.overlay`.

The build configurations are under version control in [CMakePresets.json](CMakePresets.json): `build` (SPI) and `build_sqspi` (sQSPI). In VS Code, choose **Add build configuration** and pick one under **CMake Preset**. A new configuration goes there too (the extension's **Save Configuration as Preset** writes it), with `FLASH_IF` as a cache variable and the flash files left out of its overlay and Kconfig fragment lists; listed there, the build stops with a message saying so.

Below the linker's FLASH/RAM summary, the build prints the same figures per module of `_ASW` and `_LIB` (with Zephyr, NCS and libc as one "Other" row) and writes them to `zephyr/mem_report.txt` in the image's build folder; see [MemReport](_TOOLS/MemReport/README.md).

The firmware runs without the CAN click: it logs that the controller is not ready and carries on. Before wiring the click, set the DK's VDD to 3.3 V in nRF Connect Board Configurator (it ships at 1.8 V); the wiring is in [_DOC/CAN/README.md](_DOC/CAN/README.md#1-hardware).

After changing the layout or configuration, do a pristine build (`-p always`). A chip erase also erases the device's key, so the device makes a new key and CSR and has to be provisioned again; its address stays, and it advertises no host bond, so a PC that was its host removes its old pairing keys before connecting.

## Using it from a PC

Install the requirements (`pip install -r _TOOLS/BleHostGUI/requirements.txt`: bleak, cryptography, Pillow) and run the GUI with `python _TOOLS/BleHostGUI/ble_host_gui.py`. Provisioning and host authentication need Windows 10/11 and an adapter that supports the peripheral role, because the PC hosts its own GATT service; host authentication also pairs through WinRT.

To reach a device, press its **Button 3** (LED1 blinks) and connect. An unprovisioned device takes provisioning only: provision it (Provisioning page), then authenticate the PC on the **Host Access** page. The PC needs a host credential, issued there from the CA folder (or `setu_client.py hostcert`). "Authenticate & pair" runs the handshake and Windows pairs without a prompt. From then on every page works on that device, and later connections are trusted at once. To move a device to another PC, hold its Button 3 for 3 s. A device that has forgotten this PC (Button 3 held, a wipe, a chip erase) advertises that it has no host bond, and the GUI and `setu_client.py` remove Windows' old keys for it before connecting (Windows would encrypt with them and drop every link, 0x13); after its own DEPROVISION the PC removes them once the link ends. Several devices can each trust the same PC. The GUI connects to several at once on its Device page; the pages act on the one chosen as the active device (working on several at once is planned).

The command-line client [`_TOOLS/BleHostGUI/setu_client.py`](_TOOLS/BleHostGUI/setu_client.py) does the same (`--help` lists all options):

```sh
python _TOOLS/BleHostGUI/setu_client.py hostcert "Service laptop" --ca <CA folder>          # the PC's host credential
python _TOOLS/BleHostGUI/setu_client.py auth --name "ProjectHanuman"                       # authenticate and pair; authstatus
python _TOOLS/BleHostGUI/setu_client.py hex app.hex --name "ProjectHanuman"
python _TOOLS/BleHostGUI/setu_client.py hex app.hex --store APP1.BIN --name "ProjectHanuman"   # also store it as a file
python _TOOLS/BleHostGUI/setu_client.py fs ls --name "ProjectHanuman"                           # mkdir, cd, openr, openw, write, read, ...
python _TOOLS/BleHostGUI/setu_client.py fs get /FW/APP1.BIN app1.bin --name "ProjectHanuman"    # put LOCAL REMOTE
python _TOOLS/BleHostGUI/setu_client.py fs shell --name "ProjectHanuman"                        # the UART harness's commands
python _TOOLS/BleHostGUI/setu_client.py provision --name "ProjectHanuman"              # --ca <folder>, --out <pem>
python _TOOLS/BleHostGUI/setu_client.py provision --negative --name "ProjectHanuman"   # certificates the device must reject first
python _TOOLS/BleHostGUI/setu_client.py deprovision --name "ProjectHanuman"
python _TOOLS/BleHostGUI/setu_client.py pair --central <address> --peripheral <address>
python _TOOLS/BleHostGUI/setu_client.py pairstatus --address <address>                     # unpair --address <address>
python _TOOLS/BleHostGUI/setu_client.py uds target --profile _TOOLS/EcuSim/profiles/sim.json --name "ProjectHanuman"
python _TOOLS/BleHostGUI/setu_client.py uds req 22F190 --name "ProjectHanuman"            # unlock, status, abort
python _TOOLS/BleHostGUI/setu_client.py flash APP1.BIN --profile _TOOLS/EcuSim/profiles/sim.json --name "ProjectHanuman"
```

To flash an ECU from the GUI: store the image with Hex Upload (**Store as** `APP1.BIN`), then on the ECU page **Load…** a profile (or fill in the form), **Apply target**, and on its Flash view **Refresh**, choose the file and **Flash**. The Diagnostics view sends raw requests (`22 F1 90`) and unlocks.

Pairing needs two DKs provisioned by the same CA (a device certified by another CA is refused), with this PC as the trusted host of both. In the GUI, connect both on the Device page, then choose the central and the peripheral on the Pairing page; the PC's links to both stay up afterwards. Two devices already paired with each other are not paired again until one of them is unpaired. Once paired, the PC may disconnect: the two boards reconnect to each other after every reset or lost link, and blink LED0 while connected.

The CA folder holds the CA's private key. A folder named `_CA/` at the repository root is ignored by git; keep the CA there or outside the repository, and never commit it.

The board's serial terminal runs at **921600 baud with RTS/CTS flow control** (set in the board overlay). It shows the mount of the file system, the received segments and each stored file (`FILE … size= crc=`), after provisioning both certificates as PEM, each step of a pairing, the CAN controller's configuration and error states, and received CAN frames (at most 20 a second; `CONFIG_CANIF_LOG_RX`). To see every byte of an upload, set `CONFIG_DS_HEX_DUMP=y` in `_DI/prj.conf`; each 64 KiB segment then holds the upload for several seconds while it prints.

## Testing

Host tests cover `_LIB/SETU`, `_LIB/GATT_CB`, `_LIB/FileSysManager` (on an in-memory volume), `_LIB/UdsClient` (against a scripted transport, and its ISO-TP transport against fakes of Zephyr's ISO-TP), every application module that is not only calls into the BT stack (data store with its upload files, file commands, router, CSR, certificate storage, provisioning, wipe button, pairing, host authentication with its gate and window button, the CAN interface against a scripted controller, the UDS seed→key, job engine and BLE messages, the watchdog, helpers), and the PC client, file commands, UDS commands, CA, pairing orchestrator, decoders, GUI pages, memory report and ECU simulator (also on python-can's virtual bus) in `_TOOLS`. Certificate verification runs on the real Mbed TLS, against certificates that the PC's CA issues on each build, including the cases the device must reject; the signed OOB data and the host handshake's cryptography run on the real TF-PSA-Crypto against values made by Python; the PC side runs the handshake against a simulated device, and Windows pairing against a fake WinRT. End-to-end tests run a hex upload, a full provisioning and a pairing exchange through the real SETU engine over a simulated link. A flash job runs request by request against a golden UDS conversation that the ECU simulator's tests replay from the other side, and python-udsoncan, an ISO 14229 implementation from outside the repo, checks the same conversation. Expected wire bytes come from a real upload captured in `_LOG/` and are shared by the C and Python tests. libFuzzer targets in `_TEST/fuzz` feed the code that parses outside bytes (the SETU receive path, file and UDS commands, ECU answers, stored flash files, an untrusted host's handshake) under ASan, and a static analysis gate runs cppcheck over the firmware sources and ruff and bandit over the PC tools.

```powershell
powershell -ExecutionPolicy Bypass -File _TEST\run_tests.ps1   # add -Coverage, -Static, -Fuzz
```

This needs a host `gcc` and Python 3.8+. The report is written to `build_test/report/report.html`. On GitHub, [CI](.github/workflows/ci.yml) runs the same tests (plus ASan/UBSan, and the GUI tests under `xvfb-run`), runs the static analysis gate and each fuzz target for a minute, builds the firmware for both flash interfaces (with the per-module memory table in the job summary), and publishes the results on each push and pull request. Manual `hil-tests`, `hil-pair-tests` and `hil-uds-tests` jobs are placeholders for self-hosted runners with one DK, with two DKs, and with a DK, its CAN click and a USB-CAN adapter running the ECU simulator. Details are in [_TEST/README.md](_TEST/README.md). What the pre-deployment audit found, and what is still open, is in [_DOC/Audit/FINDINGS.md](_DOC/Audit/FINDINGS.md).

## Documentation

- [SETU design and integration](_DOC/SETU/README.md)
- [SETU protocol](_DOC/SETU/PROTOCOL.md)
- [SETU API reference](_DOC/SETU/API_REFERENCE.md)
- [GATT_CB design and integration](_DOC/GATT_CB/README.md)
- [GATT_CB API reference](_DOC/GATT_CB/API_REFERENCE.md)
- [Hex upload protocol](_DOC/HexUpload/PROTOCOL.md)
- [FileSysManager design and integration](_DOC/FileSysManager/README.md)
- [FileSysManager API reference](_DOC/FileSysManager/API_REFERENCE.md)
- [File commands protocol](_DOC/FileSysManager/PROTOCOL.md)
- [Device provisioning protocol](_DOC/Provisioning/PROTOCOL.md)
- [Device provisioning design](_DOC/Provisioning/README.md)
- [Device pairing protocol](_DOC/Pairing/PROTOCOL.md)
- [Device pairing design](_DOC/Pairing/README.md)
- [Host authentication protocol](_DOC/HostAuth/PROTOCOL.md)
- [Host authentication design](_DOC/HostAuth/README.md)
- [CAN / CAN FD: hardware, configuration and API](_DOC/CAN/README.md)
- [UDS over BLE protocol](_DOC/UDS/PROTOCOL.md)
- [UDS flashing and diagnostics: design, sequence, profiles, bench](_DOC/UDS/README.md)
- [UdsClient design and integration](_DOC/UdsClient/README.md)
- [UdsClient API reference](_DOC/UdsClient/API_REFERENCE.md)
- [CBAP application notes (AN1396, AN1268)](_DOC/CBAP/)
- [Bootloader User Guide (GBL file format)](<_DOC/GBL Format/>)
- [BLE Host GUI](_TOOLS/BleHostGUI/README.md)
- [Memory report per module](_TOOLS/MemReport/README.md)
- [ECU simulator](_TOOLS/EcuSim/README.md)
- [Tests and CI](_TEST/README.md)
- [Pre-deployment audit findings](_DOC/Audit/FINDINGS.md)
- [BATL coding guidelines](_DOC/BATL%20Coding%20Guidelines/)

## License

The repository is licensed under the GNU GPL v3; see [LICENSE](LICENSE). The `_LIB` libraries carry an MIT licence header (`SPDX-License-Identifier: MIT`). `Supporting Scripts/` and the Silicon Labs-derived `DER.c` keep their Zlib notices.
