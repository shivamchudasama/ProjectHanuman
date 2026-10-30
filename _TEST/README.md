# Tests

Host tests for the libraries in `_LIB`, the testable application modules in `_ASW`, and the PC tools in `_TOOLS`. They run on every push through [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), and locally with one command. Each run produces a report that lists every test case, every failure, and the **known bugs**.

## Running

```powershell
powershell -ExecutionPolicy Bypass -File _TEST\run_tests.ps1            # all tests
powershell -ExecutionPolicy Bypass -File _TEST\run_tests.ps1 -Coverage  # + C and Python coverage
powershell -ExecutionPolicy Bypass -File _TEST\run_tests.ps1 -Static    # + cppcheck, ruff, bandit
powershell -ExecutionPolicy Bypass -File _TEST\run_tests.ps1 -Fuzz      # + each fuzz target, -FuzzSeconds (30)
```

This needs a host `gcc` on PATH (MinGW-w64 or Strawberry Perl; gcc 4.4 and newer work) and Python 3.8+. CMake, CTest and Ninja are taken from PATH, or else from `C:\ncs\toolchains`. Python dependencies go into a venv in `build_test/venv`. The first configure downloads Unity and Mbed TLS 4.1.1 (both pinned by hash) and builds Mbed TLS once. `-Static` needs cppcheck (on PATH or in `C:\Program Files\Cppcheck`; ruff and bandit go into the venv); `-Fuzz` needs clang with libFuzzer (LLVM, on PATH or in `C:\Program Files\LLVM`) and builds into `build_fuzz/`. On Windows the fuzz targets run with ASan only (the MSVC runtime has no UBSan for them); CI runs them with ASan + UBSan.

A local pass is not the whole check. gcc 4.4 has no sanitizers and is 32-bit, so out-of-bounds reads and printf formats that are wrong only on 64-bit hosts (`size_t`, `ssize_t`) show up only in CI's `host-tests` job (GCC 13, ASan + UBSan, `-Werror`). When it fails there, the sanitizer report is in the job log and in the `report-c` artifact (`junit/<test>.xml`, as the failing test's output).

The output goes to `build_test/report/`:

| File | Content |
|---|---|
| `report.html` | Every suite and test case. Failures are expanded, with their messages |
| `summary.md` | The same as a Markdown table (also the GitHub job summary) |
| `junit/*.xml` | JUnit XML per suite, one `<testcase>` per Unity test / pytest item |
| `coverage/c/index.html`, `coverage/python/` | With `-Coverage` |

## What runs where

| Tier | Local | CI job | What it tests |
|---|---|---|---|
| C unit tests (CTest + [Unity](https://github.com/ThrowTheSwitch/Unity)) | yes | `host-tests`, with ASan + UBSan | `_LIB/SETU`, `_LIB/GATT_CB`, `_LIB/FileSysManager` (with and without the write buffer, on an in-memory volume), `_ASW/_DATA_STORE` (including uploads stored as files), `_ASW/_FS_CMD` (file commands, with and without `CONFIG_FS_CMD`), `_ASW/_SETU_SVC` (router and its gate), `_ASW/_PROV` (flow and wipe button), `_ASW/_PAIR` (pairing flow, CONTROL for the trusted host only, the bond record and the bonded reconnection with its LED, end to end, and the signed OOB data on the real TF-PSA-Crypto), `_ASW/_HOST_AUTH` (host authentication: the gate, the handshake and its RESULTs, the host link's SMP callbacks, trust, the record, the window, the button, and the handshake's cryptography on the real TF-PSA-Crypto against a handshake made by Python), `_ASW/_DEVICE_CERT` (storage, and X.509 verification on the real Mbed TLS), `_ASW/_CSR` (key and CSR life cycle with the firmware's storage Kconfig, DER encoder), `_ASW/_CAN` (the CAN interface against a scripted controller, as a CAN FD and a CAN 2.0 build), `_LIB/UdsClient` (against a scripted transport; its ISO-TP transport against fakes of Zephyr's ISO-TP), `_ASW/_UDS` (seed->key with and without OEM algorithms, the job engine with the real client and File System Manager against a C ECU and the golden UDS conversation, the BLE messages on the real router), `_ASW/_WDT` (the watchdog: reset cause, task watchdog and its channel, the feed; with and without the hardware watchdog node), `_ASW/_GENERIX`, header hygiene |
| Python tests (pytest) | yes | `python-tests`, under `xvfb-run` | `setu_client.py` (protocol and command line), `setu_receiver.py`, `blehost/protocols`, `blehost/pki`, `blehost/core/gatt_server.py` (fake backend, only the active device's writes and notifications with several boards connected, and the WinRT backend against fake `winrt` modules), `blehost/core/decoders.py`, `blehost/core/ble_link.py` (a primary link and a board's labelled link with its state callback, a scanned device handed to another link, fake `bleak`), `blehost/core/devices.py` (several boards: the active device, a switch refused while busy, LINK_STATE for the active device only, a failed connect, the active device's link loss, the `ActiveService` proxy), `blehost/protocols/pairing.py` (codecs against `wire.json`, the orchestrator against simulated devices: success, refusals (including two devices paired with each other already), failures, time limit, cancellation, stale statuses, lost notifications, and on links lent by the Device page, which it never connects or disconnects), `blehost/protocols/filesystem.py` (the file commands' codecs against `wire.json`, the session, the UART harness's line parser, the `fs` command line and shell, against a scripted device), `blehost/protocols/host_auth.py` (codecs and cryptography against `wire.json`, the session against a simulated device doing the device's half for real: success, refusals, a device that cannot prove itself, another fleet, a wrong passkey), `blehost/pki/host.py` and `issue_host()` (the host profile, load errors, a device CSR refused the host role), `blehost/core/winrt_pairing.py` and `BleLink.pair_with_pin()` (ProvidePin against fake `winrt` enumeration and bluetooth modules, and the keys of an address without a link), `blehost/ui/connection_panel.py` (the Device page: several boards listed with the active one, Make active refused while a page is busy, Disconnect of the selected board, Connect only for a board not connected; a board advertising no host bond has this PC's old keys removed before connecting, one with a bond keeps them; the offer to forget stale keys when a board's link drops at once, for that board, and never for a board it did not reach), the advert codec and `forget_stale_keys()` in `blehost/protocols/host_auth.py` against `wire.json` `host_auth.advert`, `BleLink` forgetting a board's keys once the link ends after a DEPROVISION, and `setu_client.py`'s `find_device` and `deprovision` doing the same, `blehost/features/provisioning.py`, `blehost/features/host_access.py`, `blehost/features/pairing.py` and `blehost/features/file_system.py` (each page's logic, and building the real Tk page), the Hex Upload page's Store as (BEGIN / COMMIT, size and CRC check), `blehost/ui` (the flat light/dark theme and its drawn check box and switch, one-pass switching, the display widgets and that they do not redraw unchanged state, the More menu, the hex upload's coalesced progress and segment count, the status mappings the pages colour by, the main window: pages built on first show, one mapped at a time, the header with several boards connected (the active device, `+1 more`, a switch, its link loss), the status line, rail badges, traffic capture, and the window without Pillow or an icon font), `blehost/ui/icons.py` (the Pillow-drawn shapes and indicators, icon glyphs with and without a badge, every glyph whole and centred at the GUI's sizes, the window icon, and their fallbacks without Pillow or an icon font), `_TOOLS/MemReport/mem_report.py` (map parsing on a synthetic map with each shape of `zephyr.map`, attribution to modules, load addresses, merged-string pools, gaps, name clashes, the table and the command line), `blehost/protocols/uds.py` and `setu_client.py uds` / `flash` (codecs against `wire.json`, the profiles, the session and command line against a fake device running the sequence on the simulator), `_TOOLS/EcuSim/ecu_sim.py` (the golden UDS conversation replayed, every service and fault, ISO-TP on python-can's virtual bus, classic and CAN FD) |
| Static analysis (`tools/run_static.py`) | `-Static` | `static-analysis` | cppcheck (warning, performance, portability) over `_ASW` and `_LIB` with the project's include paths; ruff (pyflakes rules) and bandit (medium and up) over `_TOOLS`. Any finding fails |
| Fuzzing (`fuzz/`, libFuzzer) | `-Fuzz` | `fuzz`, 60 s per target, ASan + UBSan | The code that parses bytes from outside: `fuzz_setu_rx` (frames a BLE peer writes, through the SETU Server, router, data store and File System Manager; the scripted peer checks every frame the device sends back), `fuzz_fscmd` (file commands), `fuzz_uds_cmd` (UDS messages and the ECU answers handed back), `fuzz_uds_client` (ECU answers off CAN, with the client's length and return contracts checked), `fuzz_uds_job` (a flash job on a cut or corrupted stored file with fuzzed parameters; afterwards the bus, log, file and engine must be back, and a DONE job must have sent exactly the file's records), `fuzz_host_auth` (an untrusted host's HELLO and short messages mixed with link, security, SMP, button and time events; only a bonded host at level 4 may ever pass the gate). A crash input is the `fuzz-crashes` artifact |
| Firmware build | no (VS Code) | `firmware-build`, in `ghcr.io/nrfconnect/sdk-nrf-toolchain`, once per flash interface (`FLASH_IF=spi`, `sqspi`) | The whole app for `nrf54l15dk/nrf54l15/cpuapp`. The ROM/RAM use, and the same per module (`mem_report.txt`), go in the job summary. The SPI image is the `firmware` artifact the hardware jobs flash |
| Hardware in the loop | no | `hil-tests` (placeholder, manual) | Flash an image built with `CONFIG_HOST_AUTH_BOOT_WINDOW=y` (nobody presses Button 3), provision, `hostcert` + `auth` (the PC becomes the trusted host), then upload `AA00000100.hex` over BLE, upload it again stored as a file (`hex --store`), `fs ls`, read it back with `fs get` before and after a reset and compare it with the hex file's records, provision the board with `--negative` (the device's certificate verification), check the certificate with `openssl verify`, check that a second provisioning is refused, `deprovision` and provision again |
| Pairing on hardware | no | `hil-pair-tests` (placeholder, manual, two DKs) | Flash and provision both DKs with one CA, `auth` on both, `pair` (both must end PAIRED), check that the bond survives a reset (the reconnection and the blinking LED0 are checked by eye), then provision one DK with another CA and check that pairing is refused (PEER_CERT) |

The BLE glue (`_BLE`, `_GAP`, `SETUSvc.c`, `PairSvc.c`, `main.c`) only calls the Zephyr stack, so it is covered by the firmware build rather than by unit tests. Everything else in `_ASW` has a host test:

- `DeviceCert_Verify.c` runs on the **real** Mbed TLS 4 / TF-PSA-Crypto (the major version NCS v3.4.1 ships), built for the host by `CMakeLists.txt`, against certificates made by the PC tool's own CA and negative set (see *Ideas* below). Nothing cryptographic is stubbed there.
- `CSR_Generator.c`, `DeviceCert.c` and `Prov.c` use the PSA stub (`shim/psa_stub`) and an in-memory ITS, so every PSA result can be scripted.
- `ProvButton.c` and `HostAuthButton.c` use the DK-library shim and simulated time.
- `HostAuth.c` records its BT stack calls (overlay SMP callbacks, security, bonds, settings) and stubs the router, SETU, verification and `HostAuthCrypto.c`; `HostAuthCrypto.c` runs on the real TF-PSA-Crypto.
- `CanIf.c` runs against a scripted controller behind Zephyr's CAN API (`shim/zephyr/drivers/can.h`, declarations only). The controller records mode, bitrates and start/stop, echoes frames in loopback mode, matches frames against the installed filters as the driver does, reports state changes and returns scripted errors. Its own thread runs through `gv_SimRunThread()`.
- `Pair.c` records every BT stack call it makes (advertising, scanning, connections, SMP, OOB, bonds, GATT) through declarations-only shim APIs; `PairOob.c` runs on the real TF-PSA-Crypto.
- `FileSysManager` runs on Zephyr's file system API as `shim/fs_sim.c` provides it: an in-memory volume that behaves as Zephyr's FAT backend where the manager can tell, with one-shot error injection on every call and a free-space limit. File and directory handles come from a fixed pool that each reset clears, so a test may end with a file still open without LeakSanitizer reporting it. `DataStore.c`, `FsCmd.c` and the hex upload end to end use the real manager on it, so their tests check the files themselves.

What only the board can show (CRACEN, the flash-backed ITS, the external flash over SPI or sQSPI, the radio, the MCP2518FD Click on a CAN bus, a real UDS flash) is left to `hil-tests` and `hil-uds-tests`.

## Layout

```
CMakeLists.txt         host test project; add_unit_test() registers one Unity executable
shim/                  single-threaded stand-in for the Zephyr kernel, logging and BT APIs
  zephyr_shim.h          simulated time, k_sem/k_fifo/k_msgq/k_timer/k_mutex, k_work_delayable,
                         atomics, base64, LOG_* / LOG_HEXDUMP_* capture, __ASSERT trap
  zephyr_sim.c           log capture, SIM_EXPECT_ASSERT(), gv_SimRunThread() (may nest: a block
                         hook can run another thread), the State Machine Framework (zephyr/smf.h,
                         flat machines, Zephyr's transition order)
  zephyr/fs/fs.h, fs_sim.c  Zephyr's file system API on an in-memory FAT-like volume (one mount
                         point, files and directories, mkfs/mount, error injection: gv_SimFs*);
                         ff.h: FatFs's FATFS type
                         and the BT host APIs pairing uses (addresses, advertising, scanning,
                         connections, SMP/OOB, bonds, GATT write): declarations only
  zephyr/task_wdt/task_wdt.h, zephyr/drivers/hwinfo.h  the task watchdog; device ID and reset
                         cause (Zephyr's RESET_* flags): declarations only
  zephyr/settings/, hw_unique_key.h, dk_buttons_and_leds.h (buttons and LEDs)
                         declarations only (tests define the functions); settings has
                         init, save, delete and the static handler macro
  zephyr/device.h, devicetree.h  struct device, device_is_ready() and device_init() (declared), DT_CHOSEN(),
                         DT_ALIAS() and DEVICE_DT_GET(): DEVICE_DT_GET(DT_CHOSEN(x)) is gst_simDev_x,
                         which the test defines; DT_NODE_HAS_STATUS_OKAY(x) is its SHIM_DT_OKAY_x
  zephyr/canbus/isotp.h  Zephyr's ISO-TP addresses, flags, error codes and contexts (recv_buf: a
                         message partly read); the API declared only
  zephyr/drivers/can.h   Zephyr's CAN types, flags, modes, states and DLC helpers; the controller
                         API declared only (CAN_MAX_DLEN follows CONFIG_CAN_FD_MODE)
  psa/                   PSA ITS types and declarations (Zephyr's size_t signatures)
  psa_stub/psa/          PSA Crypto types, constants and declarations only, with recording
                         key-attribute setters; on the include path of the tests that stub PSA
  tfpsa/                 host platform for the real TF-PSA-Crypto: tf_psa_crypto_host_config.h
                         (user config), tfpsa_host_platform.c (in-memory ITS, test RNG,
                         zeroize), include/psa/ (the ITS headers its key storage expects)
unit/SETU/         test_frame.c, test_engine.c (built 3x: both / server / client roles)
  sim_link.h             simulated BLE link + scripted peer (other side of both roles),
                         plus a second live link (sst_conn2) for moving roles between links
unit/GATT_CB/          test_gatt_cb.c, against _DOC/GATT_CB/API_REFERENCE.md
unit/FileSysManager/   test_fsmgr.c (built with and without the write buffer), against
                       _DOC/FileSysManager/API_REFERENCE.md, on fs_sim.c
unit/DataStore/        test_datastore.c (built with and without CONFIG_DS_HEX_DUMP; BEGIN /
                       COMMIT on the real File System Manager),
                       test_upload_e2e.c: real Server engine + router + DataStore + File System
                       Manager + simulated client, an upload stored as a file on the air
unit/FsCmd/            test_fscmd.c: the file commands against every golden frame, the refusals
                       and limits, on the real router and File System Manager (built with and
                       without CONFIG_FS_CMD)
unit/CanIf/            test_canif.c: the CAN interface against a scripted controller (init, self-test,
                       send, filters, the queue's reserve, states, traffic log, configure with
                       rollback, lock, test frames); built as canif (CAN FD, self-test and log on)
                       and canif_classic (CAN 2.0, both off)
unit/UdsClient/        test_uds_client.c: the UDS client against sim_uds_tp.h (a scripted transport:
                       responses released after a given request, with delays, on simulated time);
                       test_uds_tp_isotp.c: the ISO-TP transport against fakes of isotp_*
unit/Uds/              test_uds_key.c (built as uds_key and uds_key_oem); test_uds_job.c: the job
                       engine with the real client, keys and File System Manager on fs_sim.c, a C
                       ECU behind sim_uds_tp.h, CanIf stubbed, the uds_flash conversation request by
                       request; test_uds_cmd.c: the BLE messages on the real router (uds_cmd and
                       uds_cmd_disabled); fscmd_uds builds test_fscmd.c with CONFIG_UDS (BUSY while
                       flashing)
unit/SETUSvc/           test_router.c: appType router registration, dispatch, filter, the gate
                       (and the filter overriding it) and the shared Client (attach on behalf of a
                       module, results back to it)
unit/HostAuth/         test_host_auth.c: host authentication (gate, handshake, SMP callbacks, trust,
                       record, window, forget, wipe, timeout, the advert against wire.json),
                       everything around it stubbed;
                       test_host_auth_crypto.c: the handshake cryptography on the real TF-PSA-Crypto
                       against wire.json "host_auth"; test_host_auth_button.c: Button 3
unit/Prov/             test_prov.c: provisioning flow, storage order, boot restore and the wipe,
                       everything around it stubbed (storage/key calls recorded in order);
                       test_prov_e2e.c: real SETU (both roles) + router + Prov.c, peer = provisioner;
                       test_prov_button.c: the 5 s wipe button (DK library stubbed, simulated time)
unit/Pair/             test_pair.c: pairing flow (CONTROL, both roles, every error, guards,
                       timeouts, link loss, UNPAIR, wipe), BT stack and neighbours stubbed;
                       test_pair_oob.c: the signed OOB frame on the real TF-PSA-Crypto;
                       test_pair_e2e.c: real SETU (both roles) + router + Pair.c, peer = the
                       other device, sim_link's second link = the host
unit/DeviceCert/       test_devicecert_store.c: certificate storage in DeviceCert.c, in-memory ITS;
                       test_devicecert_verify.c: DeviceCert_Verify.c on the real Mbed TLS, with
                       gen/cert_vectors.h (see "Ideas" below)
unit/CSR/              test_der.c: the CSR DER encoder against the real-signature CSR vector;
                       test_csr_generator.c: key and CSR life cycle (init, first boot, reuse,
                       repair, failures, wipe); its init failures run as four more CTest
                       entries (--init=...), since the init result is kept per process
unit/Wdt/              test_wdt.c: the watchdog (built as wdt, alias watchdog0 enabled, and
                       wdt_nohw, without the node)
unit/Helpers/          test_helpers.c
python/                pytest suite; conftest.py has a fake GATT link + scripted server and a shared Tk root;
                       test_uds_udsoncan.py checks the uds_flash conversation with python-udsoncan;
                       test_check_config_symbols.py the Kconfig symbol check
fuzz/                  libFuzzer targets (own CMake project, clang): fuzz_setu_rx.c, fuzz_fscmd.c,
                       fuzz_uds_cmd.c, fuzz_uds_client.c, fuzz_uds_job.c, fuzz_host_auth.c; most #include a unit test
                       with its main() renamed, to reuse its stubs; fuzz_win.h (ssize_t on Windows)
vectors/wire.json      golden wire vectors, checked by BOTH the C and the Python tests
known_header_issues.txt  headers with a known, reported problem (see below)
tools/                 gen_vectors.py, run_unity.py (Unity -> JUnit), check_headers.py, report.py,
                       gen_csr_vector.py (regenerates the CSR vector, below),
                       gen_pair_vector.py (writes the "pairing" section, below),
                       gen_fs_vector.py (writes the "hex_file" and "file_system" sections),
                       gen_uds_vector.py (writes "uds_cmd", "uds_key" and "uds_flash"),
                       gen_host_auth_vector.py (writes "host_auth": a whole handshake, the advert),
                       wire_section.py (replaces one section of wire.json in place),
                       gen_cert_vectors.py (certificates for devicecert_verify, every fresh build),
                       gen_fuzz_corpus.py (fuzz seeds from wire.json), run_fuzz.py (runs every fuzz
                       target), run_static.py (the static analysis gate) with cppcheck_zephyr.h,
                       check_config_symbols.py (CI, after each firmware build: every CONFIG_
                       symbol an #if in _ASW/_LIB tests is known to the build)
```

## Ideas the tests are built on

- **Written from the spec, not from the code.** DataStore tests follow `_DOC/HexUpload/PROTOCOL.md`, and GATT_CB tests follow `_DOC/GATT_CB/API_REFERENCE.md`. Comments name the section. When code and document disagree, the test makes that visible.
- **Real captures as golden data.** `vectors/wire.json` holds frames from `_LOG/`: the START of the real upload of `AA00000100.hex`, the END, RESULT and STORED frames, and the device's `SEG … crc=0xe2e72827` line. The C encoder, the DataStore, the end-to-end upload, `parse_ihex` and the Python client must all reproduce them byte for byte. The GUI traffic capture is replayed through the monitor's decoders.
- **One wire format, two implementations.** The C firmware and the Python client are checked against the same vectors, so a change on one side without the other fails CI.
- **The device's CSR, checked with the CA's library.** `wire.json` `provisioning.csr` is the CSR the device's `DER.c` builds, with a real ECDSA signature (the C test's signing stub returns it). `test_der.c` requires `DER.c` to produce it byte for byte; the Python tests require `cryptography` to parse and verify it, and the CA to issue a certificate whose subject and key bytes are what the device compares.
- **Stored as the device stores it.** `wire.json` `hex_file` holds the BEGIN, COMMIT and FILE frames and the first segment of `AA00000100.hex` as a file record, with the file's size and CRC-32 (`tools/gen_fs_vector.py`, which also writes the `file_system` CMD / REPLY / ENTRY frames). The data store's test checks the bytes of the file it writes against it, and the client and GUI check a device's FILE answer the same way. Rerun the tool after a change to either wire format; it replaces only its two sections.
- **Signed by one library, verified by the other.** `wire.json` `pairing.oob` is an OOB frame signed by Python's `cryptography` (`tools/gen_pair_vector.py`). `pair_oob` verifies it with the device code on the real TF-PSA-Crypto, and signs and verifies its own frames; the Python tests check the same frame and the CONTROL and STATUS vectors the C tests use. Rerun the tool (it replaces only the `pairing` section) after a change to the pairing wire format.
- **A handshake made by an independent generator.** `wire.json` `host_auth.handshake` is one whole host authentication made by `tools/gen_host_auth_vector.py` with `cryptography`, without blehost: keys, nonces, a throwaway CA's certificates, T, Z, the passkey, both signatures and the frames. `host_auth_crypto` recomputes T, Z and the passkey with the device code on the real TF-PSA-Crypto and verifies both signatures; `test_host_auth.py` checks blehost against the same values. Rerun the tool (it replaces only `host_auth`) after a change to the handshake.
- **The device verifies what the PC sends.** `tools/gen_cert_vectors.py` runs on each fresh build: it makes a device key and CSR, has the PC tool's CA (`blehost/pki/authority.py`) issue the device certificate, and takes every certificate the device must reject, with its expected RESULT status, from `blehost/pki/negative.py`. `devicecert_verify` imports that key as the persistent device key and runs the device's verification on all of them, so a change on either side that breaks the profile fails the host tests, not only a hardware run.
- **The real library where it matters.** Certificate parsing and verification are the security boundary, so their test links Mbed TLS itself. `shim/tfpsa/tf_psa_crypto_host_config.h` removes only what a host cannot provide (AES-NI and asm, the OS entropy source, the file ITS, calendar time, the OS zeroize call). Under ASan/LSan in CI, a certificate context left unfreed on any path fails the test.
- **A second opinion from outside the repo.** The PC client, the ECU simulator, the fakes and `wire.json` come from the same hands as the firmware, so a misreading of a standard can sit on both sides and pass. Where an outside implementation exists, it checks the shared vectors too: `cryptography` parses and verifies the device's CSR, python-udsoncan encodes the device's whole flash conversation (`test_uds_udsoncan.py`). Such a comparison also shows where a documented convention differs from what standard tools compute, as the CSR's SKI does (SHA-1 of X‖Y, not RFC 5280's method 1; audit finding F8).
- **Private state stays reachable.** C tests `#include` the `.c` under test, as `test_engine.c` always did, so static state can be driven and inspected without changing production code.

## Known bugs

A test that documents a defect that is still open does not turn the pipeline red, but it is never hidden either:

- **Python:** `@pytest.mark.xfail(strict=True, reason="KNOWN BUG: …")`. Strict means the test fails the run once the bug is fixed, so the marker gets removed with the fix.
- **Headers:** an entry in `known_header_issues.txt`, with the same strict behaviour.
- **C (Unity):** `TEST_IGNORE_MESSAGE("KNOWN BUG: …")`, after a check that fails the test once the bug is fixed (strict, as above).

The report lists all of them under *Known bugs*. Open now: `csr_der` `test_ShortIntegerKeepsItsLowBytes` (`DER.c` writes a short INTEGER's high-order bytes). The audit that found it is in [`_DOC/Audit/FINDINGS.md`](../_DOC/Audit/FINDINGS.md).

## Adding tests

- **A C module or library:**
  1. Create `unit/<Name>/test_<name>.c` with `setUp`/`tearDown`, `RUN_TEST(...)` in `main()` and `setvbuf(stdout, NULL, _IONBF, 0)` first.
  2. Register it in `CMakeLists.txt` with `add_unit_test(<name> SOURCES … INCLUDES …)`. Code that calls PSA Crypto adds `${PSA_STUB_DIR}` to `INCLUDES` and defines the PSA functions it reaches; code whose correctness *is* the cryptography links `mbedx509` (or `tfpsacrypto`) instead, as `devicecert_verify` and `pair_oob` do.
  3. If the code needs Zephyr or NCS APIs that the shim lacks, add them to `shim/zephyr_shim.h` (plus a forwarding header under `shim/zephyr/`) or as a declarations-only header in `shim/`, keeping the real names and contracts.
  4. Add the module's public headers to `CHECKED_HEADERS`.
- **Python:** add `python/test_<topic>.py`. A GUI feature is tested like `test_feature_provisioning.py`: its logic against stand-in Tk variables and a fake context, plus one test that builds the real page (CI gives it a display through `xvfb-run`). A test that creates widgets takes the `tk_root` fixture, one Tk root shared by the whole run (on Windows, creating several Tk interpreters in one process now and then fails to find `tk.tcl`); it skips without a display and destroys the test's widgets afterwards. The fixtures `server`, `client`, `vectors`, `repo`, `fast_timeouts` and `tk_root` come from `conftest.py`. Python dependencies go in `requirements-test.txt`; `run_tests.ps1` installs it on every run, so a new one reaches an existing venv.
- **A wire-format change:** update `vectors/wire.json` first. Both suites then show where the C and Python sides are wrong.
- **A change to `_ASW/_CSR/DER.c`:** `csr_der` fails until the CSR vector is regenerated. After a test build (`run_tests.ps1`), run `python _TEST/tools/gen_csr_vector.py build_test` with cmake on PATH (or `CMAKE=<path>`): it makes a new key, rebuilds `csr_der`, signs the TBS it prints, and writes key, SKI, TBS, signature, CSR and the STATUS key hashes into `wire.json`.
