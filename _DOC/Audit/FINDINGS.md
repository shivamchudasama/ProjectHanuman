# Pre-deployment audit: findings

Audit of the firmware (`_ASW`, `_LIB`), the PC tools (`_TOOLS`) and the tests (`_TEST`) at commit `fa53d88` (NCS v3.4.1, `nrf54l15dk/nrf54l15/cpuapp`), October 2026. The aim was to find defects and systematic flaws before the code goes into a product.

## Verdict

**Not ready to deploy yet.** The tools found no memory-safety defect in the code that parses outside input, and the UDS conversation matches an independent ISO 14229 implementation byte for byte. What blocks deployment is the product configuration and the trust model, not crashes:

1. Anyone in BLE range can wipe the device's identity, unpair it, change its files and drive UDS on the vehicle bus (F1). **Fixed since by host authentication**; what remains is listed under *Fixes*.
2. The debug port is open and there is no bootloader (F2).

F2 is kept on purpose while the BLE software and library stacks are built, and is to be closed when the application is developed on top of them. F1 (unauthenticated host link), F3 (no watchdog, halt on a fault), F4 (stack margins) and F6 (compiled-out storage init) are fixed; see *Fixes* at the end.

## How it was tested

Most of this code was written with an AI assistant, so the audit relies first on checks that do not share its reasoning: tools, fuzzers, and libraries written by other people. A model review came last, and was used only to read what the tools pointed at.

| Method | Scope | Result |
|---|---|---|
| cppcheck 2.22 (warning, performance, portability, style) | all of `_ASW`, `_LIB` | 16 notes, no defect (style, macros it cannot expand) |
| clang-tidy 23 (`clang-analyzer-*`, `bugprone-*`, `cert-*`) on the firmware's compile commands | 31 project files | no path-sensitive defect; noise from Zephyr's `LOG_*` macros |
| GCC 14.3 (Zephyr SDK) `-fanalyzer` + `-Wextra -Wshadow -Wconversion -Wformat=2 -Wnull-dereference …` | 31 project files | no analyzer path; narrowing warnings in `DER.c` led to F7 |
| ruff (pyflakes, bugbear, bandit rules), bandit, mypy | `_TOOLS` | no defect (mypy: Optional typing only) |
| `CONFIG_` symbol audit: every symbol tested in `#if` against the build's `.config` | `_ASW`, `_LIB` | F6 |
| Static stack depth (`-fstack-usage -fcallgraph-info=su`, whole image incl. Zephyr, Mbed TLS) | 8 threads | F4 |
| libFuzzer + ASan, 5 new targets (`_TEST/fuzz`) | SETU receive path, file commands, UDS messages, UDS client, flash job | about 10 million runs, **no crash, no oracle violation** |
| Mutation testing: one comparison or logical operator flipped per mutant | 12 core C files, 25 mutants each | 214 of 261 compiling mutants killed (82 %); F5, F10 |
| Independent implementations | OpenSSL 3.4, Python `cryptography`, python-udsoncan 1.26 | CSR verifies; UDS conversation matches; F8 |
| Reading against the standards, guided by the above | UDS client, pairing parsers, provisioning, upload/commit | F9; checks listed under *Checked and clean* |

## Findings

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| F1 | **Critical** (for deployment) | Security | The host link is unauthenticated: DEPROVISION, UNPAIR/START, file commands and UDS are open to anyone in range | **Fixed** (host authentication, `_ASW/_HOST_AUTH`); provisioning of an unprovisioned device stays open; hardware check pending |
| F2 | **High** | Production config | Debug port open (`NRF_APPROTECT_DISABLE`), no bootloader (no field update or image verification) | Kept on purpose until the application; open |
| F3 | **High** | Robustness | No watchdog and no `RESET_ON_FATAL_ERROR`: a fault halts the device | **Fixed** (`_ASW/_WDT`, `RESET_ON_FATAL_ERROR`) |
| F4 | **Medium** | Resources | Static stack use 91 % (provisioning), 88 % (main), 87 % (dump), 78 % (pairing), before interrupts and indirect calls | **Fixed** (stacks raised); measure on hardware |
| F5 | **Medium** | Test gap, security | No test caught a broken subject comparison for a same-length subject (another device's certificate) | **Fixed in this audit** (test added) |
| F6 | **Medium** | Systematic | HUK and settings init in `CSR_Generator.c` is compiled out: it tests `CONFIG_TRUSTED_STORAGE_*`, which this build never sets. The unit test forces those symbols on, so CI tests a configuration the firmware does not build | **Fixed** (real symbols, HUK check, CI guard) |
| F7 | Low | Latent bug | `DER.c` writes a short INTEGER's high-order bytes (`0x80` → `02 02 00 00`) | Known-bug test added |
| F8 | Low | Interop | The CSR's SKI is SHA-1 of X‖Y, not RFC 5280 method 1 (SHA-1 of `04`‖X‖Y) | Documented convention; decide |
| F9 | Low | Concurrency | Upload COMMIT, file commands and flash jobs exclude each other by check-then-act on flags, and COMMIT clears its flag before the rename | Open |
| F10 | Low | Test quality | 47 surviving mutants: mostly untested boundaries and error branches | Open, list below |
| F11 | Info | Security | No certificate expiry or revocation (no wall clock) | Documented limitation |

### F1: Unauthenticated host link (Critical for deployment)

**What.** SETU DATA (`SETUSvc.c`: `BT_GATT_PERM_WRITE`) and Pairing CONTROL (`PairSvc.c`: `BT_GATT_PERM_WRITE`) accept writes from any connected central, encrypted or not. Through them, anyone in BLE range can:
- send DEPROVISION, which destroys the device key, the certificates and the pairing bonds;
- UNPAIR, or START a pairing with a device of their choice;
- delete or overwrite files on the external flash (file commands);
- send any UDS request on the vehicle bus, unlock with the on-device seed→key, and flash an ECU (`CONFIG_UDS_CMD=y`);
- upload and store images.

**Evidence.** The permissions above; `_DOC/Provisioning/README.md` (Limitations), `_DOC/Pairing/README.md` §Security, `_DOC/UDS/PROTOCOL.md` §Security and `_DOC/FileSysManager/PROTOCOL.md` already say so.

**Recommendation.** Before any field use:
- authenticate the host: an encrypted link at level 4 from a host that proves it holds a certificate of the same CA, or at least a bonded host chosen by a physical action;
- build production images with `CONFIG_UDS_CMD=n` and `CONFIG_FS_CMD=n` unless the host is authenticated;
- gate DEPROVISION behind the button only;
- set the GATT permissions to `BT_GATT_PERM_WRITE_LESC` (or `_AUTHEN`) once the host pairs.

### F2: Production configuration (High)

- `CONFIG_NRF_APPROTECT_DISABLE=y` and `CONFIG_NRF_SECURE_APPROTECT_DISABLE=y`. Anyone with SWD access can run code on the device and use its persistent device key, so certificate-based pairing no longer proves anything. Enable APPROTECT (and secure APPROTECT) in production images.
- No bootloader (no MCUboot or NSIB in the sysbuild). The device firmware cannot be updated in the field, and nothing verifies the image at boot. Add MCUboot with signed images, and decide how the device itself receives updates.
- The UART console and logging stay on, and they print certificates (public) and, with `CONFIG_DS_HEX_DUMP=y`, ECU images. Decide what a production image logs.

### F3: No recovery from a fault or hang (High)

`CONFIG_WATCHDOG`, `CONFIG_TASK_WDT` and `CONFIG_RESET_ON_FATAL_ERROR` are all off. `CONFIG_HW_STACK_PROTECTION=y` catches a stack overflow, but Zephyr's default fatal handler then halts the CPU. A device in the field stays dead until it is power-cycled, possibly in the middle of an ECU flash. Enable `RESET_ON_FATAL_ERROR`, and a hardware watchdog fed by a task watchdog covering the SETU engine, File System Manager, UDS job, provisioning and pairing threads.

### F4: Thin stack margins (Medium)

The worst static path from each thread entry (GCC call graph of the whole image, including Zephyr, PSA and Mbed TLS):

| Thread | Stack | Static worst | Use | Deepest path |
|---|---|---|---|---|
| `sv_ProvThread` | 8192 | 7476 | **91 %** | wipe → `gv_GenerateOrLoadCSR` (1368) → `gt_DER_EncodeCSR` (920) → `psa_sign_message` → persistent key load → secure storage (`get_entry` 1224, `its_get_info` 1128) → AEAD |
| `main` | 8192 | 7204 | **88 %** | `gi_Prov_Init` → the same CSR path at boot |
| `sv_DumpThread` | 2048 | 1772 | **87 %** | `sv_SendFile` → `gi_SETUS_SendShort` → GATT notify → net_buf |
| `sv_PairThread` | 8192 | 6364 | 78 % | `ge_VerifyRemoteDeviceCertificate` → X.509 parse → `psa_import_key` → secure storage |
| SETU engine | 2048 | 1404 | 69 % | ACK notify |
| UDS job | 3072 | 1588 | 52 % | |
| CanIf | 2048 | 884 | 43 % | |
| File System Manager | 4096 | 588 | 14 % | |

The figures exclude calls through function pointers (PSA drivers, router callbacks, log backends), the exception frame an interrupt pushes on the thread stack (up to about 100 bytes with the FPU), and recursion (`st_Encode` in `DER.c`, CRACEN's RNG). Measure on the board with `CONFIG_THREAD_ANALYZER=y` under the worst case: a wipe, a pairing, an upload with COMMIT. Until then, raise the provisioning, main and pairing stacks to 10 KiB and the dump thread to 3 KiB.

### F5: Same-length subject not tested (Medium; fixed)

Flipping `||` to `&&` in the subject comparison (`DeviceCert_Verify.c:520`, length differs **or** bytes differ) left every test passing. The only negative case used the CN `"someone else"`, whose length differs from the device's subject. Yet the realistic attack is a certificate issued to another device, and every device's CN is a UUID of the same length. The code is correct; nothing would have caught a regression.

**Fixed:** `blehost/pki/negative.py` has a new case, `dev_other_device_cn` (same fields, same length, the CN's last character changed). `devicecert_verify` runs it on the real Mbed TLS, `test_negative_certs.py` checks that it differs only in those bytes, and `provision --negative` sends it to the board in `hil-tests`. Re-running the mutant now fails `devicecert_verify` (`Expected 0x07 Was 0x00 … dev_other_device_cn`).

### F6: Compiled-out storage init; a test configuration the firmware never builds (Medium)

`si_InitPersistentKeyStorage()` in `CSR_Generator.c` provisions the HUK and calls `settings_subsys_init()` only `#if defined(CONFIG_TRUSTED_STORAGE_BACKEND_AEAD_KEY_DERIVE_FROM_HUK)` / `CONFIG_TRUSTED_STORAGE_STORAGE_BACKEND_SETTINGS`. Those are NCS *Trusted Storage* symbols. This build uses Zephyr's *Secure Storage* (`CONFIG_SECURE_STORAGE_*`), and neither symbol exists in its `.config`, so the function is an empty `return 0`.

It still works on the board by coincidence: Zephyr's secure storage calls `settings_subsys_init()` from its own `SYS_INIT` (`subsys/secure_storage/src/its/store/settings.c`), and NCS writes the HUK on crypto init (`CONFIG_HW_UNIQUE_KEY_WRITE_ON_CRYPTO_INIT=y`).

The systematic part: `test_csr_generator.c` `#define`s both symbols, so the HUK paths it tests (`csr_generator_init_huk-*`, `settings-fail`) cover code the firmware does not contain.

**Recommendation:**
- Delete the dead branches, or key them on the symbols this build sets.
- Build unit tests from the firmware's Kconfig values. For example, generate the test defines from `build/zephyr/.config`, or add a test that fails when a `CONFIG_` symbol used in `_ASW`/`_LIB` is unknown to Kconfig (the audit's check found only these two).

### F7: Short INTEGER encoding in `DER.c` (Low)

For `eDT_PRIMITIVE_INTEGER`, `st_Encode()` writes byte `pos` as `value >> (8 * (DER_INTEGER_LEN - 1 - pos))`. For an integer shorter than 4 bytes these are the top bytes, so `0x80` becomes `02 02 00 00` and `1` becomes `02 01 00`. `abs(INT32_MIN)` in `st_IntLength()` is undefined. The CSR only encodes version 0, which comes out right, so no CSR is wrong today. It becomes a defect the day the encoder encodes another integer (a serial number, an extension). A known-bug test, `csr_der` `test_ShortIntegerKeepsItsLowBytes`, documents it and fails once it is fixed.

### F8: Subject Key Identifier convention (Low)

`DER.c:1335` hashes the 64 bytes X‖Y. RFC 5280 §4.2.1.2 method 1 hashes the subjectPublicKey BIT STRING contents, `04`‖X‖Y, which is what OpenSSL and `cryptography` compute. Other methods are allowed, `_DOC/Provisioning/PROTOCOL.md` states this one, and `test_SubjectKeyIdIsSha1OfThePoint` pins it, so it is deliberate (inherited from the Silicon Labs sample). Any tool that matches the CSR's SKI against a recomputed one will still disagree. Decide whether to keep it or switch to method 1 (which needs a regenerated CSR vector). Only the comparison with an outside library shows the difference: the in-repo vector comes from the device's own encoder.

### F9: Check-then-act between upload, file commands and flash jobs (Low)

`DataStore.c` BEGIN checks `gb_UdsJob_FlashRunning()`, `UdsJob.c` checks `gb_DataStore_UploadOpen()`, and `FsCmd.c` checks both, each on its own thread with no lock in common. `sv_Commit()` clears `st_uploadOpen` before CLOSE, DELETE and RENAME run, so a file command or a flash job accepted in that window competes with the commit. The File System Manager allows only one open file and runs messages in order, so the worst outcome is a spurious BUSY or a failed COMMIT (the upload is discarded and must be sent again), not corruption. Fix: one lock or a single owner for "the file system's open file", taken before each check, and clear `st_uploadOpen` after the rename.

The replace itself is not atomic either: COMMIT deletes the old file, then renames the new one. A power cut in between leaves only `UPLOAD.TMP`, which the next BEGIN deletes.

### F10: Surviving mutants (Low)

Some of the 47 survivors only change a log message or a branch that ends the same way (equivalent mutants, for example the warning-or-info choice in `CanIf.c:909` and `Prov.c:673`). The others are boundaries or error paths that no test reaches:
- **SETU Server** (`SETU_Server.c`): an ABORT from the sender with another transfer's id (381–382), DATA with another transfer's id (583), the frame-capacity boundary (1209), the short-frame/appType boundary (358). This is the most exposed code; the fuzzer found no fault there, but no test pins the behaviour.
- **SETU frame codec** (`SETU_Frame.c` 134, 311, 410): exact-size buffer boundaries.
- **UDS**: the FLASH message length boundary (`UdsCmd.c:335`), the security level limit `0x7D` (`UdsJob.c:1223`), the request length limit (`UdsJob.c:1191`), `maxNumberOfBlockLength` of exactly 3 (`UdsClient.c:959`), the functional-ID check (`UdsClient.c:193`), the deadline boundary (`UdsClient.c:379`).
- **File system**: the read chunk limit (`FileSysManagerFSM.c:1023`), the ENTRY path limit (`FsCmd.c:279`).
- **Pairing**: guards that a stale event cannot pass (`Pair.c` 1487, 1666, 1913).
- **Certificates**: a verification error other than VERIFY_FAILED (`DeviceCert_Verify.c:373`).

Add one test per boundary (at the limit and one past it). The CSV with every mutant is reproducible with the procedure below.

### F11: No expiry or revocation (Info)

`MBEDTLS_HAVE_TIME_DATE` is off because the device has no wall clock, and there is no revocation list. Both are documented. A compromised device certificate stays valid for ever; plan a deny-list update or a CA rotation for production.

## Checked and clean

- **Parsing of outside bytes.** About 10 million fuzz runs under ASan over the SETU receive path (2 M, with the peer model checking every frame the device sends back), file commands (0.35 M), UDS messages (0.64 M), the UDS client on ECU answers (4.8 M, length and return contracts checked) and flash jobs on corrupted stored files (2 M, cleanup and image invariants checked).
- **UDS against an outside implementation.** All 18 requests and 19 responses of the golden flash conversation are what python-udsoncan encodes and accepts (`test_uds_udsoncan.py`).
- **UDS behaviour against ISO 14229.** NRC 0x78 is bounded (100 answers, P2* each), NRC 0x21 has 3 retries, RequestDownload honours `lengthFormatIdentifier` and saturates beyond 32 bits, the transfer block is `maxNumberOfBlockLength - 2`, and the block counter wraps 0xFF → 0x00.
- **The device's CSR**, verified by OpenSSL: version 0, P-256, ecdsa-with-SHA256, CA:FALSE, Digital Signature + Key Agreement.
- **Pairing input**: CONTROL and SECURED writes and the received certificate and OOB objects are length- and state-checked before any copy. The OOB frame binds `r‖c‖sender‖receiver`, and LE SC binds `c` to the ECDH key, so a replayed frame cannot pair.
- **Upload naming and the commit buffer**: sized for the longest name plus the directory.
- **Configuration symbols**: apart from F6, every `CONFIG_` symbol the code tests is one Kconfig knows.

## Not covered: still needed before deployment

- **Hardware-in-the-loop.** The `hil-*` jobs are placeholders. Needed:
  - stack high-water marks (F4) and RAM under load;
  - power cuts during COMMIT, provisioning storage, a bond write and an ECU flash;
  - soak tests (repeated uploads, flash jobs and reconnects overnight);
  - RF interference;
  - Windows, Android and iOS hosts.
- **A real ECU or a commercial UDS tester** instead of `EcuSim`, at least once. The udsoncan check covers encoding, not an ECU's timing.
- **Real concurrency.** The host shim is single-threaded, so races (F9 and any others) cannot show in host tests; they need the board, or a thread-sanitized POSIX build.
- **An external security review** of `_PROV`, `_PAIR`, `_DEVICE_CERT`, `_CSR` and `_UDS` against the threat model of the product. For an ISO 21434, IEC 62443 or EU CRA product, it is also required evidence. This audit is input to it, not a replacement.
- **A second model, for cross-checking.** A review by another vendor's model with the same checklist is cheap extra coverage. It does not replace the items above.
- **CodeQL** was not set up.

## Reproducing

```powershell
powershell -ExecutionPolicy Bypass -File _TEST\run_tests.ps1 -Static -Fuzz -FuzzSeconds 600
```

CI runs the static gate (`static-analysis`) and each fuzz target for 60 s (`fuzz`) on every push. The stack depth, the configuration-symbol audit and the mutation sampling were one-off scripts: rebuild with `-DEXTRA_CFLAGS="-fstack-usage -fcallgraph-info=su"` and walk the `.ci` call graphs from each thread entry; compare `#if CONFIG_*` symbols with `build/zephyr/.config`; flip one comparison per mutant, rebuild the unit's tests and run them.

## Fixes

### F1: host authentication

New module `_ASW/_HOST_AUTH` ([../HostAuth/README.md](../HostAuth/README.md), [../HostAuth/PROTOCOL.md](../HostAuth/PROTOCOL.md)). Each recommendation, and what was done:

- **Authenticate the host.** Done: the PC proves a host certificate of the device's CA (extendedKeyUsage clientAuth), the device proves its device certificate, in a signed ECDH handshake. The passkey derived from it drives LE SC passkey entry, so the host's bond is at level 4. The device keeps one host bond. A provisioned device admits only that host, through a gate in the SETU router (hex upload, files, UDS, provisioning incl. DEPROVISION) and a check on Pairing CONTROL (ATT `0x08`).
- **Physical action.** Done: the device advertises for a host only while DK Button 3 has opened its window; holding the button forgets the bonded host. Replacing a host needs someone at the device.
- **`CONFIG_UDS_CMD` / `CONFIG_FS_CMD`.** Kept `y`: both ranges are behind the gate now.
- **DEPROVISION behind the button only.** Not done as written. DEPROVISION needs the trusted host instead, and Button 0 held still wipes.
- **GATT permissions `_LESC`.** Not done as written. SETU DATA must stay writable before encryption for the handshake itself, so the router's gate checks trust per appType instead. Pairing CONTROL checks trust in code.

What remains open:
- An **unprovisioned** device takes provisioning from any host that connects during a button window: it has no certificate yet, so it cannot authenticate one. Provision in a controlled place.
- **No revocation or expiry** of host certificates (F11).
- **On hardware:** Windows' `ProvidePin` against the DisplayOnly device (LE SC passkey entry, no prompt), the reconnection's encryption with the stored keys, the grace window, and the thread's stack (6 KiB, estimated).

Tests: `host_auth`, `host_auth_crypto`, `host_auth_button`, the host cases of `devicecert_verify`, the gate in `setu_router`, `pair` and `prov` additions, `fuzz_host_auth`, and the Python side (`test_host_auth.py`, `test_host_credential.py`, `test_winrt_pairing.py`, `test_feature_host_access.py`).

RAM: the module adds about 9.5 KB. The SPI build is at 92.0 % of 256 KiB, and the **sQSPI build at 98.3 % of 240 KiB**: measuring the stacks (F4) and trimming them is now needed before more is added there.

### F3: watchdog and reset on a fatal error

- `CONFIG_RESET_ON_FATAL_ERROR=y` (NCS): a fault, a stack overflow or a kernel panic resets the device instead of halting it. Set it to `n` while debugging a fault.
- New module `_ASW/_WDT` (`CONFIG_APP_WDT`, default y), first in `main()`:
  - it logs and clears the hwinfo reset cause, so a watchdog or fatal-error reset shows on the next boot (`reset by watchdog`, `reset by software (fatal error or reboot)`);
  - it starts Zephyr's task watchdog with the hardware watchdog `wdt31` (alias `watchdog0`, enabled in the board overlay) as its fallback, paused while a debugger halts the CPU;
  - it feeds one channel (`CONFIG_APP_WDT_TIMEOUT_MS`, 8 s) every `CONFIG_APP_WDT_FEED_MS` (1 s), from a 1 KiB supervisor thread at the lowest application priority. A hang, interrupts held off, or a thread that starves the CPU resets the device.
- Tests: `wdt` and `wdt_nohw` (11 cases each).
- Not yet done: one channel per worker thread (the SETU engine, File System Manager, UDS job, provisioning, pairing). That needs each thread's waits bounded and its longest legitimate step known; the task watchdog has 5 channels for it. Check the 8 s timeout on the board against the slowest boot (first-boot format of the external flash, key and CSR generation).

### F4: stack sizes

The provisioning, pairing and main stacks went from 8 KiB to 10 KiB, and the dump thread from 2 KiB to 3 KiB. Static worst case afterwards:

| Thread | Stack | Static worst | Use |
|---|---|---|---|
| `sv_ProvThread` | 10240 | 7476 | 73 % |
| `main` | 10240 | 7204 | 70 % |
| `sv_PairThread` | 10240 | 6364 | 62 % |
| `sv_DumpThread` | 3072 | 1772 | 58 % |
| `sv_WdtThread` (new) | 1024 | 516 | 50 % |

RAM rose by about 8.6 KiB: the SPI build is at 88.8 % of 256 KiB, the **sQSPI build at 94.8 % of 240 KiB**, which leaves little room for the application. The thread-analyzer lines in `prj.conf` (commented out) measure the real high-water marks on the board. With those numbers the stacks can be trimmed again, sQSPI first.

### F6: storage init on the real configuration

- `CSR_Generator.c` and `CSR_Generator.h` now key on the symbols this build sets: `settings_subsys_init()` runs under `CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS`. After `psa_crypto_init()`, `gt_InitCryptoStorage()` checks that the HUK exists (`hw_unique_key_are_any_written()`, under `CONFIG_HW_UNIQUE_KEY`) and returns `PSA_ERROR_STORAGE_FAILURE` if it does not, since secure storage cannot encrypt without it.
- An `#error` stops a build where secure storage takes its key from the HUK library but `CONFIG_HW_UNIQUE_KEY_WRITE_ON_CRYPTO_INIT` is off: nothing else would write the HUK.
- The unused `hw_unique_key_write_random()` path is gone, and so are the dead includes in `DeviceCert.h`.
- `test_csr_generator.c` defines the firmware's own storage symbols. `huk-fail` became `huk-missing` (crypto init succeeds but leaves no HUK).
- The systematic part: `_TEST/tools/check_config_symbols.py` runs in CI after each firmware build and fails when an `#if` in `_ASW`/`_LIB` tests a `CONFIG_` symbol the build does not know. Its first run found the two `DeviceCert.h` uses that the audit had missed. It has its own pytest.