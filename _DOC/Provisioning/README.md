# Device Provisioning

Each device gets an ECC P-256 identity, a device certificate, signed by a Certificate Authority (CA). Phase 2 (certificate-based authentication and pairing, see [`_DOC/CBAP`](../CBAP/)) uses these certificates to pair two devices: they exchange and verify each other's certificates, then sign the OOB data of LE Secure Connections pairing with their keys (AN1396 §4.2). Phase 2 is [../Pairing/README.md](../Pairing/README.md).

This document covers provisioning. The wire contract is [PROTOCOL.md](PROTOCOL.md).

## How it works

1. **First boot.** The device generates a P-256 key pair as a persistent PSA key. The key never leaves the device. The device then builds a CSR and stores it. On later boots it reuses both.
2. **Provisioning.** The PC GUI is the CA. It connects and asks for STATUS and then for the CSR. The device sends the CSR with SETU to a SETU service that the PC hosts. The PC checks the CSR, issues a device certificate, and sends it with the CA certificate.
3. **Verification and storage.** The device checks the CA certificate (self-signed CA) and holds it in RAM. It then checks the device certificate against it, its own key and its CSR subject. Only when that passes does it store both certificates in PSA ITS and delete the CSR, which is not needed any more. It logs both as PEM on the UART.
4. **Later boots.** A stored pair is loaded and re-verified (CA, then the device certificate against it and the key) and the device starts PROVISIONED, with the CA as its trust anchor. A pair that fails is wiped (step 5).
5. **One-time, until wiped.** A provisioned device refuses CSR_REQ, CA_CERT and DEV_CERT. To provision it again, a wipe (the DEPROVISION message from the PC, or holding DK Button 0 for 5 s) destroys the key, the CSR and both certificates and makes a fresh key and CSR, as on a chip-erased device.

This is the Silicon Labs flow of AN1396 §3 (`create_authority_certificate.py` and `production_line_tool.py` in [Supporting Scripts](../../Supporting%20Scripts/)), with BLE in place of J-Link and NVM3.

## Files

### Device (`_ASW`)

| File | Role |
|---|---|
| [_CSR/CSR_Generator.c](../../_ASW/_CSR/CSR_Generator.c) | `gt_InitCryptoStorage()` (settings, PSA init, then a check that the hardware unique key exists, which NCS writes during `psa_crypto_init()` with `CONFIG_HW_UNIQUE_KEY_WRITE_ON_CRYPTO_INIT`; once); `gv_GenerateOrLoadCSR()`: persistent key `0x0001` (generate or reuse), CN = UUIDv5 of the hardware device ID, CSR saved in and restored from PSA ITS; `gt_RemoveStoredCSR()`, `gt_DestroyDeviceCredentials()` (key + CSR), `gt_ProbeDeviceKey()` |
| [_CSR/DER.c](../../_ASW/_CSR/DER.c) | `gt_DER_EncodeCSR()`: minimal DER encoder for the CSR, signed with `psa_sign_message()` |
| [_DEVICE_CERT/DeviceCert_Verify.c](../../_ASW/_DEVICE_CERT/DeviceCert_Verify.c) | `ge_VerifyCACertificate()`, `ge_VerifyOwnDeviceCertificate()` (provisioning, with the CSR subject check), `ge_VerifyStoredDeviceCertificate()` (boot, without it), `ge_VerifyRemoteDeviceCertificate()` (pairing: a peer device's certificate), `ge_VerifyHostCertificate()` (host authentication: a host certificate, extendedKeyUsage clientAuth; a device certificate must not carry it): mbedTLS X.509 + PSA |
| [_DEVICE_CERT/DeviceCert.c](../../_ASW/_DEVICE_CERT/DeviceCert.c) | Certificate buffers `gst_CACertData`, `gst_deviceCertData`; their ITS storage: `gt_StoreCACert()`, `gt_StoreDeviceCert()`, `gt_LoadStoredCerts()` (the pair, or nothing), `gt_RemoveStoredCerts()`, `gv_ClearCertData()` |
| [_PROV/Prov.c](../../_ASW/_PROV/Prov.c) | The protocol: state machine, router callbacks, the CSR sent with the router's shared SETU Client to the host link, STATUS/RESULT, storage order, boot restore, the wipe (refused while pairing runs; deletes the pairing bonds), PEM logging. Owns no cryptography |
| [_PROV/ProvButton.c](../../_ASW/_PROV/ProvButton.c) | DK Button 0 held for `CONFIG_PROV_WIPE_HOLD_MS` → `gv_Prov_RequestWipe()` (NCS DK library) |
| [_SETU_SVC/SETURouter.c](../../_ASW/_SETU_SVC/SETURouter.c) | Shares the one SETU Server between hex upload (`0x10`), provisioning (`0x20`–`0x2F`) and pairing (`0x30`–`0x3F`) by appType range, and the one SETU Client between provisioning and pairing (`gi_SETURouter_ClientAttach()`; TX results by appType) |

`_PROV` callbacks run on the SETU engine thread, which has a small stack and holds the SETU lock. They only check, copy into a staging buffer, and post an event. Verification, storage, the wipe, the Client attach and send, replies and logging run on the provisioning thread (priority 10, 10 KiB stack: ITS writes keep an entry-sized buffer on the stack, and a wipe generates a key and builds a CSR). A certificate is copied from the staging buffer into `gst_CACertData`/`gst_deviceCertData` only once it is verified, so a rejected certificate never replaces a good one. The button handler only posts an event, so a wipe never races a transfer: it is refused while the CSR is being sent, a certificate is being received or verified, or a pairing runs, and holds the staging buffer while it runs. A completed wipe also deletes every bond (`gv_Pair_ForgetBonds()`) and the trusted host's record (`gv_HostAuth_Forget()`), and becoming provisioned or wiped re-evaluates advertising (`gv_BLE_RefreshAdv()`): a provisioned device advertises the Pairing service.

### PC (`_TOOLS/BleHostGUI`)

| File | Role |
|---|---|
| [blehost/pki/authority.py](../../_TOOLS/BleHostGUI/blehost/pki/authority.py) | The CA: create/load (P-256, self-signed), check a CSR against the profile (a CSR asking for an extendedKeyUsage is refused), issue a device certificate, issue a host credential (`issue_host()`, [../HostAuth/README.md](../HostAuth/README.md)), record them |
| [blehost/protocols/provisioning.py](../../_TOOLS/BleHostGUI/blehost/protocols/provisioning.py) | appTypes, STATUS/RESULT codecs, `ProvisioningSession` (the sequence) |
| [blehost/core/gatt_server.py](../../_TOOLS/BleHostGUI/blehost/core/gatt_server.py) | The PC's SETU service (WinRT `GattServiceProvider`) feeding a receiver |
| [setu_receiver.py](../../_TOOLS/BleHostGUI/setu_receiver.py) | SETU receiver role on the PC, transport independent |
| [blehost/features/provisioning.py](../../_TOOLS/BleHostGUI/blehost/features/provisioning.py) | The Provisioning page |
| [blehost/pki/negative.py](../../_TOOLS/BleHostGUI/blehost/pki/negative.py) | Certificates the device must reject, for hardware tests |

## Design decisions

- **The PC hosts a SETU service to receive the CSR.** A SETU sender is always the GATT client, and bleak is a GATT client only. So the device turns on its SETU Client role and sends to a service the PC publishes over the same connection (the host link; `gstpt_BLE_GetHostConn()`). The wire protocol is unchanged, and pairing (device to device) uses the device Client role too: the router attaches the Client for whichever module asks, moving it off another link if needed. The PC service uses WinRT directly: `bless` cannot be installed next to bleak ≥ 1 on Python 3.12 (conflicting `winrt` pins). On a WinRT failure, the fallback is a readable CSR characteristic, as in the reference `Sample Code`.
- **The key is a persistent PSA key** (`CSR_DEVICE_SIGNING_KEY_ID` = `0x0001`, ECDSA-SHA256, not exportable). It is stored in PSA ITS: Zephyr secure storage on settings/ZMS, AES-GCM encrypted with a key derived from the nRF54L15 hardware unique key (`CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_HUK_LIBRARY`).
- **The CSR persists until the device is provisioned** (ITS UID `"CSR"‖2`), so STATUS and the CSR stay the same across resets. Once both certificates are stored, the CSR is deleted.
- **Certificate storage.** Each certificate is one ITS entry holding its packed record `[u8 flag][u16 length][DER]`, written up to the DER length (at most 1027 bytes, under the 1100-byte entry limit): the CA under `"DEVCERT"‖3`, the device certificate under `"DEVCERT"‖1`. They are written only after the device certificate has verified against the CA, CA first, then the device certificate, then the CSR is deleted. If either write fails, both entries are removed and the device stays CA_OK. At boot only a complete, well-formed pair counts: none means not provisioned; one, or a malformed record, or an ITS integrity failure, means the pair is invalid and the device wipes. A plain read error wipes nothing (the device reports NO_KEY).
- **Re-verification at boot.** The stored CA is verified again, which also restores the mbedTLS trust anchor that phase 2 needs, and the device certificate is verified against it and against the device key with `ge_VerifyStoredDeviceCertificate()`. That skips the CSR subject check, because the CSR is gone; the subject was checked before storing, and ITS entries are authenticated.
- **One-time provisioning, and the wipe.** A provisioned device refuses CSR_REQ, CA_CERT and DEV_CERT, so its identity cannot be replaced over the air. The wipe (`sb_EraseAndRegenerate()`) is the only way back: it forgets the trust anchor, removes both certificates, destroys the key and the CSR, then runs `gv_GenerateOrLoadCSR()`, which finds no key and makes a new one. The same wipe recovers a device whose stored pair fails at boot, or that is in NO_KEY. Two triggers share it: DEPROVISION (`0x27`, answered with RESULT) for the PC, and DK Button 0 held 5 s for someone at the bench. A new key means certificates issued before no longer match the device.
- **Verification follows the BG22/BG24 reference.** `DeviceCert_Verify.c` keeps that reference's mbedTLS sequence (`mbedtls_x509_crt_parse` → `mbedtls_x509_crt_verify` → `mbedtls_x509_crt_free`, and `psa_import_key` of the peer key from `pk_raw`). The trust anchor is the CA received over BLE, so the CA itself is checked first. mbedTLS accepts a self-signed certificate that is in the trusted list without checking its signature, so `se_VerifySelfSignature()` checks it explicitly.
- **The certificate profile is Silicon Labs', plus digitalSignature.** CA:FALSE and KeyUsage keyAgreement on device certificates, P-256, ecdsa-with-SHA256. KeyUsage also carries digitalSignature, because pairing signs its OOB data with the device key; `sign_csr()` and the device both require the two bits. Devices that made their CSR before this (keyAgreement only) are refused by the CA and by their peers: wipe them (Button 0 or DEPROVISION) and provision again.

## Provenance of the device code

`_CSR` and `_DEVICE_CERT/DeviceCert.c` are the reference `Sample Code/_ASW` modules, ported to NCS v3.4.1 with these changes:

| Change | Why |
|---|---|
| `psa_open_key()` / `psa_close_key()` replaced by a `psa_get_key_attributes()` probe | Removed from PSA 1.x (TF-PSA-Crypto / Oberon in NCS 3.4) |
| `DERValue_T` given a struct tag | It referred to itself as `struct DERValue_T`, a different incomplete type. GCC 14 rejects that |
| Signature INTEGERs encoded minimally | An ECDSA `r` or `s` starting with `0x00` (about 1 in 128 CSRs) was encoded non-minimally, which OpenSSL 3 rejects. The CA would refuse that CSR for ever, because the CSR persists |
| `sst_derWorkBuffer` without `= { 0 }` | Static storage is zeroed anyway. Older GCC warns about the braces |
| Subject strings from Kconfig (`CONFIG_CSR_SUBJ_*`) | Configuration per product without editing code |
| `CSR_DEVICE_SIGNING_KEY_ID` moved to `CSR_Generator.h` | Verification compares the certificate's key with it |
| UUID version nibble set in byte 6, not byte 7 | RFC 4122 puts the version in the high nibble of byte 6 (`time_hi_and_version` is big-endian). The reference set byte 7, so the CN was not a version-5 UUID. A device that already holds a CSR or certificates keeps its old CN (both are restored from ITS); it gets the corrected CN at its next key and CSR generation (DEPROVISION, Button 0 held, or a chip erase) |

`DeviceCert_Verify.c` is new code, ported from the BG22/BG24 reference (`Sample Code Device Cert Verification/_ASW/_APP/Device_Certificate/DeviceCert.c`). It fixes five defects of that reference:

1. An mbedTLS failure returned `SL_STATUS_OK`, so a forged peer certificate passed `gt_VerifyRemoteDeviceCertificate()`.
2. Contexts were freed only on success.
3. There was no own-key, KeyUsage or CA:FALSE check.
4. The public key offset (26) was used without checking.
5. A 1 KiB buffer was on the stack.

## Integration

- `main()` calls, in order: `gi_DataStore_Init()` and `gi_Prov_Init()` (both register with the router; `gi_Prov_Init()` also restores and re-verifies stored certificates, or generates or loads the key and CSR), `gi_ProvButton_Init()`, `gi_Pair_Init()`, then `gi_SETURouter_Start()` (Server and Client), then `gv_BLEInitStartAdv()`.
- `_LIB/CMakeLists.txt` builds SETU with both roles. `SETU_CLI_WRITE_INFLIGHT_MAX=3` keeps Server notifications plus Client writes below `CONFIG_BT_ATT_TX_COUNT=6`.
- `_DI/prj.conf`, section "Device certificate":
  - PSA on CRACEN (ECDSA P-256, SHA-256, SHA-1);
  - persistent keys (`MBEDTLS_PSA_CRYPTO_STORAGE_C`), secure storage on settings/ZMS with 64-bit UIDs and 1100-byte entries;
  - Zephyr's Mbed TLS for X.509 (`CONFIG_MBEDTLS`, CRT/CSR parse), an 8 KiB mbedTLS heap, `CONFIG_BASE64`, `CONFIG_HWINFO`, a 10 KiB main stack (the deepest static path, key and CSR generation through PSA and secure storage, takes about 7.5 KiB);
  - `CONFIG_DK_LIBRARY` for the wipe button, and `CONFIG_PROV_WIPE_HOLD_MS=5000`.
- `_ASW/_DEVICE_CERT/CMakeLists.txt` links `mbedtls_external`. NCS adds the X.509 library to the zephyr library only.
- `_DI/Kconfig`: `PROV_WIPE_HOLD_MS` (hold time of the wipe button, 500–60000 ms) and the menu "Device certificate subject (CSR)": `CSR_SUBJ_C/ST/L/O/OU`.

## Using it

**GUI**, Provisioning page:

1. In the Certificate Authority card, **Create CA** or **Load** an existing folder (both under *CA settings*, open while no CA is loaded). The default folder is `~/.blehost/ca`, which holds the CA private key. Keep it private and never commit it.
2. Connect to the device from the Device page.
3. In the Device card, **Get Status**, then **Provision**. A pill shows the device's state, the step list ticks off each step of the sequence (a failed step is crossed), and the application log (Log page, and the status line) shows the details, prefixed `provisioning:`. The board logs and stores both certificates. A device that is already provisioned is refused with a message.
4. **More ▾ › Save certificate…** writes the device certificate as PEM or DER.
5. **More ▾ › Remove provisioning…** (after a confirmation) wipes the device: it gets a new key and CSR and can be provisioned again.

The *PC service* pill in the Device card shows whether the PC SETU service is published and whether the device has subscribed. Without it the CSR cannot be received.

**Command line:** `python setu_client.py provision --name "ProjectHanuman" [--ca DIR] [--out device.pem] [--negative]`, and `python setu_client.py deprovision --name "ProjectHanuman"` to wipe. `--negative` wipes a device that is not fresh, sends the rejected cases before the good CA and device certificate, and leaves the device provisioned.

**At the board:** hold Button 0 for 5 s to wipe. A chip erase (`nrfutil device recover`, or `chip_erase_mode=ERASE_ALL` when programming) also gives a new key; a normal flash keeps the storage partition and so the provisioning.

## Testing

- **Host (C):**
  - `prov`: every state, status and rejection, the storage order and its failures, every boot path (nothing stored, valid pair, corrupt/incomplete/unverifiable pair, unreadable storage), the wipe from BLE and from the button (refused while pairing, bonds deleted after), the CSR attach through the router to the host link, with verification and storage stubbed;
  - `prov_e2e`: the real SETU engine in both roles, the router and `Prov.c` over the simulated link, with the peer as the provisioner (the CSR reaches the provisioner's service byte for byte; provisioned, refused, wiped, provisioned again);
  - `prov_button`: the wipe button (a hold of `CONFIG_PROV_WIPE_HOLD_MS` wipes once; an earlier release, other buttons and repeated short presses do not);
  - `devicecert_store`: `DeviceCert.c` against an in-memory ITS (record layout, UIDs, incomplete or malformed pairs, errors);
  - `devicecert_verify`: `DeviceCert_Verify.c` on the **real** Mbed TLS 4 / TF-PSA-Crypto, built for the host. The certificates are made on each build by the PC's own CA and `blehost/pki/negative.py` (`_TEST/tools/gen_cert_vectors.py`): the good CA and device certificate pass; every negative case gets its expected RESULT status as the own certificate (among them another device's subject: the same fields and length, only the CN's bytes differ, so a length check alone cannot pass); the stored check differs only in skipping the subject; the remote check skips key and subject and imports the peer key. Also: a rejected CA keeps the previous one, a new CA replaces it, a CA is not a device certificate, and the own check fails without the CSR or the device key;
  - `csr_generator`: `CSR_Generator.c` with PSA, ITS, HUK, settings and the DER encoder stubbed, built with the firmware's storage Kconfig (Zephyr secure storage on settings, its key from the HUK library): the key policy (P-256, ECDSA-SHA256, persistent ID `0x0001`, not exportable), the subject (Kconfig fields and the CN from SHA-1 of namespace and hardware ID), the stored record, reuse at reboot, every repair path (key gone, corrupt or short record, read errors), every generation failure, the wipe, and each init case (`csr_generator_init_*`: HUK already present, HUK missing after crypto init, settings and crypto init failing);
  - `csr_der`: the sample encoder against a golden CSR with a real signature, plus its error and INTEGER-encoding paths. A known bug is kept as a test: an INTEGER shorter than 4 bytes is written with its high-order bytes (`0x80` as `02 02 00 00`); the CSR only encodes version 0, which comes out right;
  - `setu_router`.
- **Host (Python):** `test_authority.py` signs the device's real CSR and checks the subject and key bytes the device compares. The others are `test_provisioning.py` (the session, DEPROVISION and the `--negative` order against a simulated device that follows these rules), `test_feature_provisioning.py` (the GUI tab), `test_client_cli.py` (`provision`/`deprovision` on the command line), `test_setu_receiver.py`, `test_gatt_server.py` (including the WinRT backend against fake `winrt` modules) and `test_negative_certs.py`.
- **Hardware:** what only the board can show: CRACEN, the flash-backed ITS, the key surviving a reset, and the device discovering the PC's service. `provision --negative` sends the set in `blehost/pki/negative.py` (the same set `devicecert_verify` runs on the host), each case built from the device's own CSR, and fails on any RESULT that differs from the expected one. The CI `hil-tests` job runs it, then checks that a second provisioning is refused, wipes with `deprovision` and provisions again.

## Limitations

- **Provisioning itself is not authenticated.** A device without a certificate cannot authenticate a host, so any host that connects while the host window is open (DK Button 3) can provision an unprovisioned device. Provision in a controlled place. Once provisioned, the device serves only its trusted host ([../HostAuth/README.md](../HostAuth/README.md)): DEPROVISION over BLE needs that host, and Button 0 held still wipes. Replacing the identity without a wipe is not possible.
- **A CA held in CA_OK is lost on reset.** Nothing is stored until the device certificate verifies; the provisioner sends the CA again.
- **No atomic pair write.** ITS has no transaction. The write order and the boot checks make every interrupted write either complete or wiped, never half-trusted.
- **No validity check on the device.** It has no wall clock, so `MBEDTLS_HAVE_TIME_DATE` is off and expiry is not checked.
- **The CA key is an unencrypted PEM file on the PC.** Silicon Labs notes the same for its scripts. Production should use an HSM.
- **The PC service needs Windows 10/11** and an adapter that supports the peripheral role (checked at start). The device must be able to discover it over the connection, which only a hardware run proves (spike (a)).

## Later stages

- **Phase 2 (pairing)** is implemented: [../Pairing/README.md](../Pairing/README.md). `ge_VerifyRemoteDeviceCertificate()` verifies a peer's certificate and imports its key for the OOB signature check; signing uses key `0x0001`.
