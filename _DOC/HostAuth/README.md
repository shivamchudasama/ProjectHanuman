# Host Authentication (the trusted host)

A provisioned device serves **one trusted host**: the PC that proved it holds a host certificate of the device's CA, and then bonded with the device using a passkey that only the two of them could derive. Any other link reaches only the handshake, provisioning's GET_STATUS and the Pairing service's STATUS. That covers hex upload, the file commands, UDS and ECU flashing, deprovisioning and the pairing commands. The device advertises for a host only after a press of DK Button 3. The wire contract is [PROTOCOL.md](PROTOCOL.md).

This closes audit finding F1, the unauthenticated host link ([../Audit/FINDINGS.md](../Audit/FINDINGS.md)).

## How it works

1. **Credential.** The PC gets a host credential from the CA that provisions the devices: its own P-256 key and a host certificate (CA:FALSE, digitalSignature, extendedKeyUsage **clientAuth**), plus a copy of the CA certificate. It is made on the GUI's Host access page or with `setu_client.py hostcert`. A field laptop carries the credential, not the CA key.
2. **Window.** Someone presses the device's Button 3. The device advertises for 2 minutes, with LED1 blinking. To replace the bonded host, hold the button for 3 s: the old host's bond goes first.
3. **Handshake.** The PC connects and sends HELLO: a nonce, a fresh ECDH key and its host certificate.
   - The device checks the certificate against its CA and the host role.
   - It answers with CHALLENGE: its nonce, its fresh ECDH key, its device certificate, and its signature over a transcript of everything exchanged.
   - The PC checks the device certificate against the same CA, and the signature.
   - The PC then sends FINISH, its own signature over the transcript.
   - Both sides compute the ECDH secret, and from it the same six-digit passkey.
4. **Pairing.** The PC pairs with LE Secure Connections passkey entry, entering that passkey. The device allows this one pairing on this link only. The bond (level 4) makes the PC the trusted host; an older host bond is deleted.
5. **Later.** When the bonded PC connects again, the device asks for security, Windows encrypts with the stored keys, and the PC is trusted again. If the trusted PC's link drops, the window reopens for a minute, so the GUI can reconnect without anyone at the device (for instance to follow an ECU flash job).

## Files

| File | Role |
|---|---|
| [_HOST_AUTH/HostAuth.c](../../_ASW/_HOST_AUTH/HostAuth.c), [HostAuth.h](../../_ASW/_HOST_AUTH/HostAuth.h) | The module, on its own low-priority thread (`CONFIG_HOST_AUTH_STACK_SIZE`, 6 KiB): router callbacks for `0x60`–`0x6F`, HELLO/CHALLENGE/FINISH/RESULT/STATUS/REFUSED, the router's gate (`gb_HostAuth_Admits()`), the host link's SMP callbacks (overlay: `pairing_accept`, `app_passkey`), the bond record (`hauth/host`), trust, the window and the grace window, the timeout, LED1. One buffer holds HELLO, then CHALLENGE |
| [_HOST_AUTH/HostAuthCrypto.c](../../_ASW/_HOST_AUTH/HostAuthCrypto.c), [HostAuthCrypto.h](../../_ASW/_HOST_AUTH/HostAuthCrypto.h) | The cryptography: ephemeral P-256 key (derive only), raw ECDH, the transcript, role signatures with the device key, the HKDF-SHA256 passkey. PSA only, so it is tested on the real TF-PSA-Crypto |
| [_HOST_AUTH/HostAuthButton.c](../../_ASW/_HOST_AUTH/HostAuthButton.c), [HostAuthButton.h](../../_ASW/_HOST_AUTH/HostAuthButton.h) | Button 3 (SW3, `DK_BTN2_MSK`: the overlay deletes button1/2): a second DK library handler (`dk_button_handler_add()`); short press opens the window, a 3 s hold forgets the host and opens it |
| [_SETU_SVC/SETURouter.c](../../_ASW/_SETU_SVC/SETURouter.c) | `gi_SETURouter_SetGate()`: a gate consulted for every new transfer and short message while no pairing filter applies; refusals reported back |
| [_DEVICE_CERT/DeviceCert_Verify.c](../../_ASW/_DEVICE_CERT/DeviceCert_Verify.c) | `ge_VerifyHostCertificate()` (the host role required); device certificates must not carry clientAuth |
| [_BLE/ConnectionHandling.c](../../_ASW/_BLE/ConnectionHandling.c) | Advertising only while the window is open (or directed to a bonded central); host connect/disconnect/security changes to the module |
| [_PAIR/Pair.c](../../_ASW/_PAIR/Pair.c) | CONTROL from the trusted host only (ATT `0x08` otherwise); the host's bond is never taken for the peer's |
| [_PROV/Prov.c](../../_ASW/_PROV/Prov.c) | A wipe forgets the host record too |
| PC: [pki/host.py](../../_TOOLS/BleHostGUI/blehost/pki/host.py), [pki/authority.py](../../_TOOLS/BleHostGUI/blehost/pki/authority.py) `issue_host()` | The host credential and its issuance |
| PC: [protocols/host_auth.py](../../_TOOLS/BleHostGUI/blehost/protocols/host_auth.py) | Codecs, the cryptography (`cryptography`), `HostAuthSession` |
| PC: [core/winrt_pairing.py](../../_TOOLS/BleHostGUI/blehost/core/winrt_pairing.py), `BleLink.pair_with_pin()` | Windows pairing with `DevicePairingKinds.ProvidePin` |
| PC: [features/host_access.py](../../_TOOLS/BleHostGUI/blehost/features/host_access.py) | The Host access page, first in the rail |

## Design decisions

- **Certificates, not a shared secret.** The CA that provisions the devices also certifies hosts, so a device trusts any host the fleet's CA certified, and a host can check that the device is one of the fleet. The roles are kept apart by extendedKeyUsage clientAuth:
  - a host certificate must carry it;
  - a device certificate must not;
  - the CA refuses device CSRs that ask for any extendedKeyUsage, since `sign_csr()` copies a CSR's extensions.

  A device's key, extracted, therefore cannot pose as a host.
- **Passkey entry, derived.** Windows does not let an application supply LE OOB data, which is how two devices pair ([../Pairing/README.md](../Pairing/README.md)). It does let it supply a passkey (`ProvidePin`). The passkey comes from an ECDH exchange whose keys both sides signed with their certificate keys, so someone between them cannot learn it. LE SC passkey entry with a secret, single-use passkey is MITM-protected: level 4. Passkey entry's weakness, leaking the passkey bit by bit to an active attacker, does not matter here, because each passkey is used once.
- **DisplayOnly by `app_passkey`.** The host link gets its own SMP callbacks through `bt_conn_auth_cb_overlay()`. Its only callbacks are `pairing_accept`, `app_passkey` and `cancel`, which makes the device DisplayOnly (`CONFIG_BT_APP_PASSKEY`). The PC therefore enters the passkey, and the device "shows" the derived one. The peer link keeps `_PAIR`'s global callbacks (OOB). IO capabilities are per link, so pairing with the peer is unchanged.
- **Trust is a bond, not a session.** After the handshake the device keeps nothing but the bond and a 7-byte record. Trust on a later connection needs only the bonded address and level 4, which only the bonded keys can reach. No handshake per connection, no session keys in the application.
- **One host.** The device keeps one host bond (`CONFIG_BT_MAX_PAIRED=4` leaves room for the peer). A second host cannot authenticate while one is bonded. Replacing the host takes physical presence (Button 3 held), so a stolen certificate alone cannot take over a device that already has a host.
- **One gate.** All the host's application traffic enters through the SETU router, so one predicate there covers hex upload, files, UDS and provisioning. The Pairing service is the only other writable entry, and checks the same trust. During a pairing run, the run's filter (peer link) replaces the gate.
- **Provisioning is the bootstrap.** An unprovisioned device has no certificate, so no host can authenticate to it. It accepts only provisioning, and only after a button press opens the window. This is the factory step.
- **One buffer.** HELLO (up to 1106 bytes) is no longer needed once the transcript is made, so CHALLENGE (up to 1170 bytes) is built in the same buffer. The buffer stays reserved until the CHALLENGE transfer ends, even if the handshake fails meanwhile.
- **The window.** Not advertising takes the device off the air for anyone who wants to attack it. The grace window after a trusted host's link loss keeps long operations (an ECU flash job reconnect) working without a hand on the button. A host that fails gets the rest of the window it closed (Windows drops the link when pairing fails), so a retry does not need another press; it cannot stretch the window beyond the press. A bonded pair peripheral still advertises, but directed to its central only.

## Security notes

- **What an untrusted link can do:** the handshake (HELLO is checked, then refused or answered), provisioning's GET_STATUS, the Pairing service's STATUS, the GATT reads of the SETU service (CAPS) and the device information. Nothing that changes the device.
- **Unprovisioned devices** accept provisioning from anyone who connects during a button window, as before. Provision in a controlled place.
- **A stolen host credential** works on devices with no host bonded. It does not work on a device whose host is bonded, without the button. There is no revocation: see Limitations.
- **The device's own key** signs CHALLENGE, as it signs pairing OOB data; the ephemeral ECDH keys are volatile and destroyed at once; the ECDH secret is wiped after the passkey is derived.
- **Replay.** Both nonces and both ephemeral keys enter the transcript, so a recorded handshake does not verify again.

## Integration

- `main()` calls `gi_HostAuth_Init()` after `gi_Pair_Init()` and before `gi_SETURouter_Start()`. It registers the range, installs the gate and the SMP info callbacks. `gi_HostAuthButton_Init()` follows, after `gi_ProvButton_Init()`, which initialises the DK buttons.
- `gv_BLEInitStartAdv()` calls `gv_HostAuth_OnBtReady()` after `settings_load()`, which loaded the record through the module's static settings handler.
- `ConnectionHandling.c` calls `gv_HostAuth_OnHostConnected()` for the host link before it binds SETU, and forwards disconnects and security changes. It advertises undirected only while `gb_HostAuth_WindowOpen()` and no host is connected.
- `_PAIR` asks `gb_HostAuth_IsTrustedConn()` on CONTROL and `gb_HostAuth_IsHostAddr()` when restoring its bond. `_PROV`'s wipe calls `gv_HostAuth_Forget()`.
- Configuration:
  - `_DI/Kconfig` menu "Host authentication": `CONFIG_HOST_AUTH_WINDOW_MS`, `_GRACE_MS`, `_FORGET_HOLD_MS`, `_TIMEOUT_MS`, `_BOOT_WINDOW`, `_STACK_SIZE`.
  - `_DI/prj.conf`: `CONFIG_BT_APP_PASSKEY`, `CONFIG_DK_LIBRARY_DYNAMIC_BUTTON_HANDLERS`, `CONFIG_MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE`, and PSA ECDH, HKDF, HMAC and DERIVE.

## Using it

- **GUI.** The Host access page:
  1. Load the host credential, or issue one from a CA folder.
  2. Press the device's Button 3 and connect (Device page).
  3. Click "Authenticate & pair". Windows pairs without a prompt.

  After that, every page works on that device.
- **CLI.**
  ```
  python setu_client.py hostcert "Service laptop" --ca <CA folder>
  python setu_client.py auth --name ProjectHanuman
  python setu_client.py authstatus --name ProjectHanuman
  ```
- **Orchestrating pairing.** The PC must be the trusted host of **both** devices. The Pairing page's CONTROL writes are refused otherwise (`0x08`, retried briefly while a bonded link encrypts).

## Memory

About 7.9 KB of flash and 9.5 KB of RAM: a 6 KiB stack, the 1170-byte HELLO/CHALLENGE buffer, the event queue (8 events of about 80 bytes) and state. The stack size is an estimate (mbedTLS X.509 verification of the host certificate, PSA, settings), to be checked on the board with the thread analyzer lines in `prj.conf`.

## Testing

| Test | What |
|---|---|
| `_TEST/unit/HostAuth/test_host_auth.c` (`host_auth`) | HostAuth.c with the BT stack, router, SETU, verification and crypto stubbed: the gate in every state, every RESULT, the SMP callbacks, trust (bond + level 4), the record, one host, reconnection, the window, the grace window, forgetting, the wipe, the timeout, the shared buffer |
| `test_host_auth_crypto.c` (`host_auth_crypto`) | HostAuthCrypto.c on the real TF-PSA-Crypto against the Python-made handshake in `wire.json`: T, Z, the passkey, both signatures; altered bytes and swapped roles rejected |
| `test_host_auth_button.c` (`host_auth_button`) | Short press, hold, each press timed on its own, other buttons |
| `_TEST/unit/DeviceCert/test_devicecert_verify.c` | `ge_VerifyHostCertificate()` on the real Mbed TLS with certificates from the PC's CA: roles never mix |
| `_TEST/unit/SETUSvc/test_router.c`, `_TEST/unit/Pair/test_pair.c`, `_TEST/unit/Prov/test_prov.c` | The gate in the router; CONTROL's check and the skipped host bond; the wipe |
| `_TEST/fuzz/fuzz_host_auth.c` | Untrusted host input and link events, with the invariant that only the trusted host passes the gate |
| `_TEST/python/test_host_auth.py`, `test_host_credential.py`, `test_winrt_pairing.py`, `test_feature_host_access.py`, `test_client_cli.py` | The PC side: vectors, a simulated device doing the real cryptography, credentials, Windows pairing on a fake WinRT, the page, the CLI |

## Limitations

- **Windows only** for the pairing step (WinRT `ProvidePin`). On Linux, a BlueZ agent answering `RequestPasskey` would do the same. It is not written.
- **To be proven on hardware:**
  - that Windows runs LE SC passkey entry (not Just Works) against a DisplayOnly device with `ProvidePin`, and pairs without a prompt. If it does not, the fallback is the device as KeyboardOnly (`passkey_entry`, answered with `bt_conn_auth_passkey_entry`);
  - that on a reconnection the link is encrypted before the PC's first write. A write that comes first is refused (REFUSED, or ATT `0x08` on CONTROL, which the pairing orchestrator retries). bleak's service discovery should take longer than the encryption.
- **No revocation, no expiry.** The device has no wall clock and no revocation list ([../Audit/FINDINGS.md](../Audit/FINDINGS.md) F11). A stolen host credential is good for any device without a bonded host until the CA is replaced.
- **Unprovisioned devices are open** to provisioning while the window is open.
- **One host at a time.** A second PC needs the button (the first loses access).
- **The thread's stack** is not measured yet (see Memory).
