# Device Pairing (certificate-based OOB pairing)

Two provisioned devices pair with each other through **LE Secure Connections OOB pairing, authenticated by their device certificates**. This is phase 2 of [`_DOC/CBAP`](../CBAP/) (AN1396 §4.2). Each device proves who it is with the certificate it received in provisioning ([../Provisioning/README.md](../Provisioning/README.md)), then signs its OOB data with the key that certificate carries. The pairing that follows is authenticated (level 4) by data that only that device could have signed. A PC host orchestrates the run and watches both devices. The wire contract is [PROTOCOL.md](PROTOCOL.md).

## How it works

1. The host (GUI Pairing page, or `setu_client.py pair`), the trusted host of both devices ([../HostAuth/README.md](../HostAuth/README.md)), connects to both (the GUI uses the links its Device page holds, and keeps them afterwards) and reads their STATUS: both must be provisioned, neither in a run, and not already paired with each other (to pair them again, unpair one of them first). It then tells each device its role and its peer's address (CONTROL START).
2. The peripheral advertises directed to the central, the central scans for it, and they connect. Each device now has two links: its host link and its peer link.
3. Each moves its SETU Server and Client to the peer link, and limits that link to the pairing appTypes. Each sends its device certificate and verifies the peer's against its own CA.
4. Each makes fresh OOB data (`r`, `c`), signs `r ‖ c ‖ own address ‖ peer address` with its device key and sends it. The peer verifies the signature with the key from the certificate it has just verified.
5. The central starts LE Secure Connections pairing at level 4. Both devices give SMP both OOB data sets, so the stack completes the OOB method only with the device that made the signed `c`. The bond is stored.
6. The central writes SECURED on the peer, which the stack allows only on a level-4 link, and the peripheral lights its LED (LED0 on the DK). Both save the bond record (role, peer) and report PAIRED to the host, which may now disconnect. The peer link stays up.
7. Whenever the peer link is down later, after a reset or a lost link, the pair reconnects by itself: the peripheral advertises directed to its central, the central finds it, connects and encrypts with the stored keys. At level 4, both blink their LED for as long as the link is up.

## Files

| File | Role |
|---|---|
| [_PAIR/Pair.c](../../_ASW/_PAIR/Pair.c), [Pair.h](../../_ASW/_PAIR/Pair.h) | The state machine on its own thread: CONTROL commands, STATUS, advertising and scanning, the peer link, SETU moves and the router filter, certificate and OOB exchange, SMP callbacks (`pairing_accept`, `oob_data_request`, `pairing_complete`, `pairing_failed`), SECURED, timeouts, UNPAIR, the wipe, the bond record in settings (`pair/peer`) and bond restore at boot, the bonded reconnection (scan and connect, or wait for the central; level 4 required) and the LED (steady after pairing, blinking on a reconnected link) |
| [_PAIR/PairOob.c](../../_ASW/_PAIR/PairOob.c), [PairOob.h](../../_ASW/_PAIR/PairOob.h) | The signed OOB frame: `gt_PairOob_Sign()` and `gt_PairOob_Verify()` (PSA ECDSA P-256 SHA-256, raw r ‖ s) |
| [_PAIR/PairSvc.c](../../_ASW/_PAIR/PairSvc.c), [PairSvc.h](../../_ASW/_PAIR/PairSvc.h) | The Pairing GATT service (CONTROL, STATUS + CCC, SECURED with `BT_GATT_PERM_WRITE_LESC`) on GATT_CB; forwards to Pair.c; `gi_PairSvc_NotifyStatus()` |
| [_BLE/ConnectionHandling.c](../../_ASW/_BLE/ConnectionHandling.c) | Host link vs peer link (`gb_Pair_ClaimConn()`), per-link PHY/DLE/MTU negotiation, advertising (undirected while the host window is open; directed to the central while a bonded peripheral awaits it, `gb_Pair_AwaitsBondedPeer()` / `gb_Pair_GetBondedPeer()`), security changes to `gv_Pair_OnSecurityChanged()`, `settings_load()` for the bonds and the bond record |
| [_SETU_SVC/SETURouter.c](../../_ASW/_SETU_SVC/SETURouter.c) | The appType filter (`gv_SETURouter_SetFilter()`), and the shared Client: `gi_SETURouter_ClientAttach()` and TX results routed by appType |
| [_LIB/SETU](../../_LIB/SETU) | `gi_SETUS_Rebind()` and `gi_SETUC_Detach()` move the roles between live links ([../SETU/README.md](../SETU/README.md)) |
| [_DEVICE_CERT/DeviceCert_Verify.c](../../_ASW/_DEVICE_CERT/DeviceCert_Verify.c) | `ge_VerifyRemoteDeviceCertificate()`: the peer certificate against the CA, profile, and import of the peer key (volatile; Pair.c destroys it) |

## Design decisions

- **Two channels.** The host talks to the device over the Pairing service, not SETU. Each SETU role binds one link at a time, and during a run both roles serve the peer, while the host still has to see every step. STATUS is a notified characteristic, so the host needs no request to follow the run.
- **SETU between the devices.** The certificates (up to 1 KiB) and the OOB frames are pushed as SETU transfers. The reference read GATT characteristics in fixed blocks instead. Pushing removes that reference's race, where a peer could read the OOB characteristic before it was written. It also reuses the transport, CRC and retransmission the project already tests.
- **Roles move, then come back.** At link-up the router filter is set first, then the Server is rebound to the peer and the Client is attached there through the router. When the run ends, successfully or not, the filter is cleared, the Server is rebound to the host link and the Client is released. Both moves are refused in the middle of a transfer, which never happens at those points.
- **The router shares the Client.** Provisioning (CSR to the PC) and pairing both send with the one SETU Client. The router routes TX results by appType range and attach results to the module that asked. `gi_SETURouter_ClientAttach()` moves the Client from another link when needed.
- **SMP only where it belongs.** `pairing_accept` (`CONFIG_BT_SMP_APP_PAIRING_ACCEPT`) allows pairing only on the peer link of a run whose peer certificate has verified. The host link has SMP callbacks of its own (`_HOST_AUTH`, `bt_conn_auth_cb_overlay()`): it pairs only after host authentication, with passkey entry ([../HostAuth/README.md](../HostAuth/README.md)). The OOB flag (`bt_le_oob_set_sc_flag()`) is set only between certificate verification and the end of the run. `oob_data_request` is answered only on the peer link and only with both data sets, and is cancelled otherwise.
- **Deferred OOB answer.** SMP may ask for OOB data before the peer's frame has verified. The answer (`bt_le_oob_set_sc_data()`) is given as soon as both are true, and the stack waits for it. The OOB structures are static, because the stack keeps pointers to them until pairing ends.
- **Proof of the link.** Pairing only counts once the central has written SECURED, a characteristic with `BT_GATT_PERM_WRITE_LESC`. The write fails on any link below level 4, so PAIRED means the encrypted, authenticated link carries traffic. This is the AN1396 demo's "write a characteristic that can only be written via an authenticated connection".
- **Fresh pairing.** START deletes an older bond with the same peer, so the run always pairs with this run's OOB data and never re-encrypts with an old key. Bonds are stored with the settings on ZMS (`CONFIG_BT_SETTINGS`). A device that is not provisioned deletes its bonds at boot, and a provisioning wipe deletes them all: they belong to the identity it destroys.
- **Advertising follows provisioning.** A provisioned device advertises the Pairing service and has it in its GATT table, which is how the GUI's Pairing page tells the connected boards it can pair. Other devices advertise SETU for provisioning. Only one 128-bit UUID fits in 31 bytes beside the flags. Undirected advertising runs only while the host window is open (Button 3) and no host is connected, and never while the peripheral advertises directed to its peer in a run. A bonded peripheral whose central is away must stay reachable: it advertises directed to that central.
- **Reconnection without the host.** A bonded pair reconnects on its own, after a reset or a lost link, so the link comes back without a PC. The role is not part of Zephyr's bond, so each device saves a bond record `[role][peer address]` in settings next to it, and restores the peer from that record (not from the first bond the stack lists). The peripheral advertises directed (low duty cycle) to its central, so that nobody else can connect outside the host window; with the window open it advertises undirected, which serves both. The central scans and connects as in a run, then only requests level 4: the stack encrypts with the stored LTK. Both require level 4 within 10 s, else they drop the link, and the central retries 1 s after every drop or failure. SETU is not moved to a reconnected link, and STATUS stays PAIRED, since nothing is exchanged over it yet.
- **One LED writer.** The LED is written only by a work item that applies the wanted mode (off, steady, blinking) and re-arms itself while blinking, so the pairing thread never races the blink.
- **Link budget.** The controller reserves links per role: two peripheral links (host + peer as peripheral) and one central link (peer as central), so `CONFIG_BT_MAX_CONN=3` with `CONFIG_BT_CTLR_SDC_PERIPHERAL_COUNT=2`. The application keeps at most one host and one peer link.

## Security notes

- **Who can pair.** Only a device whose certificate chains to the same CA, within the profile (P-256, ecdsa-with-SHA256, CA:FALSE, KeyUsage digitalSignature + keyAgreement), and that signed this run's OOB data for this device's address with that certificate's key.
- **Why the OOB data authenticates.** `c` commits to the sender's SMP public key. A man in the middle cannot complete OOB pairing without a `c` that matches its own SMP key, and it cannot sign one with the device's certificate key.
- **What a peer device can do.** Only the pairing range is reachable on the peer link (router filter). CONTROL refuses writes from the peer link, and SECURED is accepted only from the peer link during a run. A peer cannot upload hex, provision, wipe, or start, cancel or unpair a run.
- **Reconnection.** Only the bonded peer's address is claimed as the peer link, and the link counts only once the stack has encrypted it at level 4 with the bonded keys, which a device with that address but without the keys cannot do; it is dropped after 10 s otherwise. Pairing stays refused outside a run, so a reconnection never creates new keys.
- **Only the trusted host drives pairing.** CONTROL answers ATT `0x08` Insufficient Authorization to any link but the device's trusted host ([../HostAuth/README.md](../HostAuth/README.md)): an authenticated, bonded host at level 4. The pairing itself cannot be faked by the host either: it only chooses who pairs with whom. STATUS stays readable by anyone connected.
- **The host's bond is not the peer's.** The bond restore at boot skips the trusted host's bond (`gb_HostAuth_IsHostAddr()`), and UNPAIR deletes only the peer's.

## Provenance

The flow follows the BG22/BG24 reference in `Sample Code Device Cert Verification`: `PairingFSM.c`, `ReadDeviceCertFSM.c` and `gatt_configuration.btconf`. The GATT service shape follows `Sample Code/_ASW/_GATT_DB/_OOB_PAIRING`. The reference is a custom scheme, not Silicon Labs' CBAP component. What was kept, and what changed:

| Reference | Here |
|---|---|
| Host (EOL tool) writes role, target address and trigger to separate characteristics | One CONTROL write: `[START][role][address]` |
| Directed low-duty advertising to the target; central scans and matches the address | Same |
| Certificate read by GATT in 192-byte blocks, only blocks 1–4 (768 bytes) | Pushed as one SETU transfer, up to 1024 bytes |
| `PairingFSM` stalled after reading the certificate (handlers without return values) | One state machine on one thread, every event handled |
| OOB data written to a characteristic the peer may read before it is filled | Pushed once made, after the sender's certificate is acknowledged |
| Signature over `r ‖ c` | Over `r ‖ c ‖ sender ‖ receiver` (the frame cannot be reused for another device) |
| `st_SignOOBData` returned an uninitialised status on a NULL argument | `PSA_ERROR_INVALID_ARGUMENT` |
| `gt_VerifyRemoteDeviceCertificate` returned OK after a failed mbedTLS call; peer key never destroyed | Each failure has its status; the peer key is destroyed at the end of every run |
| `sl_bt_sm_configure(OOB from both devices)`; no bonding; completion only from a connection-parameters event | OOB required from both (`BOTH_PEERS`), level 4 and a bond required, SMP results handled, and the link proven by SECURED |
| Peer address type assumed public | Taken from the peer's own STATUS |

## Integration

- `main()` calls `gi_Pair_Init()` after `gi_ProvButton_Init()` and before `gi_SETURouter_Start()`. It registers the range `0x30`–`0x3F`, the SMP callbacks and the LEDs.
- `gv_BLEInitStartAdv()` calls `settings_load()` after `bt_enable()` (Pair.c's static settings handler reads the bond record), then `gv_Pair_OnBtReady()`, which learns the own address, restores or deletes bonds and starts reconnecting.
- The connected callback offers every connection to `gb_Pair_ClaimConn()` first; disconnects go to `gv_Pair_OnDisconnected()` and security changes to `gv_Pair_OnSecurityChanged()`. While `gb_Pair_AwaitsBondedPeer()`, advertising runs directed to `gb_Pair_GetBondedPeer()`, also with a host connected, and is resumed after each new connection.
- `gt_Pair_OnControlWrite()` asks `_HOST_AUTH`'s `gb_HostAuth_IsTrustedConn()`; `sv_BondFound()` asks `gb_HostAuth_IsHostAddr()`.
- `_PROV` refuses a wipe during a run (`gb_Pair_IsRunning()`), calls `gv_Pair_ForgetBonds()` after one, and `gv_BLE_RefreshAdv()` when the device becomes provisioned or is wiped.
- Configuration: `_DI/prj.conf` section "Bluetooth" (central role, link counts, SMP, bonds), `_DI/Kconfig` menu "Device pairing" (`CONFIG_PAIR_TIMEOUT_MS`, `CONFIG_PAIR_CONNECT_TIMEOUT_MS`).

## Testing

| Test | What |
|---|---|
| `_TEST/unit/Pair/test_pair.c` (`pair`) | Pair.c with everything around it stubbed: CONTROL validation and its trusted-host check, the host's bond skipped at restore, the bonded peer's address for directed advertising, both roles to PAIRED, every error and detail, guards on objects, SMP and SECURED, timeouts, link loss, CANCEL, UNPAIR, wipe, bond restore, STATUS against `wire.json`; the bond record (saved, loaded, checked, stale), the reconnection in both roles (scan, connect, level 4, retries, refused links, START/UNPAIR/wipe stopping it) and the LED (steady, blinking, off) |
| `_TEST/unit/Pair/test_pair_oob.c` (`pair_oob`) | PairOob.c on the real TF-PSA-Crypto: sign and verify, the vector signed by Python verifies, every altered byte and swapped address is rejected |
| `_TEST/unit/Pair/test_pair_e2e.c` (`pair_e2e`) | Real SETU (both roles) + router + Pair.c over the simulated link, the scripted peer as the other device: roles move to the peer and back, both objects cross intact, the filter refuses other appTypes |
| `_TEST/unit/SETUSvc/test_router.c`, `_TEST/unit/SETU/test_engine.c` | Filter, shared Client, `gi_SETUS_Rebind()`, `gi_SETUC_Detach()` |
| `_TEST/python/test_pairing.py`, `test_feature_pairing.py` | The host side: codec against `wire.json`, the orchestrator, the GUI page |
| `hil-pair-tests` (manual, two DKs) | The radio: directed advertising, the connection, SMP OOB pairing, the bond after a reset. The reconnection and the blinking LEDs are checked by eye |

`ConnectionHandling.c` and `PairSvc.c` only call the BT stack and are covered by the firmware build and `hil-tests`.

## Limitations

- **One peer.** A device pairs with one peer at a time. A new START drops the previous peer link (the bond with it stays until UNPAIR or a wipe).
- **Reconnection is link only.** A reconnected pair is encrypted at level 4 but exchanges nothing yet, and STATUS does not tell the host whether the link is up (the LEDs do). A central that kept its bond while the peripheral lost its own retries every second for as long as it is PAIRED; it stops on UNPAIR. A bond made by firmware without the bond record is not reconnected (pair again).
- **Identity addresses only.** Privacy is off, so the identity address is the one on air. The scanner uses it too (`CONFIG_BT_SCAN_WITH_IDENTITY=y`): by default Zephyr scans from a non-resolvable private address while the device does not advertise, which it doesn't while a host is connected, and the controller then drops the peer's directed advertising, so both devices time out in ARMED (error 4, detail 1). With privacy (RPAs), directed advertising and the address checks would need the peer's IRK.
- **No validity dates or revocation.** As in provisioning, the device has no wall clock, so certificate expiry is not checked and there is no revocation list.
- **The host must be each device's trusted host**: to pair two devices, authenticate the PC to both first (Host Access page).
- **Hardware-only parts** (directed advertising between two DKs, the SMP OOB exchange with real keys, the bond surviving a reset, the reconnection and its encryption with the stored keys) are proven only by a run on two boards.
