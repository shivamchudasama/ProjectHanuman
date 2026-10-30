# CAN — CAN / CAN FD on the nRF54L15 DK (MCP2518FD Click)

The nRF54L15 has no CAN controller. A MikroE **MCP2518FD Click** adds one: a Microchip
MCP2518FD CAN FD controller on SPI, an ATA6563 high-speed transceiver and a 40 MHz
oscillator. Zephyr drives it with its `microchip,mcp251xfd` driver. The application module
[`_ASW/_CAN`](../../_ASW/_CAN) (`CanIf`) is the controller's **one owner**: it sets the mode
and bitrates, starts the controller, follows its error state, and gives the other modules
frame TX and filtered RX.

- **One owner:** only `CanIf` changes the mode and bitrates. Other modules send frames, add
  receive filters and listen to state changes. A protocol that binds to the controller
  itself (Zephyr's ISO-TP) gets it from `gstpt_CanIf_GetDevice()`, but still leaves the
  configuration to `CanIf`.
- **Never block the driver:** the driver calls back on its own cooperative interrupt
  thread. `CanIf` only queues the frame or state change there. Its own thread then calls the
  users, so a slow user can't hold up reception.
- **Built for flashing:** the bitrates and the classic/FD mode change at runtime, because
  every ECU differs. A session can lock the bus configuration, and listeners hear about
  bus-off. The traffic log can be switched off so that it doesn't cost SPI and CPU time
  during a flash.

This is the bottom layer of ECU flashing and diagnostics over UDS (§9, [../UDS/README.md](../UDS/README.md)). Raw CAN frames are not exposed over BLE; UDS is.

## 1. Hardware

### Supply and jumpers

- **Set the DK's VDD to 3.3 V before wiring the click.** Use nRF Connect for Desktop →
  Board Configurator → nRF54L15 DK → VDD 3.3 V. The DK ships at 1.8 V. At that voltage the
  MCP2518FD (2.7 V minimum) does not run, and the click's 3.3 V outputs would drive the
  nRF54L15's pins above its supply.
- The click needs **3.3 V** (from the DK's VDD pin, once set to 3.3 V) and **5 V** for the
  transceiver, from the DK's 5 V header pin or an external supply sharing GND. Check the
  click's schematic for its I/O-level jumper and set it to 3.3 V.
- **Terminate the bus**: 120 Ω between CANH and CANL at each end of the bus (the click's
  termination jumper counts as one end).

### Wiring

SPIM21 on port 1. SPIM2x instances only reach port 1, and SCK must be one of its clock
pins. The DK header leaves only P1.11 and P1.12 free on port 1. The board's own
`nordic_expansion_spi` (spi22 on P1.06/P1.07) clashes with the console UART's RTS/CTS. So
the click takes over **Button 1, Button 2 and LED3**:

| Click (mikroBUS) | DK pin | Was on the DK | Notes |
|---|---|---|---|
| SCK | P1.11 | free | |
| SDI (MOSI) | P1.14 | LED3 | An output: LED3 flickers during SPI traffic |
| SDO (MISO) | P1.09 | Button 1 | Don't press Button 1 while CAN runs |
| CS | P1.08 | Button 2 | Don't press Button 2 while CAN runs |
| INT | P1.12 | free | Pulled up in the devicetree |
| 3V3 | VDD (3.3 V) | | |
| 5V | 5 V | | Transceiver supply |
| GND | GND | | |

**Why INT is on P1.12.** The driver enables INT as a *level* interrupt before it probes
the chip (`mcp251xfd_init()`). If INT reads low with no click fitted, the driver's
cooperative thread, at priority 2, would loop for ever and starve Bluetooth. P1.12 has
nothing else on it and is pulled up, so a missing click leaves INT inactive. An LED pin
could hold the line low through its driver.

**Why the driver starts late.** NCS's `dk_buttons_init()` puts one GPIO callback on the
list of every port that has a button (here port 1 for Button 0 and port 0 for Button 3).
Because a callback is inserted at the head of each list, a port-1 callback added before
it is cut off. If the driver started at boot, its INT callback would be lost, INT's level
interrupt would never be switched off, the GPIO interrupt would never return, and the
hardware watchdog would reset the device about every half second (audit finding F12). So
the `can@0` node has `zephyr,deferred-init`, and `gi_CanIf_Init()`, called after the DK
library, starts the driver.

The overlay deletes the `button_1`, `button_2` and `led_3` nodes and their `sw1`, `sw2` and
`led3` aliases. NCS's DK library builds its button and LED tables from those nodes, so it
leaves the pins alone. Button 0 (`DK_BTN1`, the provisioning wipe) and LED0 (`DK_LED1`,
pairing) keep their indexes. Button 3 becomes `DK_BTN2`, the host window button of host
authentication ([../HostAuth/README.md](../HostAuth/README.md)), and LED1 and LED2 keep theirs
(LED1, `DK_LED2`, shows the host window).

**Transceiver standby.** The ATA6563's STBY pin must be low for the transceiver to drive
the bus. The Zephyr shield for this click leaves it alone. If the controller works (the
self-test passes, §5) but nothing reaches the bus, check the click's schematic. If STBY is
wired to the MCP2518FD's GPIO0, add `xstby-enable;` to the `can@0` node.

## 2. Configuration

**Devicetree** ([`_DI/boards/nrf54l15dk_nrf54l15_cpuapp.overlay`](../../_DI/boards/nrf54l15dk_nrf54l15_cpuapp.overlay),
shared by both `FLASH_IF` variants: the sQSPI flash uses only P2.00–P2.05):

- `spi21` with the pins above, CS on P1.08.
- `mcp2518fd: can@0`: `microchip,mcp251xfd`, `spi-max-frequency` 8 MHz (SPIM21's limit;
  the chip allows 18), `osc-freq` 40 MHz, `int-gpios` P1.12 active-low with pull-up,
  `zephyr,deferred-init` (started by `gi_CanIf_Init()`, see §1), and a `can-transceiver`
  with a 5 Mbit/s limit.
- `chosen { zephyr,canbus = &mcp2518fd; }`. `CanIf` uses the chosen controller.
- The bitrates are not set here; `CanIf` sets them from Kconfig before it starts the
  controller.

**Kconfig** ([`_DI/prj.conf`](../../_DI/prj.conf) "CAN bus", options in
[`_DI/Kconfig`](../../_DI/Kconfig) menu "CAN bus"):

| Option | Value | Meaning |
|---|---|---|
| `CONFIG_CAN`, `CONFIG_CAN_FD_MODE` | y | Zephyr's CAN API with CAN FD. `CAN_MCP251XFD` follows from the devicetree and selects SPI and CRC |
| `CONFIG_CAN_MCP251XFD_INT_THREAD_STACK_SIZE` | 1024 | The driver's thread also runs `CanIf`'s callbacks (default 768) |
| `CONFIG_CANIF` | y | Builds `_ASW/_CAN` (needs `CAN`) |
| `CONFIG_CANIF_FD` | n | Boot mode: classic CAN 2.0, so a classic-only bus monitor sees all the traffic (y: CAN FD). A UDS target can still ask for CAN FD at runtime |
| `CONFIG_CANIF_BITRATE` | 500000 | Boot nominal bitrate |
| `CONFIG_CANIF_BITRATE_DATA` | 2000000 | Boot FD data-phase bitrate (frames with BRS), used only when booting in CAN FD mode |
| `CONFIG_CANIF_LISTEN_ONLY` | n | Boot in listen-only mode: no ACK, no sending |
| `CONFIG_CANIF_SELFTEST` | n | Loopback self-test at boot. **Bench only**: it sends two frames on the bus (§5) |
| `CONFIG_CANIF_LOG_RX` | y | Traffic log on at boot |
| `CONFIG_CANIF_LOG_RX_MAX_PER_SEC` | 20 | Most frames logged per second |
| `CONFIG_CANIF_TEST_TX_PERIOD_MS` | 1000 | Test frame period (0 = off): on for the bench, one a second. **Bench only**: set 0 on a vehicle |
| `CONFIG_CANIF_MAX_FILTERS` | 8 | User filters. Each takes a driver filter, as do the traffic log's two. The `CAN_MCP251XFD_MAX_FILTERS` (16) left over are for ISO-TP. A `BUILD_ASSERT` keeps the sum within the driver's |
| `CONFIG_CANIF_RX_QUEUE_DEPTH` | 16 | Queue between the driver's thread and `CanIf`'s |
| `CONFIG_CANIF_STACK_SIZE`, `CONFIG_CANIF_PRIORITY` | 2048, 6 | `CanIf`'s thread: below the SETU engine (5), above the File System Manager (10) |

Remote frames (RTR) are rejected by the driver unless `CONFIG_CAN_ACCEPT_RTR=y`. They are
not used in CAN FD or UDS.

## 3. Design

| File | Role |
|---|---|
| [`CanIf.h`](../../_ASW/_CAN/CanIf.h) | The API (§4): `CanIfConfig_T`, `CanIfStatus_T`, `CanIfRx_F`, `CanIfState_F` |
| [`CanIf.c`](../../_ASW/_CAN/CanIf.c) | Everything: init and self-test, configuration, send, filters, the queue and thread, the traffic log, the test frames |
| [`CMakeLists.txt`](../../_ASW/_CAN/CMakeLists.txt) | Builds `CanIf.c` only with `CONFIG_CANIF` |

```
 MCP2518FD ──SPI──► driver interrupt thread (coop, prio 2)
                     │  can_add_rx_filter() callbacks, state-change callback
                     ▼  copy only, never block
               k_msgq (CANIF_RX_QUEUE_DEPTH, 2 entries kept for state changes)
                     │
                     ▼
               CanIf thread (prio 6) ──► CanIfRx_F of the matching filter
                                     ──► traffic log (rate-limited)
                                     ──► state log, bus-off count, CanIfState_F listeners
 any thread ──► gi_CanIf_Send() ──► can_send() (blocking)
 any thread ──► gi_CanIf_Configure() ──► stop, mode, bitrates, start (mutex; lock owner)
```

- **Queue with a reserve.** Frames may fill the queue only up to two entries short of its
  depth. A bus-off report therefore always gets through, even during a burst of traffic.
  Frames that find the queue full are counted as dropped (`u32_rxDropped`).
- **Filter slots with a generation.** Each user filter is a slot with a generation number,
  which changes when the slot is taken or freed. A frame is queued with the generation
  current at the time. If the filter is removed before the thread gets to the frame, the
  frame is dropped instead of reaching whoever took the slot next.
- **Configuration.** `gi_CanIf_Configure()` stops the controller, sets the mode and
  bitrates, and starts it again. If the controller refuses any step, the previous
  configuration is put back. Filters and listeners stay through this.
- **Bus lock.** `gi_CanIf_Lock(owner)` reserves the configuration for one session, such as a
  flash job. Anyone else's `gi_CanIf_Configure()` gets `-EBUSY`, and the test frames pause.
  `gi_CanIf_Send()` stays open to everyone: CAN arbitration orders the frames.
- **Traffic log.** Two catch-all driver filters, one for standard and one for extended IDs,
  send every frame on the bus to the log. That costs an SPI read per frame, so the flasher
  should call `gv_CanIf_SetMonitor(false)`.
- **Self-test.** The self-test sends a classic frame and a 64-byte FD frame with BRS, both with
  ID `0x5A5`, in `CAN_MODE_LOOPBACK`. It then checks that they come back unchanged within
  100 ms. Zephyr maps that mode to the MCP2518FD's *external* loopback, which also drives
  TXCAN. So the frames go out on the bus too, and the self-test is off by default. The FD
  frame is sent whenever the build has CAN FD (`CONFIG_CAN_FD_MODE`), even when the boot
  mode is classic, so a classic-only bus monitor reports it as an error.
- **Test frames.** With `CANIF_TEST_TX_PERIOD_MS` set, the system work queue sends ID `0x5A5`
  every period. The frame carries a 32-bit counter and then a byte pattern. In FD mode every
  other frame is a 64-byte FD frame with BRS. The frames are not sent while the controller
  is stopped, in listen-only mode or while the bus is locked.

## 4. API

All functions return `0` or a negative errno. Before `gi_CanIf_Init()` has found the
controller, everything except the lock, the listeners and `gi_CanIf_GetStatus()` returns
`-ENODEV`.

| Function | Contract |
|---|---|
| `int gi_CanIf_Init(void)` | Called once from `main()`, after `dk_buttons_init()`. Starts the deferred driver (`device_init()`; `-EALREADY` from a driver started at boot is fine, another error is logged as `can@0 init failed (…)`), checks the controller is ready and supports the boot mode, runs the self-test if enabled, applies the boot configuration and starts the controller. Then installs the traffic log and schedules the test frames, if enabled. Returns `-EALREADY` on a second call. `-ENODEV`: no controller (click, wiring, supply). `-ENOTSUP`: boot mode FD without an FD controller. `-EIO`: the self-test failed, and the interface stays unusable. If only the start fails, the driver's error is returned and the interface is ready but stopped, so `gi_CanIf_Configure()` can retry. |
| `int gi_CanIf_Configure(const CanIfConfig_T *cfg, const void *owner)` | Applies `{b_fd, b_listenOnly, u32_bitrate, u32_bitrateData}`; `u32_bitrateData` is only used with `b_fd`. Returns `-EINVAL` for NULL or a zero bitrate, `-ENOTSUP` for FD without support, `-EBUSY` while someone other than `owner` holds the lock. Otherwise the driver's error, after the previous configuration has been restored. If restoring fails too, that is logged and the controller stays stopped. |
| `int gi_CanIf_Lock(const void *owner)` / `int gi_CanIf_Unlock(const void *owner)` | Lock: `-EINVAL` for NULL, `-EALREADY` if `owner` holds it, `-EBUSY` if someone else does. Unlock: `-EPERM` if `owner` does not hold it. |
| `int gi_CanIf_Send(const struct can_frame *f, k_timeout_t t)` | Sends from any thread and waits until the frame is on the bus. `t` bounds the wait for a free transmit buffer. Returns:<br>• `-EINVAL`: NULL, flags other than IDE/RTR/FDF/BRS, ID out of range, DLC above 8 (classic) or 15 (FD), RTR+FDF, BRS without FDF.<br>• `-ENOTSUP`: FD frame in classic mode.<br>• `-ENETDOWN`: controller stopped.<br>• `-EACCES`: listen-only.<br>• Otherwise `can_send()`'s error: `-ENETUNREACH` bus-off, `-EAGAIN` timeout, `-EIO`. |
| `int gi_CanIf_AddRxFilter(const struct can_filter *flt, CanIfRx_F cb, void *user)` | Returns a filter id `0..CANIF_MAX_FILTERS-1`. A filter matches standard IDs, or extended IDs with `CAN_FILTER_IDE`, by `(id & mask) == (flt.id & flt.mask)`, classic and FD frames alike. `cb` runs on `CanIf`'s thread, and the frame is valid only during the call. Errors: `-EINVAL` for NULL, `-ENOSPC` when all slots are used, otherwise the driver's error. |
| `int gi_CanIf_RemoveRxFilter(int id)` | Frames already queued for the filter are dropped. `-EINVAL` for an id not in use. |
| `int gi_CanIf_AddStateListener(CanIfState_F cb, void *user)` / `…Remove…` | Up to `CANIF_STATE_LISTENERS` (2). Works before init. The listener is called on `CanIf`'s thread with the new `enum can_state` and the TX/RX error counters. Add: `-EALREADY` for a pair already registered, `-ENOSPC` when full. Remove: `-ENOENT` for an unknown pair. |
| `void gv_CanIf_SetMonitor(bool on)` | Traffic log on or off. Turning it on twice is harmless. |
| `int gi_CanIf_GetStatus(CanIfStatus_T *s)` | Fills in: ready, started, locked, monitor, the configuration, the error state and counters (live from the controller, else the last state `CanIf` knows), frames sent, queued and dropped, and the bus-off count. Returns `-EINVAL` for NULL. |
| `const struct device *gstpt_CanIf_GetDevice(void)` | The controller, or NULL if not ready. |

Bus-off recovery is automatic (`CONFIG_CAN_MANUAL_RECOVERY_MODE` stays off). The
controller returns to ERROR_ACTIVE after 128 × 11 recessive bits, and the listeners hear
both changes.

## 5. Serial output

```
<inf> APP_LOG: sv_LogConfig: can@0 started: classic CAN, 500000 bit/s
<inf> APP_LOG: sv_LogFrame: RX 0x123 [8]
<inf> APP_LOG: RX data
                 11 22 33 44 55 66 77 88                          |"3DUfw.
<inf> APP_LOG: sv_LogFrame: RX 0x18daf110 [64] FD BRS
<inf> APP_LOG: sv_LogFrame: 37 frames not logged
<wrn> APP_LOG: sv_OnState: state ERROR_PASSIVE (tx err 128, rx err 0)
<wrn> APP_LOG: sv_OnState: state BUS_OFF (tx err 255, rx err 0)
```

The device is named after its devicetree node (`can@0`). The "not logged" line comes with
the first frame of the next one-second window. Booting in CAN FD mode (`CONFIG_CANIF_FD=y`),
the first line reads `can@0 started: CAN FD, 500000 bit/s, data 2000000 bit/s`. FD frames,
such as the `[64] FD BRS` line, are received only in CAN FD mode: at boot with
`CONFIG_CANIF_FD=y`, or after a UDS target that asks for CAN FD.

- **No click:** `can@0 init failed (…)` from the driver's start, then `can@0 not ready: check
  the click, its wiring and the DK's VDD (3.3 V)`. The rest of the firmware runs on.
- **Reset loop with the click fitted**, only the driver's `Switched to mode …` lines and
  `reset by watchdog` on the next boot: the INT callback was lost (§1, `zephyr,deferred-init`
  missing or `gi_CanIf_Init()` called before the DK library).
- **Self-test** (`CONFIG_CANIF_SELFTEST=y`, bench only): `loopback self-test passed
  (classic and FD)`. A failure (`loopback self-test failed (-116): …`) usually means MISO,
  MOSI or SCK is wrong, the oscillator is not running, or the click has no supply.

## 6. Memory

On the SPI build: `_ASW/_CAN` takes about 2.9 KB of flash and 3.7 KB of RAM (thread stack,
queue, slots). Zephyr's CAN and MCP251xFD driver add their share to "Other". The whole image
then uses 81% of the RAM, and 87% of the 240 KiB left on the sQSPI build. See the
per-module table after each build ([MemReport](../../_TOOLS/MemReport/README.md)).

## 7. Integration

- Start it from `main()` with `gi_CanIf_Init()`, after the BLE-independent modules and
  before `gi_SETURouter_Start()`. `main.c` calls it only with `CONFIG_CANIF`.
- Call it after `dk_buttons_init()` (`gi_ProvButton_Init()`), and keep `zephyr,deferred-init`
  on the CAN node (§1; a `BUILD_ASSERT` checks it when the DK library is built). Any other
  GPIO callback on port 0 or 1 that must survive the DK library has to be added after it
  too.
- A module that receives: `gi_CanIf_AddRxFilter()` with its IDs, and handle the frames in
  the callback (they arrive on `CanIf`'s thread). A module that sends: `gi_CanIf_Send()`,
  from its own thread.
- A session that must keep the configuration (a flash job): `gi_CanIf_Lock(self)`, then
  `gi_CanIf_Configure(&cfg, self)`, `gv_CanIf_SetMonitor(false)` and
  `gi_CanIf_AddStateListener()` to abort on bus-off. Undo all of that at the end.

## 8. Limitations

- SPI at 8 MHz: each received FD frame costs an SPI read of about 80 bytes on the driver's
  cooperative thread. A heavily loaded 2 Mbit/s FD bus takes a noticeable share of the
  CPU, so keep the traffic log off when that matters.
- The controller's receive FIFO holds 16 frames (`CAN_MCP251XFD_RX_FIFO_ITEMS`), and
  `CanIf`'s queue 14 (16 minus the state reserve). Bursts beyond that are dropped and
  counted.
- `gi_CanIf_Send()` blocks until the frame is on the bus. There is no asynchronous send
  yet.
- No receive timestamps (`CONFIG_CAN_RX_TIMESTAMP` is off).
- The self-test and the test frames transmit on whatever bus is connected. Keep both off
  on a vehicle; `prj.conf` currently sends a test frame every second for the bench.
- Raw CAN frames are not exposed over BLE (UDS is, [../UDS/PROTOCOL.md](../UDS/PROTOCOL.md)).
  The host tests cover `CanIf` against a scripted controller; only the click itself needs the
  board (the manual `hil-uds-tests` job is a placeholder).

## 9. UDS on top: ECU flashing and diagnostics

The device flashes and diagnoses ECUs itself, triggered over BLE ([../UDS/README.md](../UDS/README.md)):

1. A remote client uploads the ECU image over SETU. The hex upload with `--store` writes it to
   `/FLASH_DISK:/FW/<name>`, one `[address][length][data]` record per segment. Those records map
   directly onto UDS RequestDownload (address and length) and TransferData blocks.
2. The same or another client triggers the flash over BLE with SETU appTypes `0x50`–`0x5F`
   ([../UDS/PROTOCOL.md](../UDS/PROTOCOL.md)). The router now has 5 route slots.
3. The device runs UDS over ISO-TP over CAN/CAN FD on its own:
   - Zephyr's ISO-TP (`CONFIG_ISOTP`) is bound to `gstpt_CanIf_GetDevice()`.
   - The UDS client is [`_LIB/UdsClient`](../../_LIB/UdsClient).
   - The job engine [`_ASW/_UDS`](../../_ASW/_UDS) has an API that does not depend on BLE.

   For a flash job, the engine locks the bus (`gi_CanIf_Lock()`), configures it for the ECU,
   turns the traffic log off and listens for bus-off. A touchscreen front-end can later call the
   same API.

ISO-TP is not tunnelled over BLE: the connection interval would slow every flow-control round
trip, and a flash must not depend on the phone or PC staying connected.

## 10. Tests

[`_TEST/unit/CanIf/test_canif.c`](../../_TEST/unit/CanIf/test_canif.c) runs `CanIf.c`
against a scripted controller that implements Zephyr's CAN API
([`shim/zephyr/drivers/can.h`](../../_TEST/shim/zephyr/drivers/can.h)). Two builds:

- `canif`: CAN FD, self-test and traffic log on.
- `canif_classic`: a CAN 2.0 build with both off.

The tests cover:

- init: the deferred driver started first (or already started at boot), no controller, no
  FD, start failure, listen-only;
- every self-test failure;
- frame validation and send errors;
- filter matching, limits and removal with frames still queued;
- the queue's reserve for state changes;
- state logging, bus-off count and listeners;
- the traffic log's rate limit and runtime switch;
- configuration with rollback;
- the lock;
- the test frames.
