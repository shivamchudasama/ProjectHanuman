# EcuSim — a UDS ECU simulator for the bench

`ecu_sim.py` plays the ECU that Project Hanuman flashes and diagnoses
([_DOC/UDS/README.md](../../_DOC/UDS/README.md)). It is a UDS server (ISO 14229) over
ISO-TP (ISO 15765-2) on a PC with a USB-CAN adapter, on the same bus as the DK with its
MCP2518FD Click. It answers the device's generic programming sequence, keeps the image it
receives, and answers a few diagnostics. It needs no real ECU and no OEM seed→key algorithm.

```
PC: setu_client.py / BLE Host GUI ──BLE──► DK (UdsJob) ──CAN──► USB-CAN adapter ──► PC: ecu_sim.py
```

## Running it

```sh
pip install -r _TOOLS/EcuSim/requirements.txt          # python-can, can-isotp
python _TOOLS/EcuSim/ecu_sim.py --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 --out flashed.bin
```

Then, from the BLE side:

```sh
python _TOOLS/BleHostGUI/setu_client.py hex app.hex --store APP1.BIN --name "ProjectHanuman"
python _TOOLS/BleHostGUI/setu_client.py flash APP1.BIN --profile _TOOLS/EcuSim/profiles/sim.json --name "ProjectHanuman"
python _TOOLS/BleHostGUI/setu_client.py fs get /FW/APP1.BIN app1.bin --name "ProjectHanuman"
```

Or from the GUI's ECU page (_TOOLS/BleHostGUI/README.md): **Load…** `profiles/sim.json` (the
simulator's profiles are in the format the page saves), **Apply target**, then Flash.

`flashed.bin` (written after every RequestTransferExit) then equals `app1.bin`. Both are
records `[u32 LE address][u32 LE length][data]`, the layout the device stores.

| Option | Default | Meaning |
|---|---|---|
| `--interface`, `--channel` | `virtual`, `test` | python-can interface: `pcan`, `kvaser`, `slcan`, `gs_usb` (candleLight), `vector`, `socketcan`, `virtual` |
| `--bitrate` | 500000 | Nominal bitrate |
| `--fd`, `--brs`, `--data-bitrate` | off, off, 2000000 | CAN FD: 64-byte ISO-TP frames, bit-rate switching. Use the profile `profiles/sim_fd.json` on the device side |
| `--bus-arg KEY=VALUE` | | Extra python-can bus option, repeatable. CAN FD on most adapters needs its timing, e.g. PCAN `--bus-arg f_clock_mhz=80 --bus-arg nom_brp=...`; see python-can's documentation of the interface |
| `--rx`, `--tx`, `--functional` | 0x7E0, 0x7E8, 0x7DF | Request, response and functional request IDs |
| `--ext-ids` | off | 29-bit identifiers |
| `--out FILE` | | Write the received image |
| `--seed HEX` | 11223344 | The SecurityAccess seed |
| `--max-block N` | 0x0FFA | maxNumberOfBlockLength in RequestDownload answers |
| `--pending N` | 1 | NRC 0x78s before entering the programming session |
| `--nrc-at SID:NRC` | | Answer the first request of SID with that NRC, e.g. `36:72` |
| `--slow-erase S` | 0 | The erase routine takes S seconds (an NRC 0x78 first) |
| `--drop-at-block N` | | Leave TransferData block N unanswered (the device times out) |
| `--quiet` | | Do not print the requests and responses |

## What it implements

| Service | Behaviour |
|---|---|
| 0x10 DiagnosticSessionControl | 01, 02, 03. Answers P2 = 50 ms, P2* = 5 s. Entering 02 sends `--pending` NRC 0x78 first and locks security again |
| 0x11 ECUReset | Back to the default session, locked |
| 0x27 SecurityAccess | Not in the default session (NRC 0x7F). Seed `--seed`, key = BENCH_XOR (the device's algorithm 1, `_ASW/_UDS/UdsKey.c`). A wrong key gives 0x35; the third gives 0x36 and locks it. A zero seed once unlocked. Key before seed: 0x24 |
| 0x28, 0x85, 0x3E | Positive answers; 0x3E 80 and 0x85 82 suppress them |
| 0x22 / 0x2E | F190 VIN (`WMI0HANUMAN000001`), F15A fingerprint (writing needs programming session + unlocked, else 0x33); other DIDs 0x31 |
| 0x31 RoutineControl | 01 FF00 erase (any arguments); 01 FF01 check: status 00 if the CRC-32 argument matches the received data (or there is none), else 01. Programming session + unlocked |
| 0x34 / 0x36 / 0x37 | One download at a time (0x22). Block counter checked (0x73), block length checked (0x71), sequence checked (0x24). A record is kept when its RequestTransferExit comes with all its bytes |
| 0x19 02 / 0x14 | Two fake DTCs, filtered by the status mask; cleared by 0x14 |
| anything else | NRC 0x11 (nothing for a functional request) |

Functional requests (`--functional` ID) are answered on the response ID. A suppressed positive
response (bit 7 of the sub-function) is not sent.

## Structure

- `EcuSim` is the ECU without CAN. `handle(request)` returns `[(delay, response), ...]`, so
  the tests drive it directly.
- `make_stacks()` builds can-isotp `NotifierBasedCanStack`s for the physical and functional
  IDs on one python-can bus. `serve()` answers requests until stopped.
- `main()` is the command line.

## Tests

[`_TEST/python/test_ecu_sim.py`](../../_TEST/python/test_ecu_sim.py):
- **Golden conversation:** the simulator replays the `uds_flash` conversation of
  `_TEST/vectors/wire.json` request by request. The firmware's flasher test (`uds_job`) plays
  the device's side of the same conversation, so the two cannot drift apart.
- **BENCH_XOR:** checked against the `uds_key` vectors.
- **Services and faults:** every service, every refusal and the fault injection.
- **On a CAN bus:** the simulator runs on python-can's `virtual` bus with a can-isotp tester,
  classic and CAN FD, including a segmented response.

[`test_uds_protocol.py`](../../_TEST/python/test_uds_protocol.py) uses it as the ECU behind
the fake device to test `setu_client.py flash` end to end.
