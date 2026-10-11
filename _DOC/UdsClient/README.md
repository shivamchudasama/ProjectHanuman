# UdsClient — UDS tester over ISO-TP (Zephyr)

UdsClient is the **tester side** of UDS (ISO 14229-1, Unified Diagnostic Services). It sends
a request to an ECU, waits for the response that answers it, and returns the outcome:
positive, the negative response code (NRC), or why nothing usable came back. Requests
travel over a **transport** (`UdsTp_T`). The one in this library, `UdsTp_Isotp.c`, runs on
Zephyr's ISO-TP (ISO 15765-2, `CONFIG_ISOTP`) on the device's CAN / CAN FD controller.

Zephyr has ISO-TP but no UDS, so this library provides UDS itself. It is generic: it knows
nothing about files, BLE or flash jobs. The application's flasher and diagnostic front-end
([`_ASW/_UDS`](../../_ASW/_UDS), [../UDS/README.md](../UDS/README.md)) are built on top of
it.

- **Request → matching response.** A response belongs to a request when it has the
  request's SID + 0x40 and, for services with a sub-function, echoes the sub-function. A
  negative response belongs to it when it is `7F <SID> <NRC>`. Anything else (a late answer
  to an earlier request, another service's answer) is skipped. Stale responses are drained
  before every request.
- **ISO 14229 timing.**
  - The client waits P2 for a response, and P2* after each NRC 0x78
    (requestCorrectlyReceived-ResponsePending), up to 100 times.
  - It repeats the request after NRC 0x21 busyRepeatRequest (`UDS_BUSY_RETRIES` times).
  - It takes the ECU's P2/P2* from each DiagnosticSessionControl response, plus a 50 ms
    margin, unless the target overrides them.
- **Keep-alive without a timer of its own.** A non-default session needs TesterPresent
  (`3E 80`) within S3 (5 s). `gi32_UdsClient_KeepAlive()` sends it when the client has been
  idle for `UDS_TESTER_PRESENT_MS`, and returns when to call it next. The owner calls it
  from its own thread.

  There is deliberately no timer: Zephyr's ISO-TP runs its state machine on the **system
  work queue**. A blocking send made from a work item would wait for itself there.
- **The services ECU programming needs** as helpers that build the request and check the
  answer:
  - session and reset: DiagnosticSessionControl, ECUReset;
  - security: SecurityAccess, with a seed→key callback;
  - communication: CommunicationControl, ControlDTCSetting;
  - data: Read- and WriteDataByIdentifier;
  - RoutineControl;
  - download: RequestDownload (parses maxNumberOfBlockLength), TransferData (block counter
    checked, no copy), RequestTransferExit;
  - TesterPresent.

  Anything else goes through `gi_UdsClient_Request()`.

## Structure

| File | Role |
|---|---|
| [`UdsClient_Types.h`](../../_LIB/UdsClient/UdsClient_Types.h) | `UdsTarget_T` (IDs, `UDS_TGT_*` flags, frame length, timing overrides), `UdsTp_T` (the transport interface), `UdsKey_F`, SIDs and NRCs |
| [`UdsClient_Config.h`](../../_LIB/UdsClient/UdsClient_Config.h) | Tunables (Kconfig values when defined): P2, P2*, margin, keep-alive period, busy retries, pending limit, buffer size |
| [`UdsClient.h`](../../_LIB/UdsClient/UdsClient.h) / [`.c`](../../_LIB/UdsClient/UdsClient.c) | `UdsClient_T`, the request/response engine and the service helpers |
| [`UdsTp_Isotp.h`](../../_LIB/UdsClient/UdsTp_Isotp.h) / [`.c`](../../_LIB/UdsClient/UdsTp_Isotp.c) | The transport on Zephyr's ISO-TP |
| [`CMakeLists.txt`](../../_LIB/UdsClient/CMakeLists.txt) | Builds the sources only with `CONFIG_UDS` |

## Design

**One owner, blocking calls.** A client belongs to one thread, which calls it and is blocked
until the answer (or P2/P2*) comes. That keeps the timing rules in one straight line of
code. The flasher's thread can simply run one step after the other. The client has no lock;
two threads must not share one.

**Transport as an interface.** `UdsTp_T` has four functions: bind to a target, unbind, send
one request, and receive one whole message. The client never sees CAN frames, so the
host tests drive it with a scripted transport. Another transport (DoIP, a K-line adapter)
could replace ISO-TP without touching the client.

**ISO-TP details.**
- Binding listens on the response identifier with flow control BS = 0, STmin = 0: the ECU
  sends a long response without waiting. The client's own flow-control frames go out on the
  request identifier.
- A send is a blocking `isotp_send()`.
- `isotp_recv()` hands a long message over in pieces. So a message that does not fit the
  buffer is drained and reported as `-EMSGSIZE`; its rest never passes for the next response.
- Functional requests (to all ECUs) are limited to one single frame (7 bytes), as ISO 15765-2
  requires.
- Padding is Zephyr's: `CONFIG_ISOTP_ENABLE_TX_PADDING` pads with 0xCC.
- Extended addressing (`UDS_TGT_EXT_ADDR`) is reserved and refused (`-ENOTSUP`).

**Return values.** Every request function returns:
- `0` for a positive response;
- the **NRC** (1..255) for a negative one;
- a **negative errno** when no usable answer came.

A caller can therefore tell "the ECU said no" from "the ECU said nothing".

## Integration

1. Enable `CONFIG_ISOTP` (and `CONFIG_UDS`, which builds the sources), see `_DI/prj.conf`
   "UDS".
2. Make the transport and the client, once:
   ```c
   static UdsTp_T sst_tp;
   static UdsTpIsotp_T sst_tpCtx;
   static UdsClient_T sst_uds;

   gv_UdsTpIsotp_Init(&sst_tp, &sst_tpCtx, gstpt_CanIf_GetDevice());
   gi_UdsClient_Init(&sst_uds, &sst_tp);
   ```
3. Point it at an ECU: `gi_UdsClient_SetTarget(&sst_uds, &target)` (e.g. 11-bit
   `0x7E0`/`0x7E8`, functional `0x7DF`). The CAN bitrate and mode are `CanIf`'s business
   (`gi_CanIf_Configure()`), not the client's.
4. Call services from the owning thread, and `gi32_UdsClient_KeepAlive()` whenever its
   returned time is up while waiting for other work.

## Memory

A `UdsClient_T` is about 160 bytes, with two 64-byte buffers (`UDS_CLIENT_BUF_SIZE`), and a
`UdsTpIsotp_T` a few hundred. The caller provides the buffers for long responses and
TransferData blocks. ISO-TP's own receive buffers are set by `CONFIG_ISOTP_RX_BUF_*`.

## Limitations

- Tester side only (no UDS server).
- No extended or mixed addressing; normal (and, through 29-bit IDs, normal fixed)
  addressing only.
- Functional requests take the first response; responses of further ECUs are drained before
  the next request.
- No UDS-on-CAN `0x29` Authentication or secured data transmission.
- `-ETIMEDOUT` covers both "no response within P2/P2*" and ISO-TP's own N_As/N_Bs/N_Cr
  timeouts.

## Tests

- [`_TEST/unit/UdsClient/test_uds_client.c`](../../_TEST/unit/UdsClient/test_uds_client.c),
  against a scripted transport ([`sim_uds_tp.h`](../../_TEST/unit/UdsClient/sim_uds_tp.h);
  responses released after a given request, with delays, on simulated time). It covers:
  - matching and NRCs;
  - P2 timeouts, NRC 0x78 chains up to P2*, NRC 0x21 retries;
  - stale and foreign responses;
  - the sub-function echo, suppressed positive responses, functional requests;
  - the ECU's session timing and the keep-alive;
  - each helper's request bytes, answer checks and errors.
- [`test_uds_tp_isotp.c`](../../_TEST/unit/UdsClient/test_uds_tp_isotp.c), against recording
  fakes of Zephyr's ISO-TP API ([`shim/zephyr/canbus/isotp.h`](../../_TEST/shim/zephyr/canbus/isotp.h)).
  It covers the addresses and flow-control options, physical and functional sends, receiving
  whole messages (an oversized one drained) and the error mapping.

The exact contract is in [API_REFERENCE.md](API_REFERENCE.md).
