# UdsClient — API Reference

The exact contract of [`_LIB/UdsClient`](../../_LIB/UdsClient). Design and integration are in
[README.md](README.md).

| Header | Contents |
|---|---|
| [UdsClient.h](../../_LIB/UdsClient/UdsClient.h) | `UdsClient_T` and every client function |
| [UdsClient_Types.h](../../_LIB/UdsClient/UdsClient_Types.h) | `UdsTarget_T`, `UDS_TGT_*`, `UdsTp_T`, `UdsKey_F`, SIDs and NRCs |
| [UdsClient_Config.h](../../_LIB/UdsClient/UdsClient_Config.h) | Tunables |
| [UdsTp_Isotp.h](../../_LIB/UdsClient/UdsTp_Isotp.h) | `UdsTpIsotp_T`, `gv_UdsTpIsotp_Init()`, `gi_UdsTpIsotp_Errno()` |

## 1. Return values

Every function that sends a request returns:

| Value | Meaning |
|---|---|
| `0` | Positive response (or, for a suppressed positive response, none within P2) |
| `1`..`255` | The ECU's **NRC**: `7F <SID> <NRC>`. Never `0x78` or `0x21` while the client still handles them (see §4) |
| `-EINVAL` | NULL or out-of-range arguments |
| `-ENOTCONN` | No target bound |
| `-ETIMEDOUT` | No response within P2 (P2* after NRC 0x78); also ISO-TP's own N_As/N_Bs/N_Cr timeouts |
| `-EBADMSG` | A positive response without what the helper checks: the sub-function, DID, routine identifier or block counter echoed, a seed, a block length |
| `-EMSGSIZE` | The response did not fit the buffer (it is discarded), or the helper's data or key is too long |
| other negative | The transport's error: `-EIO` (ISO-TP protocol error), `-ENOSPC` (no CAN filter), `-ENOMEM` (no ISO-TP buffer), … |

`gu8_UdsClient_LastSid()` / `gu8_UdsClient_LastNrc()` give the last request's SID and NRC
(0 if none).

## 2. Types

### `UdsTarget_T`

| Field | Meaning |
|---|---|
| `u32_txId` | Physical request identifier (e.g. `0x7E0`) |
| `u32_rxId` | Response identifier (e.g. `0x7E8`) |
| `u32_funcId` | Functional request identifier (e.g. `0x7DF`), valid with `UDS_TGT_FUNC` |
| `u8_flags` | `UDS_TGT_EXT_ID` (29-bit IDs), `UDS_TGT_FD`, `UDS_TGT_BRS` (needs FD), `UDS_TGT_PAD`, `UDS_TGT_EXT_ADDR` (reserved: refused), `UDS_TGT_FUNC` |
| `u8_txDl` | TX frame length: 0 (8, or 64 with FD), 8, or with FD 12/16/20/24/32/48/64 |
| `u16_p2Ms`, `u16_p2StarMs` | Fixed P2 / P2* in ms; 0 = the default, then the ECU's from each session response |

### `UdsTp_T`

| Member | Contract |
|---|---|
| `int fpt_bind(ctx, target)` | Listen for the target's responses, replacing an earlier binding. 0 or a negative errno |
| `void fpt_unbind(ctx)` | Stop listening |
| `int fpt_send(ctx, data, len, functional)` | Send one request; block until it is on the bus. 0 or a negative errno |
| `int fpt_recv(ctx, buf, max, timeout)` | One whole message: its length; `-EAGAIN` on timeout; `-EMSGSIZE` if it did not fit (the rest is discarded); another negative errno on a reception error |
| `vpt_ctx` | Passed to every member |

### `UdsKey_F`

`int (*)(uint8_t level, const uint8_t *seed, size_t seedLen, uint8_t *key, size_t keyMax, size_t *keyLen, void *user)`:
compute the key for a seed of a requestSeed level. Returns 0, or a negative errno
(`-ENOTSUP` for an unknown algorithm), which the client returns as is.

## 3. Lifecycle

#### `int gi_UdsClient_Init(UdsClient_T *client, const UdsTp_T *tp)`
Clears the client and keeps the transport (which must outlive it). P2 and P2* start at
`UDS_P2_MS` / `UDS_P2STAR_MS`. `-EINVAL` for NULL or a transport with a NULL member.

#### `int gi_UdsClient_SetTarget(UdsClient_T *client, const UdsTarget_T *target)`
Checks the target, then:
1. unbinds the previous one;
2. copies the target;
3. sets P2/P2* (its overrides, else the defaults);
4. returns to the default session (no keep-alive);
5. binds the transport.

Returns `-EINVAL` for unknown flags, an ID out of range (11 or 29 bits), BRS without FD, or a
bad frame length. Returns `-ENOTSUP` for `UDS_TGT_EXT_ADDR`. Otherwise the transport's bind
error, and the client stays unbound.

#### `void gv_UdsClient_Close(UdsClient_T *client)`
Unbinds and forgets the session. Safe to call twice.

## 4. Requests

#### `int gi_UdsClient_Request(client, req, reqLen, functional, rsp, rspMax, *rspLen)`
Send any request and wait for its response. In order:
1. Discard responses that are already waiting (up to 8).
2. Send `req`, physically or (`functional`, needs `UDS_TGT_FUNC`, at most 7 bytes) to the
   functional identifier.
3. Read messages until the deadline (send time + P2):
   - `7F <SID> 78`: wait P2* from now, up to `UDS_PENDING_MAX` (100) times.
   - `7F <SID> 21`: wait `UDS_BUSY_DELAY_MS`, send again, wait P2. Up to
     `UDS_BUSY_RETRIES` (3) times.
   - `7F <SID> <NRC>`: return the NRC.
   - `<SID+0x40> …`: for a service with a sub-function (0x10, 0x11, 0x19, 0x27, 0x28, 0x31,
     0x3E, 0x85), the sub-function must be echoed, else `-EBADMSG`. Otherwise return 0.
   - Anything else: skipped.
4. Without an answer by the deadline: `-ETIMEDOUT`. For a request whose sub-function has bit
   7 set (suppressPosRspMsgIndicationBit), the client waits P2 for a negative response, and
   none means success (`*rspLen` = 0).

`*rspLen` is the length of the response returned (positive or negative).

After a positive response:
- To DiagnosticSessionControl: the session is non-default unless sub-function 0x01. If the
  response carries the sessionParameterRecord, P2 = P2server + 50 ms and
  P2* = P2*server × 10 ms + 50 ms, unless the target fixes them.
- To ECUReset: the session is default.

#### `int32_t gi32_UdsClient_KeepAlive(UdsClient_T *client)`
In a non-default session, it sends TesterPresent `3E 80` once nothing has been sent for
`UDS_TESTER_PRESENT_MS`. A negative answer is only logged. It returns the milliseconds until
the next call is due, or `UDS_KEEPALIVE_NONE` (-1) without a session to keep. Call it from
the owner's thread.

#### `void gv_UdsClient_EndSession(UdsClient_T *client)`
Stops the keep-alive without sending anything. The ECU returns to its default session once
S3 runs out (5 s). Use it after a failed job rather than keeping a half-programmed ECU in its
programming session.

## 5. Service helpers

All return as in §1. Requests and responses go through the client's own 64-byte buffers
(`UDS_CLIENT_BUF_SIZE`) unless noted.

| Function | Request | Checks / result |
|---|---|---|
| `gi_UdsClient_Session(c, session)` | `10 <session>` | §4 timing and session |
| `gi_UdsClient_EcuReset(c, type)` | `11 <type>` | Session back to default |
| `gi_UdsClient_CommControl(c, control, type)` | `28 <control> <type>` | |
| `gi_UdsClient_DtcSetting(c, type)` | `85 <type>` | |
| `gi_UdsClient_SecurityAccess(c, level, key, user)` | `27 <level>`, then `27 <level+1> <key>` | `level` odd, 0x01..0x7D, else `-EINVAL`. An all-zero seed: already unlocked, returns 0 without sending a key. No seed: `-EBADMSG`. The NRC of either request (0x35 invalidKey, 0x36, 0x37, …), or the key callback's error |
| `gi_UdsClient_ReadDid(c, did, data, max, *len)` | `22 <did>` | The response is read into `data` (`max` ≥ 3), then only the data record is kept. DID not echoed: `-EBADMSG` |
| `gi_UdsClient_WriteDid(c, did, data, len)` | `2E <did> <data>` | `len` 1..61, else `-EINVAL`/`-EMSGSIZE`. DID not echoed: `-EBADMSG` |
| `gi_UdsClient_Routine(c, type, rid, args, argLen, status, statusMax, *statusLen)` | `31 <type> <rid> <args>` | `argLen` ≤ 60. Routine identifier not echoed: `-EBADMSG`. The status record is copied, cut to `statusMax` (`status`/`statusLen` may be NULL) |
| `gi_UdsClient_RequestDownload(c, dfi, alfid, address, size, *maxBlock)` | `34 <dfi> <alfid> <address> <size>` | `alfid` high nibble = size bytes, low nibble = address bytes, each 1..4. A value that does not fit its bytes: `-EINVAL`. `*maxBlock` = maxNumberOfBlockLength: the longest TransferData *request*, SID and counter included. A response with no length, a cut one, or one below 3: `-EBADMSG` |
| `gi_UdsClient_TransferData(c, bsc, req, dataLen)` | `36 <bsc> <data>` | `req` holds 2 free bytes, then `dataLen` (≥ 1) bytes of data. The SID and counter are written into the free bytes, so nothing is copied. Counter not echoed: `-EBADMSG` |
| `gi_UdsClient_TransferExit(c)` | `37` | |
| `gi_UdsClient_TesterPresent(c)` | `3E 80` | Suppressed: 0 unless an NRC comes within P2 |

The block sequence counter of TransferData starts at 1 after each RequestDownload and wraps
from 0xFF to 0x00. That is the caller's job.

## 6. ISO-TP transport — `UdsTp_Isotp.h`

#### `void gv_UdsTpIsotp_Init(UdsTp_T *tp, UdsTpIsotp_T *ctx, const struct device *can)`
Makes `tp` the ISO-TP transport whose state lives in `ctx`. Both must outlive the client.
`can` is the CAN controller (`gstpt_CanIf_GetDevice()`). With NULL, every bind fails with
`-ENODEV`.

| Member | Behaviour |
|---|---|
| bind | `isotp_bind(rx: rxId, tx: txId, BS 0, STmin 0, K_NO_WAIT)`. Flags: `UDS_TGT_EXT_ID` → `ISOTP_MSG_IDE`, `UDS_TGT_FD` → `ISOTP_MSG_FDF`, `UDS_TGT_BRS` → `ISOTP_MSG_BRS`. TX frame length `u8_txDl`. Rebinding unbinds first |
| send | Blocking `isotp_send()` to txId (or funcId), with flow control on rxId. Not bound: `-ENOTCONN`. Functional without `UDS_TGT_FUNC`: `-EINVAL`. Functional over 7 bytes: `-EMSGSIZE` |
| recv | `isotp_recv()`. `ISOTP_RECV_TIMEOUT` → `-EAGAIN`. A message longer than the buffer is drained, then `-EMSGSIZE` |
| unbind | `isotp_unbind()` if bound |

`UdsTpIsotp_T.i_lastIsotpErr` holds the last raw ISO-TP error.

#### `int gi_UdsTpIsotp_Errno(int isotpErr)`

| ISO-TP | errno |
|---|---|
| `ISOTP_N_OK` | 0 |
| `ISOTP_N_TIMEOUT_A`, `_BS`, `_CR` | `-ETIMEDOUT` |
| `ISOTP_NO_FREE_FILTER` | `-ENOSPC` |
| `ISOTP_NO_NET_BUF_LEFT`, `ISOTP_NO_BUF_DATA_LEFT`, `ISOTP_NO_CTX_LEFT` | `-ENOMEM` |
| `ISOTP_N_BUFFER_OVERFLW` | `-EMSGSIZE` |
| any other | `-EIO` |

## 7. Tunables — `UdsClient_Config.h`

| Macro | Default | Kconfig |
|---|---|---|
| `UDS_P2_MS` | 150 | `CONFIG_UDS_P2_MS` |
| `UDS_P2STAR_MS` | 5000 | `CONFIG_UDS_P2STAR_MS` |
| `UDS_P2_MARGIN_MS` | 50 | — |
| `UDS_TESTER_PRESENT_MS` | 2000 | `CONFIG_UDS_TESTER_PRESENT_MS` |
| `UDS_BUSY_RETRIES` | 3 | `CONFIG_UDS_BUSY_RETRIES` |
| `UDS_BUSY_DELAY_MS` | 20 | — |
| `UDS_PENDING_MAX` | 100 | — |
| `UDS_CLIENT_BUF_SIZE` | 64 | — |

## 8. Threading

- A client belongs to one thread and has no lock.
- Every request blocks that thread for at most P2 (or P2* per NRC 0x78, up to
  `UDS_PENDING_MAX`), plus the ISO-TP transfer.
- **Never call the client from the system work queue.** Zephyr's ISO-TP runs its send and
  receive state machines there, and a blocking `isotp_send()` from a work item would wait
  for itself.
