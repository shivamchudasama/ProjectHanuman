# File Commands over BLE — Protocol

This is the contract between the firmware's file commands ([`_ASW/_FS_CMD`](../../_ASW/_FS_CMD),
on top of the [File System Manager](README.md)) and a host that drives the device's file
system: the GUI's Files page ([`_TOOLS/BleHostGUI`](../../_TOOLS/BleHostGUI/README.md)) and
`setu_client.py fs`. It is the FileSystemPoC's UART test harness, moved onto BLE: the same
commands, now with a result for each.

Everything travels as SETU **short messages** on the host link: the host writes them to the
device's DATA characteristic and the device notifies on CTRL. The SETU service, the frame
format and link setup are in [../SETU/PROTOCOL.md](../SETU/PROTOCOL.md) and
[../HexUpload/PROTOCOL.md §1–2](../HexUpload/PROTOCOL.md#1-discovery). A short frame is
`[u8 payload length][u8 appType][payload]`, payload at most 242 bytes.

## 1. Messages

| appType | Direction | Payload |
|---|---|---|
| `0x40` CMD | host → device | `[u8 seq][u8 op][arg]` |
| `0x41` REPLY | device → host | `[u8 seq][u8 op][u8 status][data]` — ends every command |
| `0x42` ENTRY | device → host | `[u8 seq][u8 type][u32 LE size][path]` — LS only, one per entry, before the REPLY |

`seq` is chosen by the host and echoed in the REPLY and ENTRYs of that command; `op` is echoed
in the REPLY. `0x43`–`0x4F` are reserved. A transfer (START) with an appType of the range is
refused. While the SETU Server is bound to a peer device for pairing, the router admits
only `0x30`–`0x3F`, so a peer cannot reach the file commands.

ENTRY `type`: `0` file, `1` directory (size `0`). Paths are UTF-8, absolute
(`/FLASH_DISK:/…`), not terminated; a path longer than 236 bytes is cut.

## 2. Operations

| op | Name (harness command) | arg | REPLY data on success |
|---|---|---|---|
| 1 | MKDIR (`mkdir <path>`) | Directory path; an existing one is fine | The directory's path; it becomes the current directory |
| 2 | CD (`cd <path>`) | Directory path | The directory's path |
| 3 | OPENR (`openr <path>`) | File path | The file's path |
| 4 | OPENW (`openw <path>`) | File path; created if missing, **not truncated** | The file's path |
| 5 | WRITE (`write <text>`) | 1..240 data bytes | `u32 LE` bytes written to the file so far |
| 6 | READ (`read [bytes]`) | none, or `u16 LE` count (`0`: as many as fit) | Up to 239 bytes; none at the end of the file |
| 7 | LS (`ls`) | none | `u16 LE` number of ENTRYs sent |
| 8 | DELFILE (`delfile <path>`) | File path | — |
| 9 | DELDIR (`deldir <path>`) | Directory path; its files are deleted first | — |
| 10 | CLOSE (`close`) | none | `u32 LE` bytes written (0 for a file read) |
| 11 | ABORT (`abort`) | none | — |

A failed command's REPLY has no data.

**Paths.** `/FLASH_DISK:/x` is used as is, `/x` is taken from the root, and a relative name from
the root for MKDIR, CD and DELDIR and from the current directory for OPENR, OPENW and DELFILE.

**State.** The device has one current directory and one open file, and keeps both across
connections. OPENR / OPENW need no open file; WRITE needs a file open for writing, READ one open
for reading; MKDIR, CD, LS, DELFILE and DELDIR need no open file. Anything else is BAD_STATE and
changes nothing. A failed WRITE, READ or CLOSE (other than BAD_ARG, BAD_STATE or BUSY) closes the
file. CLOSE and ABORT without an open file succeed; ABORT without an open file also makes the
root the current directory again.

**LS** lists the root and, after each directory there, that directory's direct children;
directories below that are listed but not entered.

## 3. Status codes

| Code | Name | Typical cause |
|---|---|---|
| 0 | OK | |
| 1 | NOT_FOUND | No such file or directory, or the parent is missing |
| 2 | EXISTS | |
| 3 | NOT_EMPTY | |
| 4 | NO_SPACE | The volume is full |
| 5 | BAD_ARG | Unknown op, empty WRITE, READ with a 1- or 3+-byte argument, empty path, path too long |
| 6 | BAD_STATE | Not allowed now (§2 State) |
| 7 | BUSY | Another command is in progress, the hex upload is storing a file, a UDS flash job runs ([../UDS/PROTOCOL.md](../UDS/PROTOCOL.md)), or the device's queue is full |
| 8 | NOT_MOUNTED | The volume could not be mounted |
| 9 | IO | Any other error |
| 10 | NOT_SUPPORTED | DELDIR of a directory with a subdirectory |
| 11 | WRONG_TYPE | CD or DELDIR on a file, DELFILE on a directory |
| 12 | DENIED | |

These are the File System Manager's `FsmgrStatus_E`
([API_REFERENCE.md §3](API_REFERENCE.md#fsmgrstatus_e-and-gu8_fsmgr_statuscode)); the device log
shows the errno behind each.

## 4. Sequence and rules

1. Connect and subscribe to CTRL, as for an upload.
2. Send one CMD and wait for the REPLY with the same `seq` (collecting the ENTRYs of LS on the
   way). Allow several seconds: flash erases and syncs take time.
3. Only then send the next CMD. A CMD that arrives while one is in progress is answered BUSY at
   once, as is any CMD between a hex upload's BEGIN and COMMIT
   ([../HexUpload/PROTOCOL.md §7](../HexUpload/PROTOCOL.md#7-storing-the-upload-as-a-file)); BEGIN
   in turn is refused while a file is open through these commands. Every CMD is also answered
   BUSY while a UDS flash job runs ([../UDS/PROTOCOL.md](../UDS/PROTOCOL.md)): it reads its file
   twice. A flash job started while a file is open through these commands ends FAILED with
   status BUSY.
4. A CMD shorter than 2 bytes is ignored (no REPLY): it has no `seq`.

To read a whole file: OPENR, READ until a REPLY without data, CLOSE. The PC tools run that loop
themselves: the Files page's Read and `read [N]` on its command line or in `setu_client.py fs`
send READs from the current position until N bytes or the end of the file, Download… and
`fs get` the whole OPENR … CLOSE. To write one: OPENW, WRITE
in pieces of at most 240 bytes, CLOSE (DELFILE first to replace a longer file). The Files page's Write and
Write file… send those WRITEs one after another until all is sent, a WRITE fails or Stop is pressed
(after the WRITE in flight); the file stays open. Its Read, Write and Download… show their progress
and average rate; the protocol gives no file size, so a read to the end takes it from the last LS.

## 5. Examples

The golden frames are in [`_TEST/vectors/wire.json`](../../_TEST/vectors/wire.json), section
`file_system` (checked by the C and the Python tests). Frames as on the air:

```
CMD    04 40 01 01 46 57                       seq 1 MKDIR "FW"
REPLY  12 41 01 01 00 2f 46 4c 41 53 48 5f …   seq 1 MKDIR OK "/FLASH_DISK:/FW"
CMD    07 40 04 05 68 65 6c 6c 6f              seq 4 WRITE "hello"
REPLY  07 41 04 05 00 05 00 00 00              seq 4 WRITE OK, 5 bytes written
CMD    04 40 08 06 10 00                       seq 8 READ 16
REPLY  08 41 08 06 00 68 65 6c 6c 6f           seq 8 READ OK "hello"
CMD    02 40 0a 07                             seq 10 LS
ENTRY  15 42 0a 01 00 00 00 00 2f 46 4c …      seq 10 DIR  "/FLASH_DISK:/FW"
ENTRY  19 42 0a 00 a8 19 00 00 2f 46 4c …      seq 10 FILE "/FLASH_DISK:/FW/FW1" 6568 bytes
REPLY  05 41 0a 07 00 02 00                    seq 10 LS OK, 2 entries
REPLY  03 41 0f 04 07                          seq 15 OPENW BUSY
```

## 6. Security

Like the hex upload, the file commands reach a provisioned device only from its **trusted host**
([../HostAuth/PROTOCOL.md §2](../HostAuth/PROTOCOL.md#2-the-gate)), a bonded, level-4 link made by
host authentication. A CMD from any other link is dropped and answered with REFUSED (`0x66`), and
an unprovisioned device does not take them at all. `CONFIG_FS_CMD=n` still leaves the range
unregistered (every CMD is then ignored), for images that need no file access over BLE.
