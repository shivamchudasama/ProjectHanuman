# FileSysManager — FAT file system on the external flash (Zephyr / nRF54)

FileSysManager mounts a FAT volume on the DK's external NOR flash (MX25R6435F, 8 MiB) and
runs every file system operation on **one thread of its own**. Users never call Zephyr's
`fs_*` API themselves: they submit a command (`FileSysMessage_T`) to the manager's queue
and get the result back through a callback, or wait for it.

- **One owner, one order:** commands run strictly one after another, so two users never
  interleave inside FatFs. The thread runs below the SETU engine, so flash erases never
  delay the link.
- **A state machine, not a free API:** a Zephyr SMF machine decides which command is
  allowed when (no read or write without an open file, no delete or listing while a file is
  open). A refused command gets a result like any other (`-EPERM`).
- **Every command answers:** exactly one final result per message, listing entries before
  it. A peer gets the result as a portable status code (`gu8_FSMGR_StatusCode()`), since
  errno values differ between C libraries.
- **Formats itself:** a volume that does not mount is formatted and mounted again.

The exact API contract is in [API_REFERENCE.md](API_REFERENCE.md). The BLE file commands
built on it (the GUI's Files page) are specified in [PROTOCOL.md](PROTOCOL.md).

## Structure

| File | Role |
|---|---|
| [FileSysManager.h](../../_LIB/FileSysManager/FileSysManager.h) | Public API: start, submit, call, mount and open-file state, status codes. The only header users include |
| [FileSysManager_Types.h](../../_LIB/FileSysManager/FileSysManager_Types.h) | `FileSysCommand_E`, `FsmgrStatus_E`, `FileSysMessage_T`, `FsmgrResult_T`, `FsmgrResult_F`, the mount point and message flags |
| [FileSysManager_Config.h](../../_LIB/FileSysManager/FileSysManager_Config.h) | Tunables: thread stack and priority, queue depth, write buffer, path length. Each takes its Kconfig value when there is one |
| [FileSysManager.c](../../_LIB/FileSysManager/FileSysManager.c) | Mount or format, the queue, the thread, `gi_FSMGR_Submit()` / `gi_FSMGR_Call()`, the status mapping |
| [FileSysManagerFSM.h](../../_LIB/FileSysManager/FileSysManagerFSM.h) / [.c](../../_LIB/FileSysManager/FileSysManagerFSM.c) | The state machine: path building, directories, open, read, write (buffered or direct), close, delete, list, rename |
| [CMakeLists.txt](../../_LIB/FileSysManager/CMakeLists.txt) | Globs `*.c` into `app` and puts the folder on the include path |

```
 user thread ──gi_FSMGR_Submit(msg, cb)──▶ k_msgq ──▶ FSMGR thread ──▶ SMF state machine ──▶ fs_* (FatFs)
      ▲                                                     │                                    │
      └──────────── cb(result) on the FSMGR thread ◀────────┘          zephyr,flash-disk "FLASH_DISK"
 user thread ──gi_FSMGR_Call(msg)── waits for the final result            │
                                                                     SPI NOR or sQSPI (FLPR)
```

## Design

**State machine.** IDLE accepts directory, open, delete, list, rename, close and abort
commands. Opening a file moves to READ_FILE or WRITE_FILE, which accept only their own data
command, CLOSE and ABORT. CREATE_DIR, CREATE_FILE, DELETE, CLOSE and FAILED are transient:
they do their work in the entry action and leave at once. Any failure goes through FAILED,
which closes the file and drops buffered data. The table per state is in
[API_REFERENCE.md §5](API_REFERENCE.md#5-commands-per-state).

**Results.** The message carries its callback and user pointer. The FSM reports exactly once
per message (`gv_FileSysManagerFSMReport()`); a command that would end without a result (a
defect) is reported as `-EIO`, so a waiting user never hangs. `gi_FSMGR_Call()` is the
blocking form for threads that only need the status (the data store).

**Paths.** `"/FLASH_DISK:/a/b"` is used as is, `"/a/b"` is taken from the root, and a relative
name from the root for directories and from the current directory for files (the sample's
rules). A name that does not fit a path buffer fails with `-ENAMETOOLONG`.

**Writes.** With `CONFIG_FSMGR_BUFFERED_WRITE` (on in this project) write payloads collect in
a RAM buffer and go to `fs_write()` in `CONFIG_FSMGR_WRITE_BUFFER_SIZE` pieces; CLOSE writes the
rest and syncs. A write error can therefore surface on a later WRITE or on CLOSE. Opening for
writing does **not** truncate (`FS_O_CREATE | FS_O_WRITE`, as in the sample): delete a file
first to replace a longer one.

**Mount.** `gi_FSMGR_Start()` starts the thread, which mounts the volume, formats it if
mounting fails, and mounts again. Messages submitted before that wait in the queue; if the
volume cannot be mounted, every command fails with `-ENODEV`.

## Flash interfaces

The volume is the first 4 MiB of the MX25R6435F (`ext_storage` partition), as a
`zephyr,flash-disk` named `FLASH_DISK` with a 4 KiB cache. The interface is chosen at build
time with `FLASH_IF` (root `CMakeLists.txt`), which adds `_DI/conf/flash_<if>.conf` and
`_DI/boards/<board>_flash_<if>.overlay`:

| `FLASH_IF` | Interface | What the files do |
|---|---|---|
| `spi` (default) | SPI NOR on `spi00`, the board's `jedec,spi-nor` node | Partition + flash disk; 4 KiB erase pages (`CONFIG_SPI_NOR_FLASH_LAYOUT_PAGE_SIZE`; the default 64 KiB is larger than the disk cache) |
| `sqspi` | sQSPI soft peripheral on the FLPR (RISC-V) core, quad I/O | FLPR pins and 16 KiB of reserved RAM at `0x2003c000` for the `nordic,nrf-sqspi` node; `mx25r64` moved onto it as `jedec,mspi-nor`; `MSPI_NRF_SQSPI`; the application's RAM shrunk to 240 KiB so the linker keeps out of the reserved region |

```sh
west build -b nrf54l15dk/nrf54l15/cpuapp --sysbuild -d build .                      # SPI
west build -b nrf54l15dk/nrf54l15/cpuapp --sysbuild -d build . -- -DFLASH_IF=sqspi  # sQSPI
```

In VS Code, use the `build_sqspi` preset in the root `CMakePresets.json` (or add
`-DFLASH_IF=sqspi` to the build configuration's extra CMake arguments), and do not pick the `flash_<if>` files in its overlay or Kconfig fragment lists: added twice, the
overlay makes ninja fail ("defined as an output multiple times"), and as the base overlay it
replaces the board overlay. The root `CMakeLists.txt` stops the build with a message when
they are given.

## Provenance

Ported from the FileSystemPoC (`Sample Code FS/`, NCS 3.2.2, by Yash Sunil Giramkar), with its
copyright marking replaced by the MIT licence of `_LIB`. Changes:

| In the sample | Here |
|---|---|
| UART test harness (`UartTestHarness.c`) on the log UART | Not ported: the same commands go over BLE (`_ASW/_FS_CMD`, [PROTOCOL.md](PROTOCOL.md)) to the GUI's Files page and `setu_client.py fs` |
| Results only logged | Every command reports one result (`FsmgrResult_T`), listing entries included; portable status codes for peers |
| Thread auto-started, `gstpt_FSMGR_GetMsgQ()` for raw queue access | `gi_FSMGR_Start()` from `main()`; `gi_FSMGR_Submit()` / `gi_FSMGR_Call()` |
| Commands while unmounted ran into FatFs | `-ENODEV` |
| A command in the wrong state was logged and dropped | Refused with `-EPERM` |
| A name too long for the path buffer was cut short silently | `-ENAMETOOLONG` |
| ABORT in IDLE emptied the current directory, so relative paths broke | It resets to the root |
| ABORT while writing left the write buffer's fill count | Cleared |
| A short `fs_write()` (full volume) counted as success | `-ENOSPC` |
| CLOSE flushed and synced files open for reading too | Only files open for writing |
| — | `eFSC_RENAME` (`"old\0new"`), the `FSMGR_MSG_KEEP_DIR` flag (create a directory without making it current), `gb_FSMGR_IsFileOpen()` |
| `TransferMsgTypes.h` in `_LIB/Common`; debug counter `gu8_consumedBuff`; unused `u32_totalExpectedBytes`, `MAX_FILENAME_LEN`, `MAX_PATH_LEN` | `FileSysManager_Types.h`; removed |
| `FS_MAX_CHUNK_SIZE` 242, documented as 240 | 242, the SETU short message payload |
| Partition Manager `pm.yml` | Not used: Partition Manager is off in this NCS 3.4.1 build; the overlays' `fixed-partitions` and `zephyr,flash-disk` nodes do the same |
| Overlays disabled `&ficr` | Kept enabled: `HWINFO` reads the device ID from FICR for the CSR's CN |
| Kconfig options in the sample's `_DI/Kconfig` | `_DI/Kconfig`, menu "File system manager", plus stack, priority and queue depth; the library also builds without them (`FileSysManager_Config.h`) |

## Integration

1. Add the library to the build: [`_LIB/CMakeLists.txt`](../../_LIB/CMakeLists.txt) adds
   `FileSysManager` after `SETU`.
2. Enable the file system in `prj.conf` (section "File system": disk access on a flash disk,
   FatFs with mkfs and long names, the `FLASH_DISK` mount point) and pick the flash interface
   (`FLASH_IF`, see above). A board other than the nRF54L15 DK needs its own
   `<board>_flash_<if>.overlay`.
3. Call `gi_FSMGR_Start()` early in `main()`.
4. Submit commands. Keep to absolute paths when several users share the volume: the current
   directory is shared.

In this project:

| User | Uses |
|---|---|
| [`_ASW/_DATA_STORE`](../../_ASW/_DATA_STORE) | `gi_FSMGR_Call()` from its dump thread: stores a hex upload as `/FLASH_DISK:/FW/<name>` ([HexUpload PROTOCOL §7](../HexUpload/PROTOCOL.md#7-storing-the-upload-as-a-file)) |
| [`_ASW/_FS_CMD`](../../_ASW/_FS_CMD) | `gi_FSMGR_Submit()` from the SETU engine, results sent back from the manager's thread ([PROTOCOL.md](PROTOCOL.md)) |
| [`_ASW/_UDS`](../../_ASW/_UDS) | A UDS flash job reads a stored upload with `gi_FSMGR_Call()` (open, close) and `gi_FSMGR_Submit()` reads from its own thread, twice: to check it, then to send it to the ECU ([UDS README §2](../UDS/README.md#2-the-job-engine)) |

They share the one open file. The file commands and a hex upload's BEGIN refuse (`BUSY`) while another holds it or a flash job runs; a flash job refuses to start while an upload is being stored, and ends `BUSY` if the file commands hold a file.

## Memory

On the nRF54L15 the library takes about 5.7 KB of flash and 8.3 KB of RAM (the 4 KiB thread
stack, the queue of 8 messages, the FSM context with its 512-byte write buffer); FatFs, the
disk layer and the 4 KiB flash disk cache come on top, under "Other" in the
[memory report](../../_TOOLS/MemReport/README.md).

## Limitations

- One open file at a time, and one current directory, for all users.
- The listing covers the root and one level below; deeper directories are listed but not entered.
- Deleting a directory deletes its files but refuses a subdirectory (`-ENOTSUP`); it is not recursive.
- Opening for writing does not truncate.
- Any mount failure formats the volume, so a transient failure loses its content.
- FAT is not power-fail safe: a reset in the middle of a write can leave the volume
  inconsistent (the next mount may format it). Uploads go to a temporary file first, so a
  stored file is never half-written under its real name.
- No free-space query; a full volume shows as `-ENOSPC` on a write or on CLOSE.
- 4 of the flash's 8 MiB are used; the rest is free for a second partition.

## Tests

| Path | What |
|---|---|
| [`_TEST/unit/FileSysManager/test_fsmgr.c`](../../_TEST/unit/FileSysManager/test_fsmgr.c) | Unity tests against [API_REFERENCE.md](API_REFERENCE.md), built with and without the write buffer: mount and format, start, submit and call, every command in every state, path rules, writes, reads, failures, listing, deletion, rename, status codes. The volume is the in-memory one of `_TEST/shim/fs_sim.c` |
| [`_TEST/unit/DataStore`](../../_TEST/unit/DataStore), [`_TEST/unit/FsCmd`](../../_TEST/unit/FsCmd), [`_TEST/unit/Uds`](../../_TEST/unit/Uds) (`uds_job`) | The users, on the real library |

The public headers are also compiled on their own by the header check. Both run locally and in
CI (`host-tests`, with ASan + UBSan); see [`_TEST/README.md`](../../_TEST/README.md). The flash
itself (SPI and sQSPI) is covered by the firmware build of both variants and by `hil-tests`.
