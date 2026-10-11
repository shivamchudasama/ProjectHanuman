# BLE Host GUI

PC-side GUI (Tkinter + [bleak](https://github.com/hbldh/bleak), a flat light / dark ttk theme of its own, icons drawn with [Pillow](https://python-pillow.org)) for the Project Hanuman firmware. The PC is the BLE central and the SETU **Client**; the board is the GATT server and SETU Server. For device provisioning the PC also hosts a SETU service of its own, so the board can send its CSR to it. For device pairing the PC orchestrates two boards at once, over one link to each, and never pairs with them itself.

The window shows one page at a time. A navigation rail on the left switches between **Device** (`Ctrl+1`), one page per feature (`Ctrl+2`, `Ctrl+3`, …), and, at the bottom of the rail, **Log** (`Ctrl+L`) and **Traffic** (`Ctrl+T`). The header names the page and always shows the link: the device, its ATT MTU and a state pill (click it for the Device page). The status line at the bottom shows the latest log line, coloured by level; **Log ›** opens the log. An error logged while another page is shown puts a red dot on the Log button until the log is opened. The sun / moon button at the foot of the rail, or `Ctrl+Shift+L`, switches between light and dark; it starts in Windows' app mode.

It covers:

- **Device**: scan, connect, disconnect, and read the SETU CAPS characteristic; the link's ATT MTU and CAPS are under *Link details*, which opens after **Read Caps**. The base UUID is under *Advanced*. Connecting from this page opens the first feature page. On Windows 11, connecting also asks Windows for its throughput-optimized connection parameters (15 ms interval) for as long as the link is up. Otherwise Windows settles on about 45 ms after service discovery, which caps an upload at about 10 KB/s. The result goes to the log, and each interval change shows in the traffic monitor as `CONN`.
- **Hex Upload**: browse for an Intel HEX file, split it into contiguous segments, and send each segment as one transfer (`appType 0x10`, `[u32 LE address][data]`). The server must answer with STORED before the next segment is sent. Start and Abort buttons control the upload. Tiles show segments, size, bytes sent and the rate, and a pill shows the upload's state. The segment list, with each segment's status coloured, is under *Segments (n)*, closed by default. With a name in **Store as**, the board also stores the upload as the file `/FLASH_DISK:/FW/<name>` on its external flash (BEGIN before the segments, COMMIT after them), and the upload succeeds only if the file's size and CRC-32 match the records sent. The contract is in [_DOC/HexUpload/PROTOCOL.md](../../_DOC/HexUpload/PROTOCOL.md).
- **Files**: the board's FAT file system on its external flash, through the file commands that replace the FileSystemPoC's UART test harness. The **Command line** runs the harness's commands as typed (`mkdir`, `cd`, `openr`, `openw`, `write <text>`, `read [bytes]`, `ls`, `delfile`, `deldir`, `close`, `abort`, `help`; Enter runs it). Below it, the same commands have buttons: a path field with Make dir, Change dir, Open read, Open write, Delete file and Delete dir; a data field (text, or hex with *Hex*) with **Write** (any length, sent 240 bytes per command) and **Write file…** (a PC file into the file open for writing); a byte count with **Read**; **List**, **Close**, **Abort**; and **Download…**, which reads the file named in the path field to a PC file. Tiles show the current directory and the open file as the replies tell them (the board keeps both between connections, so they start unknown). **List** fills the *Listing* table; selecting a row puts its path in the path field. Read data shows as a hex dump under *Read data*. Results go to the application log, prefixed `files:`. The contract is in [_DOC/FileSysManager/PROTOCOL.md](../../_DOC/FileSysManager/PROTOCOL.md).
- **Provisioning**: the PC is the Certificate Authority. Create or load a CA folder, read the device's STATUS, then **Provision**: the device sends its CSR, the PC checks it and issues a device certificate, and sends it with the CA certificate; the device verifies both, stores both, deletes its CSR and logs them as PEM. The page shows the device and the CA side by side, with pills for the PC service, the device's state and the CA, and a step list that follows the sequence. The CA's folder and *Create CA* are under *CA settings*, open while no CA is loaded. The session's lines go to the application log, prefixed `provisioning:`. Provisioning is one-time: a provisioned device is refused. **More ▾** holds the less used commands: **Save certificate…** writes the device certificate, and **Remove provisioning…** (after a confirmation) sends DEPROVISION, which wipes the device's key, CSR and certificates; the device makes a new key and CSR and can be provisioned again. The contract is in [_DOC/Provisioning/PROTOCOL.md](../../_DOC/Provisioning/PROTOCOL.md), the design in [_DOC/Provisioning/README.md](../../_DOC/Provisioning/README.md).
- **Pairing**: certificate-based OOB pairing of two provisioned boards. **Scan** finds the boards that advertise the Pairing service (only provisioned boards do) and clears the progress pane. Choose which board is the **Central** and which the **Peripheral** (the first two found are proposed; **Swap** exchanges them). **Check** reads the pairing status of those two boards (provisioned, paired and with whom, the last run's error) into the devices list and the progress pane, and says when they are paired with each other already. Then **Pair**. Two boards paired with each other are not paired again: Pair stays disabled until one of them is unpaired (the page also checks again when it connects, should another tool have paired them). The page connects to both boards, sends each its role and the other's address, and follows both live in a step list per board: reach the peer, connected, certificates exchanged, peer certificate verified, signed OOB data exchanged, pairing, paired. It ends when both are PAIRED or one has FAILED, with the reason (for example *the peer's certificate was rejected (BAD_SIG)*), and disconnects from both: the boards keep their encrypted, bonded link, and the peripheral lights LED0. After a reset or a lost link the boards reconnect to each other by themselves and blink LED0 while connected; the PC takes no part. **Cancel** sends CANCEL to both. **More ▾** unpairs the central or the peripheral board (deletes its bond and drops its link to its peer). The page makes its own links, so the Device page must be disconnected. Its lines go to the application log, prefixed `pairing:`. The contract is in [_DOC/Pairing/PROTOCOL.md](../../_DOC/Pairing/PROTOCOL.md), the design in [_DOC/Pairing/README.md](../../_DOC/Pairing/README.md).
- **BLE traffic monitor**: every write, read, notification and link event, shown as hex and decoded SETU frames (provisioning's STATUS and RESULT, pairing's CONTROL and STATUS, the hex upload's BEGIN / COMMIT / FILE and the file commands' FS_CMD / FS_REPLY / FS_ENTRY decoded too). Traffic of the PC's own service is marked `PC service`; traffic of the Pairing page's links is tagged `central` / `peripheral`. The **Capture** switch on the Traffic page turns it on or off (`Ctrl+T` opens the page with capture on). It captures nothing while it is off, and keeps capturing while other pages are shown; a blue dot on the Traffic button says it is on. It stays a dark terminal in both themes; TX, RX, Events and the hide / full-payload filters are toggle buttons.

## Run

```sh
pip install -r requirements.txt
python ble_host_gui.py
```

Python 3.10 or later; `requirements.txt` installs bleak (≥ 1, for the winrt 3.x packages), cryptography and Pillow. Without Pillow, pills and the step list fall back to Tk's own (jagged) shapes, check boxes and switches to ttk's plain indicator, and buttons show text only; without the Segoe Fluent Icons font (Windows 11; Segoe MDL2 Assets on Windows 10) buttons show text only. The SETU protocol code lives in [`setu_client.py`](setu_client.py), which is also a command-line client (`python setu_client.py --help`), and [`setu_receiver.py`](setu_receiver.py) (the receiver role); keep both next to `ble_host_gui.py`.

Typical session: on the Device page **Scan**, select `ProjectHanuman`, **Connect** (or double-click it); the Hex Upload page opens: **Browse…**, optionally a **Store as** name, **Start Upload**. The board prints each segment on its serial terminal (921600 baud, RTS/CTS). Headless: `python setu_client.py hex app.hex --name "ProjectHanuman" [--store APP1.BIN]`.

Files session: connect, open the Files page, type `ls` (or **List**); select the stored file, **Download…**. Headless: `python setu_client.py fs ls|mkdir|cd|openr|openw|write|read|delfile|deldir|close|abort … --name "ProjectHanuman"`, `fs get REMOTE LOCAL`, `fs put LOCAL REMOTE`, and `fs shell`, which reads the UART harness's command lines from the keyboard.

Provisioning session: on the Provisioning page **Create CA** once (or **Load** a folder; the default `~/.blehost/ca` holds the CA private key, keep it private), connect, **Get Status**, **Provision**. Headless: `python setu_client.py provision --name "ProjectHanuman" [--ca DIR] [--out device.pem] [--negative]` (`--negative` wipes a device that is not fresh, sends the certificates it must reject and checks each answer, then provisions it) and `python setu_client.py deprovision --name "ProjectHanuman"` (wipe).

UDS session (headless only for now): `python setu_client.py uds target --profile PROFILE.json`, `uds req 22F190`, `uds unlock --level 1 --algo BENCH_XOR`, `uds status`, `uds abort`, and `flash NAME --profile PROFILE.json`, which flashes the stored file `/FLASH_DISK:/FW/NAME` into the ECU with the profile's sequence (_DOC/UDS/README.md; the bench ECU is _TOOLS/EcuSim).

Pairing session: provision both boards first (with the same CA). On the Pairing page **Scan**, choose the central and the peripheral, **Check**, **Pair**. Headless: `python setu_client.py pair --central ADDRESS --peripheral ADDRESS` (exit code 0 only when both end PAIRED; refused when the two are paired with each other already), `pairstatus --address ADDRESS` and `unpair --address ADDRESS`.

The PC's own SETU service is published at start-up through WinRT's `GattServiceProvider` (Windows 10/11, adapter with the peripheral role; the Provisioning page's *PC service* pill says whether it is up). `bless` is not used: it cannot be installed next to bleak ≥ 1 on Python 3.12.

**Base UUID** must match the firmware's `BaseUUIDs.h`. The default is the project base, `16a1-4812-af35-f3f29a92f6ca`. **Max segment** must not exceed the server's `DS_BUF_SIZE` (65536).

## Layout

```
ble_host_gui.py          entry point; FEATURES lists the feature pages; starts the PC GATT service
setu_client.py       SETU reference client (protocol + command line, incl. hex --store, fs, provision/deprovision, pair/pairstatus/unpair, uds, flash); imported by protocols/setu.py
setu_receiver.py     SETU receiver role (protocol §7), transport independent
blehost/
  context.py             AppContext: settings, event bus, asyncio runner, link, services
  core/
    async_runner.py      asyncio loop on a worker thread (all bleak calls run here)
    event_bus.py         thread-safe worker -> Tk messaging (LINK_STATE, LOG, TRAFFIC)
    ble_link.py          BleLink: the only bleak user; scan/connect/GATT, traffic capture; ctx.link is the main
                         one, a feature's own links are BleLink(label=..., primary=False)
    gatt_server.py       PcGattServer: the PC's SETU service (WinRT) + receiver; the only WinRT GATT-server user
    traffic.py           TrafficEvent + TrafficTap
    decoders.py          characteristic names and payload decoders for the monitor
  protocols/
    setu.py          imports the reference client, frame decoder, SETUService
    provisioning.py      provisioning appTypes, STATUS/RESULT codecs, ProvisioningSession (incl. deprovision)
    pairing.py           Pairing service UUIDs, CONTROL/STATUS codecs, PairingOrchestrator (probe, pair, unpair)
    filesystem.py        file commands: CMD/REPLY/ENTRY codecs, FileSystemSession, the UART harness's line parser, fs CLI and shell
    uds.py               UDS over BLE (0x50-0x58): Target/FlashParams/Status codecs, the JSON profile loader, UdsSession, uds CLI
  pki/
    authority.py         the CA: create/load, check a CSR, issue a device certificate
    negative.py          certificates the device must reject (host test devicecert_verify, provision --negative)
  features/
    base.py              Feature base class (one page each: title, rail icon, build())
    hex_upload.py        Hex Upload page (Store as: BEGIN / COMMIT)
    file_system.py       Files page (the UART test harness: command line, buttons, listing, read data, download)
    provisioning.py      Provisioning page
    pairing.py           Pairing page
  ui/
    main_window.py       window: navigation rail, pages (built on first show), header, status line, Log page; show()
    connection_panel.py  the Device page: scan / connect / caps
    traffic_view.py      the Traffic page: BLE traffic monitor and its Capture switch
    theme.py             Theme: flat light / dark on ttk's clam, shared styles, palettes, on_change, px() / sp(); of(ctx)
    widgets.py           display widgets: card(), Pill, StatTile, Stepper, Disclosure, MoreMenu, Tooltip; set_icon(), set_var()
    icons.py             Pillow images: pills, step markers, check box and switch, icon-font glyphs (badged too), the window icon
```

### Threading

Tk runs on the main thread. BLE work runs on an asyncio loop in a worker thread. The Tk side starts work with `ctx.run(coro, on_done=…, on_error=…, on_cancel=…)`, and those callbacks run back on the Tk thread. The worker reports to Tk only through `ctx.bus` (`post` / `call`). Never touch a widget from a coroutine: use `ctx.bus.call(fn, …)`.

### Look and feel

`MainWindow` creates the `Theme` (`ui/theme.py`) and puts it in `ctx.theme`; a panel gets it with `theme.of(ctx)`, which returns a passive light theme when the panel is built on its own (a test). The theme is ttk's `clam` coloured from the palettes in `theme.py`: every button, field, list and scrollbar is drawn with Tk's rectangles and text, and only the check box and switch indicators are small fixed-size images. ttk widgets follow the theme by themselves; use the shared styles (`Card.TFrame`, `Accent.TButton`, `Danger.TButton`, `Toggle.TButton`, `Switch.TCheckbutton`, `Toolbutton`, `Caption.TLabel`, `Strong.TLabel`, `Title.TLabel`, `Value.TLabel`, `Mono.TLabel`, `Link.TLabel`) rather than colours or fonts of your own. Classic Tk widgets (`Text`, `Canvas`, `Menu`) and Treeview row tags do not follow it: register `theme.on_change(fn)`, which calls `fn(palette)` at once and after every switch (`theme.style_text()` colours a log `Text`, `style_menu()` a menu, `style_combobox()` a combobox's drop-down list). Status colours are the tones `ok`, `info`, `warn`, `err` and `idle`, each a (foreground, background) pair readable in both modes.

The display widgets (pills, tiles, the step list) only show state: they follow the `StringVar`s and calls the feature logic already makes (for example through `trace_add`), so the logic and its tests do not depend on them.

**Icons and sizes.** Give a button an icon with `set_icon(button, theme, "upload")` (`accent=True` on an `Accent.TButton`): a glyph of Windows' icon font, recoloured on every switch, to the left of the text. The names are in `icons.GLYPHS`. Pills and the step list are drawn by `icons.py` at four times their size and scaled down, so their edges stay smooth. Write sizes in pixels at 100 % and pass them through `theme.px(n)`, and spacing through `theme.sp("xs" | "s" | "m" | "l")`, so the layout follows the display scale. Fonts are in points, so they follow it already; `Theme` sets Tk's named fonts (`TkDefaultFont`, …) to the same family.

**Keeping it smooth.** The GUI used the sv-ttk theme before. It draws every button, entry, tab and scrollbar as a stretched, alpha-blended PNG, which Tk on Windows blends in software on every redraw. At 150 % display scale a theme switch took 400–750 ms, a tab switch 160–270 ms and a window resize up to 1.5 s, and hiding parts of the window did not help. With the flat theme, the first frame takes about 0.2 s, a theme switch about 35 ms, a page switch about 30 ms and a resize about 100 ms. To keep it so:

- Do not bring back image-drawn elements that stretch (a rounded button from a 9-slice image, say). Small fixed-size images (the indicators, glyphs, pills) are cheap.
- Show one page at a time. A page is built the first time it is shown, and only the current page is mapped, so Tk lays out and redraws only its widgets.

- Redraw only what changed. Write a value that a timer or a progress callback refreshes through `set_var(var, value)`, which skips the write, and its traces, when nothing changed. `Pill.set()`, `Stepper.show()` and `StatTile.set()` do nothing when the state is the same.
- Do not let a value change the layout. A label whose text changes often asks for a fixed width (`StatTile` does), and a `<Configure>` handler changes an option only when the new value differs (`features/provisioning.py`, `follow_wrap()`).
- Coalesce bursts. The hex upload shows its progress at most every 66 ms (`PROGRESS_MS`), however fast the ACKs come.
- `ble_host_gui.py` builds the window withdrawn and shows it with `MainWindow.show()`, so the first frame on screen is already themed and laid out.

## Adding a feature

1. Create `blehost/features/<name>.py` with a `Feature` subclass. Set `title` (the page's name, under its rail button) and `icon` (a name in `ui/icons.GLYPHS`), build the page in `build(parent)` from `ui/widgets.card()` sections and the shared styles (see *Look and feel*), and react to `on_connected` / `on_disconnected`. The page is built the first time it is shown, and those two are called only once it is built, so `build()` must show the link as it is then. Put what is seldom needed behind a `Disclosure` or a `MoreMenu`, and send the feature's messages to `ctx.log()` (the Log page and the status line) rather than a log of its own. Report `busy` and implement `cancel()` if the feature runs long operations.
2. Talk to the device only through `ctx.link` (`gatt.write_gatt_char`, `gatt.read_gatt_char`, `start_notify`) or a service in `ctx.services`. Traffic then shows in the monitor automatically. A feature that needs several devices at once makes its own links, `BleLink(ctx.bus, ctx.tap, label=..., primary=False)`: they post no `LINK_STATE` (the window keeps following `ctx.link`), and their traffic is tagged with the label (see `features/pairing.py`).
3. If the feature has its own wire format, put the codec in `blehost/protocols/` and register its characteristics with `ctx.decoders.register(uuid, name, decoder)`. SETU appTypes are named with `setu.register_app_type()`.
4. Add the class to `FEATURES` in `ble_host_gui.py`; it gets the next rail button and `Ctrl+<n>`.
5. Add its tests to `_TEST/python/` with the feature: the codec and protocol logic, and the page itself. The `conftest.py` there provides a fake GATT link and a scripted SETU server, so no adapter is needed. Test the page's logic against stand-in Tk variables and a fake context, plus one test that builds the real page, as `test_feature_provisioning.py` does (see [_TEST/README.md](../../_TEST/README.md)).

A connection-wide service, such as a shared protocol endpoint, registers `link.add_connect_hook()` / `add_disconnect_hook()` and goes in `ctx.services` (see `SETUService`, and `PcGattServer` for a service the PC hosts: `ctx.services["pc_server"].receiver` receives what the device sends).

## Planned

Encrypted communication between the paired boards beyond the SECURED proof (the boards reconnect by themselves, but exchange nothing yet), and showing on the Pairing page whether their link is up. The PC itself never pairs with a board: device-to-device pairing needs no WinRT pairing on the PC.
