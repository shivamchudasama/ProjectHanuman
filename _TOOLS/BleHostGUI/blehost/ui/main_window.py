"""Main window: a navigation rail on the left and one page at a time beside it
(Device, one per feature, Log, BLE traffic). A header names the page and
shows the active device (core/devices.py) and how many other boards are
connected; a status line under it shows the latest log line. Light or dark
theme (ui/theme.py).

Pages are built the first time they are shown, and only the current one is
mapped, so Tk lays out and redraws one page's widgets, not the whole window's.

ble_host_gui.py builds it with the root withdrawn and shows it with show(),
so the first frame on screen is already themed and laid out."""

import time
import tkinter as tk
from tkinter import messagebox, ttk

from ..core.ble_link import LinkState
from ..core.event_bus import DEVICES, LINK_STATE, LOG
from . import icons
from . import theme as th
from .connection_panel import STATE_PILL, ConnectionPanel
from .traffic_view import TrafficView
from .widgets import Pill, Tooltip, set_icon, set_var

APP_TITLE = "BLE Host"
LOG_LINES = 2000                       # the log page keeps this many lines
RAIL_ICON = 20                         # rail glyphs, pixels at 100 %


class Page:
    """One page: its rail button, and its frame once built."""

    def __init__(self, key, title, icon, build, shortcut="", label=None):
        self.key, self.title, self.icon, self.shortcut = key, title, icon, shortcut
        self.label = label or title            # under the rail icon
        self._build = build
        self.frame = None
        self.button = None
        self.badge = None                  # a palette tone shown as a dot on the button

    @property
    def built(self) -> bool:
        return self.frame is not None

    def build(self, parent):
        if self.frame is None:
            self.frame = self._build(parent)
        return self.frame


class MainWindow:
    def __init__(self, root, ctx, feature_classes):
        self.root = root
        self.ctx = ctx
        root.title(APP_TITLE)
        k = root.winfo_fpixels("1i") / 96            # display scale (1.0 at 100 %)
        w = min(int(1100 * k), int(root.winfo_screenwidth() * 0.9))
        h = min(int(760 * k), int(root.winfo_screenheight() * 0.85))
        root.geometry(f"{w}x{h}")
        root.minsize(int(820 * k), int(560 * k))

        self.theme = ctx.theme = th.Theme(root, th.system_mode())
        self.theme.apply()
        self.mode_var = tk.StringVar(value=self.theme.mode)
        t = self.theme

        self.features = [cls(ctx) for cls in feature_classes]
        ctx.devices.is_busy = self._busy           # no switch of the active device while busy
        self.pages = {"device": Page("device", "Device", "device", self._build_device)}
        for i, f in enumerate(self.features):
            self.pages[f"feature{i}"] = Page(f"feature{i}", f.title, f.icon,
                                             lambda parent, f=f: f.build(parent))
        self.pages["log"] = Page("log", "Log", "log", self._build_log, "Ctrl+L")
        self.pages["traffic"] = Page("traffic", "BLE traffic", "traffic", self._build_traffic, "Ctrl+T",
                                     label="Traffic")
        for i, page in enumerate(p for p in self.pages.values() if p.key not in ("log", "traffic")):
            page.shortcut = f"Ctrl+{i + 1}"
        self.page_var = tk.StringVar()
        self.title_var = tk.StringVar()
        self._current = None
        self.conn = None
        self.traffic = None
        self._reason = None                    # why the active device's link went, for the header

        self._build_status_bar()
        body = ttk.Frame(root)
        body.pack(fill="both", expand=True)
        self._build_rail(body)
        ttk.Separator(body, orient="vertical").pack(side="left", fill="y")
        main = ttk.Frame(body)
        main.pack(side="left", fill="both", expand=True)
        self._build_header(main)
        self.content = ttk.Frame(main, padding=(t.sp("m"), t.sp("s"), t.sp("m"), t.sp("m")))
        self.content.pack(fill="both", expand=True)

        # The device page and the log are needed from the start (link state, log lines)
        self.pages["log"].build(self.content)
        self.show_page("device")

        keys = [p.key for p in self.pages.values() if p.key not in ("log", "traffic")]
        for i, key in enumerate(keys[:9]):
            root.bind_all(f"<Control-Key-{i + 1}>", lambda e, key=key: self.show_page(key))
        root.bind_all("<Control-t>", lambda e: self.open_traffic())
        root.bind_all("<Control-l>", lambda e: self.show_page("log"))
        root.bind_all("<Control-L>", lambda e: self._toggle_mode())     # Ctrl+Shift+L
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        ctx.bus.subscribe(LINK_STATE, self._on_link_state)
        ctx.bus.subscribe(DEVICES, self._on_devices)
        ctx.bus.subscribe(LOG, self._on_log)
        self.theme.on_change(self._on_theme)

    def show(self):
        """Put the window on screen (ble_host_gui.py: it was built withdrawn):
        title bar and icon first, so the first frame is the finished one."""
        self.root.update_idletasks()
        self.theme.title_bar()
        self._app_icons = icons.app_icon(self.root, th.PALETTES[th.LIGHT]["accent"])
        if self._app_icons:
            self.root.iconphoto(True, *self._app_icons)
        self.root.deiconify()

    # ---- construction ------------------------------------------------------
    def _build_rail(self, parent):
        t = self.theme
        rail = ttk.Frame(parent, style="Rail.TFrame", padding=(t.sp("xs"), t.sp("s")))
        rail.pack(side="left", fill="y")
        self._logo = ttk.Label(rail, style="Rail.TLabel", anchor="center")
        self._logo.pack(fill="x", pady=(t.sp("xs"), t.sp("m")))
        for page in self.pages.values():
            b = ttk.Radiobutton(rail, text=page.label,
                                value=page.key, variable=self.page_var, style="Rail.Toolbutton",
                                takefocus=False, command=lambda key=page.key: self.show_page(key))
            if page.key not in ("log", "traffic"):
                b.pack(side="top", fill="x", pady=t.px(2))
            page.button = b
            page.tip = Tooltip(b, f"{page.title} ({page.shortcut})", t)
        # At the bottom, from the bottom up: theme, a rule, BLE traffic, Log
        self.mode_btn = ttk.Button(rail, style="Rail.Toolbutton", takefocus=False,
                                   command=self._toggle_mode)
        self.mode_btn.pack(side="bottom", fill="x", pady=t.px(2))
        self.mode_tip = Tooltip(self.mode_btn, "", t)
        ttk.Separator(rail, orient="horizontal").pack(side="bottom", fill="x", pady=t.sp("s"))
        for key in ("traffic", "log"):
            self.pages[key].button.pack(side="bottom", fill="x", pady=t.px(2))

    def _build_header(self, parent):
        t = self.theme
        head = ttk.Frame(parent, padding=(t.sp("m"), t.sp("s"), t.sp("m"), t.sp("xs")))
        head.pack(fill="x")
        ttk.Label(head, textvariable=self.title_var, style="Title.TLabel").pack(side="left")
        self.status_pill = Pill(head, t, "Idle", "idle")
        self.status_pill.pack(side="right")
        self.status_pill.configure(cursor="hand2")
        self.status_pill.bind("<Button-1>", lambda e: self.show_page("device"))
        Tooltip(self.status_pill, "Device page (Ctrl+1)", t)
        self.status_var = tk.StringVar(value="Not connected")
        ttk.Label(head, textvariable=self.status_var, style="Caption.TLabel").pack(
            side="right", padx=t.sp("s"))

    def _build_status_bar(self):
        t = self.theme
        bar = ttk.Frame(self.root, padding=(t.sp("m"), t.sp("xs")))
        bar.pack(side="bottom", fill="x")
        ttk.Separator(self.root, orient="horizontal").pack(side="bottom", fill="x")
        self.last_log_var = tk.StringVar(value="")
        self._last_level = "info"
        self.last_log = ttk.Label(bar, textvariable=self.last_log_var, style="Caption.TLabel",
                                  width=1, anchor="w")
        self.last_log.pack(side="left", fill="x", expand=True)
        open_log = ttk.Button(bar, text="Log ›", style="Link.TLabel", cursor="hand2",
                              takefocus=False, command=lambda: self.show_page("log"))
        open_log.pack(side="right")

    def _build_device(self, parent):
        self.conn = ConnectionPanel(parent, self.ctx, is_busy=self._busy)
        return self.conn

    def _busy(self) -> bool:
        """A feature has work in progress (any thread: only reads)."""
        return any(f.busy for f in self.features)

    def _build_log(self, parent):
        t = self.theme
        frame = ttk.Frame(parent)
        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=(0, t.sp("s")))
        ttk.Label(bar, text="Application log: the link, every feature, errors.",
                  style="Caption.TLabel").pack(side="left")
        clear = ttk.Button(bar, text="Clear", command=lambda: text.delete("1.0", "end"))
        clear.pack(side="right")
        set_icon(clear, t, "clear")
        body = ttk.Frame(frame)
        body.pack(fill="both", expand=True)
        text = tk.Text(body, height=5, wrap="word", font=t.fonts["mono"], state="normal",
                       padx=8, pady=6)
        sb = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=sb.set)
        text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        text.bind("<Key>", lambda e: None if (e.state & 0x4 and e.keysym.lower() == "c") else "break")
        t.on_change(lambda p: th.style_text(text, p))
        self.log_text = text
        return frame

    def _build_traffic(self, parent):
        self.traffic = TrafficView(parent, self.ctx, on_capture=self._on_capture)
        return self.traffic

    # ---- pages -------------------------------------------------------------
    @property
    def current_page(self) -> str:
        return self._current.key if self._current else ""

    def show_page(self, key: str):
        """Show page key (building it the first time) in place of the current one."""
        page = self.pages[key]
        if page is self._current:
            return
        frame = page.build(self.content)
        if self._current is not None:
            self._current.frame.pack_forget()
        frame.pack(fill="both", expand=True)
        self._current = page
        set_var(self.page_var, key)
        set_var(self.title_var, page.title)
        if key == "log":
            self._set_badge("log", None)

    def _built_features(self):
        return [f for i, f in enumerate(self.features) if self.pages[f"feature{i}"].built]

    def _set_badge(self, key: str, tone):
        page = self.pages[key]
        if page.badge != tone:
            page.badge = tone
            self._rail_icon(page)

    def _rail_icon(self, page):
        p = self.theme.palette
        spec = icons.button_spec(page.button, self.theme, page.icon, size=RAIL_ICON,
                                 selected="accent", badge=p[page.badge][0] if page.badge else None)
        page.button.configure(image=spec, compound="top" if spec else "none")

    # ---- traffic -----------------------------------------------------------
    def open_traffic(self):
        """Ctrl+T: the traffic page, capturing."""
        self.show_page("traffic")
        self.traffic.set_capture(True)

    def _on_capture(self, on: bool):
        self._set_badge("traffic", "info" if on else None)

    # ---- theme -------------------------------------------------------------
    def _toggle_mode(self):
        self._set_mode(th.DARK if self.theme.mode == th.LIGHT else th.LIGHT)

    def _set_mode(self, mode):
        self.theme.apply(mode)
        self.mode_var.set(self.theme.mode)

    def _on_theme(self, palette):
        t = self.theme
        dark = t.mode == th.DARK
        target = "light" if dark else "dark"
        self.mode_tip.text = f"Switch to {target} mode (Ctrl+Shift+L)"
        img = icons.glyph(self.mode_btn, "sun" if dark else "moon", t.px(RAIL_ICON), palette["sub"])
        if img is not None:                             # an icon button, the tooltip says what it does
            self.mode_btn.configure(image=img, text="")
        else:
            self.mode_btn.configure(image="", text="☀" if dark else "☾")
        self.mode_btn.mode = target                     # what a click switches to (tests)
        logo = icons.app_icon(self._logo, palette["accent"], sizes=(t.px(28),))
        self._logo.configure(image=logo[0] if logo else "", text="" if logo else APP_TITLE)
        for page in self.pages.values():
            self._rail_icon(page)
        self._show_last_level()

    # ---- events ------------------------------------------------------------
    def _on_log(self, payload):
        level, text = payload
        t = time.strftime("%H:%M:%S")
        self.log_text.insert("end", f"{t}  ", "time", f"{text}\n", level)
        lines = int(self.log_text.index("end-1c").split(".")[0])
        if lines > LOG_LINES:
            self.log_text.delete("1.0", f"{lines - LOG_LINES}.0")
        self.log_text.see("end")
        set_var(self.last_log_var, f"{t}  {text}")
        if level != self._last_level:
            self._last_level = level
            self._show_last_level()
        if level == "error" and self.current_page != "log":
            self._set_badge("log", "err")

    def _show_last_level(self):
        p = self.theme.palette
        colour = {"error": p["err"][0], "warn": p["warn"][0]}.get(self._last_level, p["sub"])
        self.last_log.configure(foreground=colour)

    def _on_link_state(self, payload):
        """The active device's link (core/devices.py)."""
        state, info = payload
        name = info.get("name") or info.get("address")
        if state == LinkState.CONNECTED:
            if info.get("switched"):
                self.ctx.log(f"active device: {name}")
            else:
                self.ctx.log(f"connected to {name}")
            for f in self._built_features():
                f.on_connected(info)
            # The first board: on to the first feature; more boards: stay to connect them
            if (not info.get("switched") and self.current_page == "device" and self.features
                    and len(self.ctx.devices.connected()) <= 1):
                self.show_page("feature0")
        elif state == LinkState.IDLE and "reason" in info:     # logged by _on_devices
            for f in self._built_features():
                f.on_disconnected(info["reason"])
        self._reason = info.get("reason") if state == LinkState.IDLE else None
        self._show_header()

    def _on_devices(self, payload):
        """A board's link changed, or the active device or the scan."""
        session, state, info = payload
        if session is not None and state == LinkState.IDLE and "reason" in info:
            self._reason = info["reason"]              # the header says why the last link went
            self.ctx.log(f"{session.name or session.address}: {info['reason']}",
                         "warn" if info["reason"] == "link lost" else "info")
        if self.conn is not None:
            self.conn.show_devices(payload)
        for f in self._built_features():
            f.on_devices_changed()
        self._show_header()

    def _show_header(self):
        """The header's pill and line: the active device, and the others."""
        reason = self._reason
        devices = self.ctx.devices
        active = devices.active
        others = len([s for s in devices.sessions.values() if s is not active])
        more = f"  ·  +{others} more" if others else ""
        if active is not None:
            st = active.state
            self.status_pill.set(*STATE_PILL.get(st, (st.value, "idle")))
            line = f"{active.name or '?'} [{active.address}]"
            if active.connected:
                line += f"  ·  ATT MTU {active.link.mtu_size}"
            set_var(self.status_var, line + more)
        elif devices.scanning:
            self.status_pill.set(*STATE_PILL[LinkState.SCANNING])
            set_var(self.status_var, "Scanning…" + more)
        else:
            self.status_pill.set(*STATE_PILL[LinkState.IDLE])
            text = "No active device" if others else "Not connected"
            if reason and reason != "switched":
                text += f" ({reason})"
            set_var(self.status_var, text + more)

    def _on_close(self):
        if any(f.busy for f in self.features) and not messagebox.askyesno(
                "Exit", "A transfer is in progress. Abort it and exit?"):
            return
        for f in self._built_features():
            try:
                f.shutdown()
            except Exception:
                pass
        try:
            self.ctx.runner.submit(self.ctx.devices.disconnect_all()).result(timeout=3)
        except Exception:
            pass
        self.ctx.runner.stop()
        self.root.destroy()
