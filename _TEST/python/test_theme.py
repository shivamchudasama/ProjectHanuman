# SPDX-License-Identifier: MIT
"""The GUI's look: the flat theme and its switching (_TOOLS/BleHostGUI/blehost/ui/
theme.py), the display widgets (ui/widgets.py), the main window's navigation
rail and pages (ui/main_window.py), and the mappings the pages use to colour
their state (hex segment status, provisioning steps and device state). Also
that nothing is redrawn when what it shows has not changed (pills, step list,
tiles, the hex upload's progress), which is what keeps the window from
flickering. The images themselves are tested in test_icons.py.

The mappings and palettes need no display. The tests that create Tk widgets
are skipped where Tk has no display (headless CI).
"""

import types

import pytest

from blehost.context import AppContext
from blehost.core.ble_link import LinkState
from blehost.features import hex_upload as hu
from blehost.features import provisioning as fp
from blehost.protocols import provisioning as prov
from blehost.ui import theme as th


# ---- palettes ---------------------------------------------------------------------
def _luminance(hex_colour):
    def channel(c):
        c = int(c, 16) / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(hex_colour[i:i + 2]) for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


@pytest.mark.parametrize("mode", [th.LIGHT, th.DARK])
def test_palettes_have_every_key_and_readable_tones(mode):
    p = th.PALETTES[mode]
    assert set(p) == set(th.PALETTES[th.LIGHT])
    assert contrast(p["fg"], p["bg"]) >= 7
    assert contrast(p["sub"], p["bg"]) >= 4.5
    assert contrast(p["log_fg"], p["log_bg"]) >= 7
    for tone in th.TONES:
        fg, bg = p[tone]
        assert contrast(fg, bg) >= 4.5, f"{mode} {tone} on its pill"
        assert contrast(fg, p["bg"]) >= 4.5, f"{mode} {tone} on the window"


def test_terminal_colours_are_readable():
    t = th.TERMINAL
    for key in ("fg", "tx", "rx", "info"):
        assert contrast(t[key], t["bg"]) >= 4.5, key


def test_system_mode_is_light_or_dark():
    assert th.system_mode() in (th.LIGHT, th.DARK)


def test_system_mode_off_windows(monkeypatch):
    monkeypatch.setattr(th.sys, "platform", "linux")
    assert th.system_mode() == th.LIGHT


# ---- passive theme (a tab built on its own) ----------------------------------------
def test_of_falls_back_to_the_passive_light_theme():
    passive = th.of(types.SimpleNamespace())
    assert passive is th.of(types.SimpleNamespace(theme=None))
    assert passive.mode == th.LIGHT and passive.root is None
    own = th.Theme()
    assert th.of(types.SimpleNamespace(theme=own)) is own


def test_on_change_calls_back_at_once_and_apply_without_root_does_nothing():
    t = th.Theme(mode=th.DARK)
    seen = []
    t.on_change(seen.append)
    assert seen == [th.PALETTES[th.DARK]]
    t.apply(th.LIGHT)                     # no root: mode only, no callback
    assert t.mode == th.LIGHT and len(seen) == 1


def test_dark_mode_is_always_available():
    """The theme is drawn here, with no optional package behind it."""
    t = th.Theme(mode=th.DARK)
    assert t.available
    t.apply(th.DARK)
    assert t.mode == th.DARK


def test_px_and_spacing_follow_the_scale():
    t = th.Theme()
    assert t.scale == 1.0 and t.px(4) == 4 and t.sp("m") == th.SP["m"]
    t.scale = 1.5
    assert t.px(10) == 15 and t.sp("s") == 12
    assert t.px(0.2) == 1, "never less than a pixel"


def test_colorref():
    assert th._colorref("#123456") == 0x563412


def test_unknown_mode_and_tone_fall_back():
    t = th.Theme(mode="sepia")
    assert t.mode == th.LIGHT
    assert t.tone("nonsense") == t.palette["idle"]
    assert t.tone("err") == t.palette["err"]


# ---- what the pages show -------------------------------------------------------------
@pytest.mark.parametrize("text, tone", [
    ("pending", "idle"),
    ("sending", "info"),
    ("stored, 195 kbit/s", "ok"),
    ("aborted", "warn"),
    ("failed: NACK", "err"),
    ("STORED mismatch: ERR 0x00000000 0 B", "err"),
    ("", "idle"),
])
def test_segment_status_tone(text, tone):
    assert hu.status_tone(text) == tone


def test_every_upload_phase_has_a_pill():
    assert set(hu.PHASE_PILL) == {"nofile", "error", "ready", "uploading", "done", "failed", "aborted"}
    assert all(tone in th.TONES for _, tone in hu.PHASE_PILL.values())


def test_step_texts_match_the_session():
    """The step list follows the strings ProvisioningSession.provision() reports."""
    import inspect
    src = inspect.getsource(prov.ProvisioningSession)
    for text in fp.STEP_TEXTS:
        assert f'self.step("{text}")' in src
    assert len(fp.STEPS) == len(fp.STEP_TEXTS)


@pytest.mark.parametrize("text, current, expected", [
    ("", 3, (0, "idle")),
    ("reading device status", 0, (0, "running")),
    ("signing the CSR", 0, (2, "running")),
    ("provisioned", 4, (5, "done")),
    ("failed", 3, (3, "failed")),
    ("aborted", 1, (1, "aborted")),
    ("something else", 2, (2, "running")),
])
def test_step_position(text, current, expected):
    assert fp.step_position(text, current) == expected


@pytest.mark.parametrize("text, expected", [
    ("Device: -", ("Unknown", "idle")),
    ("Device: KEY_READY, CSR 371 B, key SHA-256 0001…", ("KEY_READY", "info")),
    ("Device: PROVISIONED, certificate serial 1a2b", ("PROVISIONED", "ok")),
    ("Device: NO_KEY, CSR 0 B, key SHA-256 00…", ("NO_KEY", "warn")),
    ("Device: 0x07, CSR 0 B", ("0x07", "idle")),
])
def test_device_pill(text, expected):
    assert fp.device_pill(text) == expected


# ---- with a display ----------------------------------------------------------------------
@pytest.fixture
def root(tk_root):
    return tk_root


def test_switching_recolours_text_and_title(root):
    import tkinter as tk
    t = th.Theme(root, th.LIGHT)
    t.apply()
    log, term = tk.Text(root), tk.Text(root)
    t.on_change(lambda p: th.style_text(log, p))
    t.on_change(lambda p: th.style_text(term, p, terminal=True))
    assert log.cget("background") == th.PALETTES[th.LIGHT]["log_bg"]
    calls = []
    t.on_change(calls.append)
    calls.clear()
    t.toggle()
    # Done when apply() returns: each listener is called once (no second
    # pass, no timer)
    assert t.mode == th.DARK and calls == [th.PALETTES[th.DARK]]
    assert log.cget("background") == th.PALETTES[th.DARK]["log_bg"]
    assert term.cget("background") == th.TERMINAL["bg"], "the terminal stays dark"
    assert log.tag_cget("error", "foreground") == th.PALETTES[th.DARK]["err"][0]
    root.update()
    assert log.cget("background") == th.PALETTES[th.DARK]["log_bg"], "nothing repaints it later"


def test_apply_draws_the_flat_theme_in_the_palette(root):
    """clam, coloured from the palette: no images behind buttons, fields,
    lists or scrollbars, which is what keeps redraws fast."""
    from tkinter import ttk
    s = ttk.Style(root)
    for mode in (th.LIGHT, th.DARK, th.LIGHT):
        t = th.Theme(root, mode)
        t.apply()
        p = th.PALETTES[mode]
        assert s.theme_use() == th.BASE_THEME == "clam"
        assert s.lookup("TButton", "background") == p["btn"]
        assert s.lookup("Accent.TButton", "background") == p["accent"]
        assert s.lookup("TEntry", "fieldbackground") == p["log_bg"]
        assert s.lookup("Treeview", "background") == p["log_bg"]
        assert s.lookup("Rail.TFrame", "background") == p["rail"]
        assert s.lookup("Rail.Toolbutton", "background", ["selected"]) == p["sel"]
        assert s.lookup("Caption.TLabel", "foreground") == p["sub"]
        for style in ("TButton", "Toggle.TButton", "TMenubutton"):
            assert str(s.lookup(style, "width")) == "0", f"{style}: as wide as its text and icon"
        assert str(root.cget("background")) == p["bg"]
        assert "arrow" not in str(s.layout("Vertical.TScrollbar")), "a thumb in a trough"


def test_check_box_and_switch_are_drawn_and_follow_the_mode(root):
    from tkinter import ttk
    from blehost.ui import icons
    if not icons.available():
        pytest.skip("Pillow not installed: clam's indicator")
    from PIL import ImageTk
    th.Theme(root, th.LIGHT).apply()
    s = ttk.Style(root)
    assert "Check.indicator" in s.element_names() and "Switch.indicator" in s.element_names()
    assert "Switch.indicator" in str(s.layout("Switch.TCheckbutton"))
    images = root._blehost_indicators
    on = images["switch_on"]
    light = ImageTk.getimage(on).getpixel((4, on.height() // 2))
    th.Theme(root, th.DARK).apply()          # a second theme on the same root: same images, redrawn
    assert root._blehost_indicators is images
    assert ImageTk.getimage(on).getpixel((4, on.height() // 2)) != light
    ttk.Checkbutton(root, text="Autoscroll", style="Switch.TCheckbutton").pack()
    root.update_idletasks()
    th.Theme(root, th.LIGHT).apply()


def test_more_menu_entries_enable_like_buttons(root):
    from blehost.ui import widgets
    t = th.Theme(root, th.LIGHT)
    more = widgets.MoreMenu(root, t)
    seen = []
    save = more.add("Save…", lambda: seen.append("save"))
    wipe = more.add("Remove…", lambda: seen.append("wipe"))
    assert save.enabled and wipe.enabled
    save.state(["disabled"])
    assert not save.enabled and wipe.enabled
    save.state(["!disabled"])
    assert save.enabled
    more.menu.invoke(1)
    assert seen == ["wipe"]
    t.apply(th.DARK)
    assert str(more.menu.cget("background")) == th.PALETTES[th.DARK]["btn"], "the menu follows the mode"
    t.apply(th.LIGHT)


def test_disclosure_title_and_fill(root):
    from blehost.ui import widgets
    t = th.Theme(root, th.LIGHT)
    d = widgets.Disclosure(root, "Segments", theme=t, fill="both")
    d.set_title("Segments (3)")
    assert d.title == "Segments (3)" and d.toggle_btn.cget("text").endswith("Segments (3)")
    d.set_open(True)
    assert d.body.pack_info()["fill"] == "both" and int(d.body.pack_info()["expand"])


def test_pill_stepper_tile_and_disclosure(root):
    from blehost.ui import widgets
    t = th.Theme(root, th.LIGHT)
    pill = widgets.Pill(root, t, "Idle", "idle")
    pill.set("Connected", "ok")
    assert (pill.text, pill.tone) == ("Connected", "ok")
    assert int(pill.cget("width")) > 40 and pill.find_all()
    width = int(pill.cget("width"))
    pill.set("Connected and more")                # keeps the tone, grows
    assert pill.tone == "ok" and int(pill.cget("width")) > width

    st = widgets.Stepper(root, t, fp.STEPS)
    st.show(*fp.step_position("signing the CSR"))
    assert (st.current, st.state) == (2, "running")
    st.show(99, "done")
    assert st.current == len(fp.STEPS) - 1
    for state in ("failed", "aborted", "idle"):
        st.show(1, state)
        assert st.find_all()

    tile = widgets.StatTile(root, "Rate", "–", "")
    tile.set("195 kbit/s", "current segment")
    assert tile.value_var.get() == "195 kbit/s" and tile.note_var.get() == "current segment"
    tile.set("200 kbit/s")
    assert tile.note_var.get() == "current segment"

    for theme in (None, t):
        d = widgets.Disclosure(root, "Advanced", theme=theme)
        assert not d.is_open
        d.toggle()
        assert d.is_open and d.toggle_btn.cget("text").endswith("Advanced")
        d.set_open(False)
        assert not d.is_open


def test_nothing_redraws_when_nothing_changed(root):
    """A timer or progress callback may set the same state again and again:
    that must not redraw (the cause of the once-a-second flash)."""
    from blehost.ui import widgets
    t = th.Theme(root, th.LIGHT)
    pill = widgets.Pill(root, t, "Idle", "idle")
    n, items = pill.redraws, pill.find_all()
    pill.set("Idle", "idle")
    pill.set("Idle")
    assert pill.redraws == n
    pill.set("Connected", "ok")
    assert pill.redraws == n + 1 and pill.find_all() == items, "items are reused, not recreated"

    st = widgets.Stepper(root, t, fp.STEPS)
    st.show(2, "running")
    n = st.redraws
    st.show(2, "running")
    assert st.redraws == n
    st.set_steps(fp.STEPS)
    assert st.redraws == n and st.current == 2, "the same steps: nothing changes"
    st.set_steps(["one", "two"])
    assert st.redraws == n + 1 and (st.current, st.state) == (0, "idle")
    assert int(st.cget("height")) == 2 * st.row

    writes = []
    var = __import__("tkinter").StringVar(root, "a")
    var.trace_add("write", lambda *a: writes.append(var.get()))
    widgets.set_var(var, "a")
    widgets.set_var(var, "b")
    widgets.set_var(var, "b")
    assert writes == ["b"]

    tile = widgets.StatTile(root, "Sent", "–", "")
    tile.value_var.trace_add("write", lambda *a: writes.append("tile"))
    tile.set("–", "")
    assert writes == ["b"]


def test_tile_labels_ask_for_a_fixed_width(root):
    """A new value must not change what the tiles ask for: the row stays put."""
    from blehost.ui import widgets
    tile = widgets.StatTile(root, "Sent", "–", "")
    tile.pack()
    root.update_idletasks()
    width = tile.winfo_reqwidth()
    tile.set("1,234,567 B", "a much longer note than before")
    root.update_idletasks()
    assert tile.winfo_reqwidth() == width


def test_pill_without_pillow_draws_tk_shapes(root, monkeypatch):
    from blehost.ui import icons, widgets
    monkeypatch.setattr(icons, "Image", None)
    t = th.Theme(root, th.LIGHT)
    pill = widgets.Pill(root, t, "Idle", "idle")
    assert len(pill.find_all()) > 2, "ovals, a bar, the dot and the text"
    pill.set("Connected", "ok")
    st = widgets.Stepper(root, t, fp.STEPS)
    st.show(1, "failed")
    assert st.find_all()


def test_set_icon_and_tooltip(root):
    from tkinter import ttk
    from blehost.ui import icons, widgets
    t = th.Theme(root, th.LIGHT)
    b = ttk.Button(root, text="Upload")
    widgets.set_icon(b, t, "upload")
    if icons.has_glyphs():
        assert b.cget("image") and str(b.cget("compound")) == "left"
    else:
        assert str(b.cget("compound")) == "none", "text only without an icon font"
    assert b.cget("text") == "Upload"

    tip = widgets.Tooltip(b, "Send the file", t)
    tip.show()
    assert tip.shown
    tip.hide()
    assert not tip.shown
    tip.text = ""
    tip.show()
    assert not tip.shown, "nothing to say, nothing shown"
    tip._schedule()
    tip.hide()                                    # cancels the pending show
    assert tip._after is None


def test_hex_progress_is_coalesced(root, monkeypatch):
    """Progress arrives once per ACK window; the tab shows the latest at most
    every PROGRESS_MS, and at once when the upload ends."""
    from blehost.features.hex_upload import HexUploadFeature
    ctx = AppContext()
    f = HexUploadFeature(ctx)
    f.build(root)
    f.segments = [(0, b"x" * 1000)]
    for done in range(100, 1001, 100):
        f._progress(0, done, 1000, 2000.0 if done == 300 else None)
    assert f.tile_sent.value_var.get() == "–", "nothing shown yet"
    assert f._progress_after is not None
    f._flush_progress()
    assert f.tile_sent.value_var.get() == "1,000 B" and f.tile_sent.note_var.get() == "100 %"
    assert f.tile_rate.value_var.get() == "16 kbit/s", "the last rate seen is kept"
    assert f._progress_after is None and f._pending_progress is None

    f._progress(0, 500, 1000, None)
    f._t_start = __import__("time").perf_counter()
    f._finished(1)                                # shows the pending progress first
    assert f._pending_progress is None and f._progress_after is None
    assert f.progress_var.get().startswith("done")
    f._flush_progress()                           # nothing pending: nothing happens


def test_hex_segments_section_counts_the_segments(root, tmp_path):
    from blehost.features.hex_upload import HexUploadFeature
    ctx = AppContext()
    f = HexUploadFeature(ctx)
    f.build(root)
    assert f.seg_section.title == "Segments" and not f.seg_section.is_open, "closed by default"
    hexfile = tmp_path / "two.hex"
    hexfile.write_text(":0400000001020304F2\n:0400100001020304E2\n:00000001FF\n")
    f.path_var.set(str(hexfile))
    assert f._load(quiet=True)
    assert f.seg_section.title == hu.segments_title(len(f.segments)) == "Segments (2)"
    assert len(f.tree.get_children()) == 2
    f.path_var.set(str(tmp_path / "missing.hex"))
    f._parsed = None
    assert not f._load(quiet=True)
    assert f.seg_section.title == "Segments"


class BoardLink:
    """A board's link for core/devices.py: connects at once, as BleLink reports it."""

    def __init__(self, label=""):
        self.label = label
        self.state = LinkState.IDLE
        self.info = {}
        self.on_state = None
        self.gatt = None
        self.mtu_size = 0

    @property
    def connected(self):
        return self.state == LinkState.CONNECTED

    def add_connect_hook(self, fn):
        pass

    def add_disconnect_hook(self, fn):
        pass

    def _set(self, state, **info):
        self.state, self.info = state, info
        if self.on_state:
            self.on_state(self, state, dict(info))

    async def connect(self, address, name="", timeout=15.0, device=None):
        self.gatt = types.SimpleNamespace(has_characteristic=lambda uuid: False)
        self.mtu_size = 247
        self._set(LinkState.CONNECTED, address=address, name=name, mtu=247)

    def drop(self, reason="link lost"):
        self.gatt, self.mtu_size = None, 0
        self._set(LinkState.IDLE, reason=reason)

    def device(self, address):
        return None


def pump(ctx):
    """Hand the bus's queued events to the window, as the Tk pump would."""
    import queue
    while True:
        try:
            topic, payload = ctx.bus._q.get_nowait()
        except queue.Empty:
            return
        for fn in ctx.bus._subs.get(topic, ()):
            fn(payload)


def test_main_window_builds_and_switches(root, monkeypatch):
    from blehost.features.hex_upload import HexUploadFeature
    from blehost.features.provisioning import ProvisioningFeature
    from blehost.protocols.setu import SETUService
    from blehost.ui import main_window as mw

    monkeypatch.setattr(th, "system_mode", lambda: th.LIGHT)
    monkeypatch.setattr(fp.CertificateAuthority, "exists", staticmethod(lambda folder: False))
    from blehost.core.devices import ActiveService, DeviceManager
    ctx = AppContext()
    ctx.devices = DeviceManager(ctx.bus, ctx.tap, make_link=BoardLink)
    ctx.devices.add_session_hook(
        lambda s: s.services.__setitem__(SETUService.NAME, SETUService(ctx, s.link)))
    ctx.services[SETUService.NAME] = ActiveService(ctx.devices, SETUService.NAME)
    ctx.services["pc_server"] = types.SimpleNamespace(available=False, subscribers=0, error="test",
                                                      receiver=None)
    win = mw.MainWindow(root, ctx, [HexUploadFeature, ProvisioningFeature])
    assert ctx.theme is win.theme and win.theme.mode == th.LIGHT
    assert win.status_pill.text == "Idle"
    assert win.current_page == "device" and win.title_var.get() == "Device"
    assert win.pages["log"].built, "the log is there from the start"
    assert not any(win.pages[k].built for k in ("feature0", "feature1", "traffic")), \
        "pages are built when first shown"
    assert [p.shortcut for p in win.pages.values()] == ["Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+L", "Ctrl+T"]

    def mapped():
        return [k for k, p in win.pages.items() if p.built and p.frame.winfo_manager()]
    assert mapped() == ["device"]

    # Connecting the first board leaves the window on the device page;
    # an unbuilt feature is not told (it shows the link when it is built)
    import asyncio
    asyncio.run(ctx.devices.connect("AA:00:00:00:00:01", "dev"))
    pump(ctx)
    assert win.status_pill.tone == "ok" and win.conn.name_var.get() == "dev"
    assert "ATT MTU 247" in win.status_var.get() and "more" not in win.status_var.get()
    assert win.current_page == "device" and mapped() == ["device"], "only the user changes pages"
    assert win.conn.dev_tree.set("AA:00:00:00:00:01", "state") == "Active"
    assert not any(win.pages[k].built for k in ("feature0", "feature1"))
    win.conn._caps_done((2, 244, 16, 247))
    assert win.conn._facts["Window"].get() == "16" and win.conn.details.is_open

    win.show_page("feature1")
    assert mapped() == ["feature1"] and win.page_var.get() == "feature1"
    assert win.title_var.get() == "Provisioning"
    prov_tab = win.features[1]
    assert prov_tab.pc_pill.text == "PC service: not available"
    prov_tab.dev_var.set("Device: PROVISIONED, certificate serial 1a2b")
    assert prov_tab.dev_pill.text == "PROVISIONED"
    prov_tab.step_var.set("requesting the CSR")
    assert prov_tab.stepper.current == 1

    assert win.mode_btn.mode == th.DARK and "dark" in win.mode_tip.text
    logo = str(win._logo.cget("image"))
    win._toggle_mode()
    assert str(win._logo.cget("image")) == logo, "the logo keeps its blue in dark mode"
    assert win.theme.mode == th.DARK and win.mode_var.get() == th.DARK
    assert win.mode_btn.mode == th.LIGHT and "light" in win.mode_tip.text

    n = prov_tab.pc_pill.redraws
    prov_tab._tick()                                   # the once-a-second refresh
    assert prov_tab.pc_pill.redraws == n, "unchanged: not redrawn"

    # The status line shows the latest log line; an error badges the Log button
    win._on_log(("error", "boom"))
    assert win.last_log_var.get().endswith("boom") and win.pages["log"].badge == "err"
    assert str(win.last_log.cget("foreground")) == th.PALETTES[th.DARK]["err"][0]
    assert "boom" in win.log_text.get("1.0", "end")
    win.show_page("log")
    assert win.pages["log"].badge is None, "seen"
    win._on_log(("error", "again"))
    assert win.pages["log"].badge is None, "on the log page: nothing to point at"
    win._on_log(("info", "fine"))
    assert str(win.last_log.cget("foreground")) == th.PALETTES[th.DARK]["sub"]

    # Ctrl+T: the traffic page, capturing; capture stays on on other pages
    win.open_traffic()
    assert win.current_page == "traffic" and ctx.tap.enabled and win.traffic.capture.get()
    assert win.pages["traffic"].badge == "info"
    win.show_page("device")
    assert ctx.tap.enabled
    win.traffic.set_capture(False)
    assert not ctx.tap.enabled and win.pages["traffic"].badge is None

    # A second board: the window stays on the device page, the header counts it
    first = ctx.devices.active
    asyncio.run(ctx.devices.connect("BB:00:00:00:00:02", "dev2"))
    pump(ctx)
    assert win.current_page == "device", "not sent away while connecting more boards"
    assert ctx.devices.active.name == "dev2" and "dev2" in win.status_var.get()
    assert win.status_var.get().endswith("+1 more")
    assert win.conn.dev_tree.set("AA:00:00:00:00:01", "state") == "Connected"
    assert "active device" not in win.log_text.get("1.0", "end")
    # Back to the first board: a switch, logged as such
    assert ctx.devices.set_active(first.address)
    pump(ctx)
    assert ctx.link is first.link and "[AA:00:00:00:00:01]" in win.status_var.get()
    assert "active device: dev" in win.log_text.get("1.0", "end")
    assert win.current_page == "device"

    # The active board's link drops: no active device until the user picks one
    first.link.drop()
    pump(ctx)
    assert win.status_pill.text == "Idle" and win.conn._facts["Window"].get() == "–"
    assert win.status_var.get() == "No active device (link lost)  ·  +1 more"
    assert "dev: link lost" in win.log_text.get("1.0", "end")
    ctx.devices.get("BB:00:00:00:00:02").link.drop("disconnected")
    pump(ctx)
    assert win.status_var.get() == "Not connected (disconnected)"
    win._set_mode(th.LIGHT)


def test_main_window_without_pillow_or_icon_font(root, monkeypatch):
    """No Pillow (so no glyphs either): the theme keeps clam's indicators, the
    rail and the theme button show text, and every page still builds."""
    from blehost.features.hex_upload import HexUploadFeature
    from blehost.features.provisioning import ProvisioningFeature
    from blehost.protocols.setu import SETUService
    from blehost.ui import icons
    from blehost.ui import main_window as mw

    monkeypatch.setattr(icons, "Image", None)
    monkeypatch.setattr(th, "system_mode", lambda: th.DARK)
    monkeypatch.setattr(fp.CertificateAuthority, "exists", staticmethod(lambda folder: False))
    ctx = AppContext()
    ctx.services[SETUService.NAME] = SETUService(ctx)
    ctx.services["pc_server"] = types.SimpleNamespace(available=False, subscribers=0, error="test",
                                                      receiver=None)
    win = mw.MainWindow(root, ctx, [HexUploadFeature, ProvisioningFeature])
    assert win.theme.mode == th.DARK
    assert str(win.mode_btn.cget("image")) == "" and win.mode_btn.cget("text") == "☀"
    for page in win.pages.values():
        assert str(page.button.cget("compound")) == "none" and page.button.cget("text") == page.label
        win.show_page(page.key)
    win._on_log(("error", "boom"))                   # a badge without an image: no error
    win._toggle_mode()
    assert win.theme.mode == th.LIGHT
