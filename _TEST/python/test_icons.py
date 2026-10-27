# SPDX-License-Identifier: MIT
"""The GUI's images (_TOOLS/BleHostGUI/blehost/ui/icons.py): smooth pills, step
markers, check box and switch indicators drawn with Pillow, glyphs from
Windows' icon font (with a badge dot for the navigation rail), the window
icon, and what happens without Pillow or without an icon font (Linux CI): no
image, and the widgets keep their text.

Glyph tests that need the icon font are skipped where it is missing.
"""

import pytest

from blehost.ui import icons
from blehost.ui import theme as th

PIL = pytest.importorskip("PIL", reason="Pillow draws the GUI's images")
from PIL import ImageTk  # noqa: E402

needs_font = pytest.mark.skipif(not icons.has_glyphs(), reason="no Segoe icon font (not Windows)")


@pytest.fixture
def root(tk_root):
    icons.clear_cache()
    yield tk_root
    icons.clear_cache()


def near(pixel, rgb, tol=2):
    """pixel's colour is rgb, give or take the resampling's rounding."""
    return all(abs(a - b) <= tol for a, b in zip(pixel[:3], rgb))


def pixels(photo):
    """The RGBA PIL image behind a PhotoImage."""
    return ImageTk.getimage(photo)


# ---- shapes ------------------------------------------------------------------------
def test_pill_is_the_size_asked_cached_and_per_colour(root):
    a = icons.pill(root, 80, 22, "#dff6dd", "#0e700e", 7, 11)
    assert (a.width(), a.height()) == (80, 22)
    assert icons.pill(root, 80, 22, "#dff6dd", "#0e700e", 7, 11) is a, "cached"
    assert icons.pill(root, 80, 22, "#fde7e9", "#c42b1c", 7, 11) is not a


def test_pill_edges_are_anti_aliased(root):
    img = pixels(icons.pill(root, 80, 22, "#005fb8"))
    alphas = {img.getpixel((x, y))[3] for x in range(6) for y in range(22)}
    assert 0 in alphas and 255 in alphas, "transparent corners, solid body"
    assert any(0 < a < 255 for a in alphas), "partly covered edge pixels: smooth, not jagged"
    assert img.getpixel((40, 11))[:3] == (0x00, 0x5f, 0xb8)


def test_pill_dot(root):
    img = pixels(icons.pill(root, 80, 22, "#ffffff", "#000000", 8, 10))
    assert img.getpixel((14, 11))[:3] == (0, 0, 0), "the dot"
    assert img.getpixel((40, 11))[:3] == (255, 255, 255), "the bar"


@pytest.mark.parametrize("kind", icons.MARKERS)
def test_step_markers(root, kind):
    m = icons.step_marker(root, kind, 18, "#005fb8", "#ffffff")
    assert (m.width(), m.height()) == (18, 18)
    img = pixels(m)
    centre = img.getpixel((9, 9))
    if kind == "pending":
        assert centre[3] == 0, "a ring: empty inside"
    else:
        assert centre[3] > 0
    alphas = {img.getpixel((x, y))[3] for x in range(18) for y in range(18)}
    assert any(0 < a < 255 for a in alphas), "partly covered edge pixels: smooth"


def test_step_markers_differ_and_reject_unknown_kinds(root):
    shots = {k: pixels(icons.step_marker(root, k, 18, "#005fb8")).tobytes() for k in icons.MARKERS}
    assert len(set(shots.values())) == len(icons.MARKERS)
    with pytest.raises(ValueError):
        icons.step_marker(root, "sideways", 18, "#005fb8")


def test_shapes_scale(root):
    t = th.Theme()
    t.scale = 1.5
    m = icons.step_marker(root, "done", t.px(18), "#005fb8")
    assert m.width() == 27


def test_check_box(root):
    off = icons.check_box(16, "#ffffff", "#5d5d5d")
    on = icons.check_box(16, "#005fb8", "#005fb8", "#ffffff")
    assert off.size == on.size == (16, 16)
    assert off.getpixel((8, 8))[:3] == (255, 255, 255), "empty inside"
    assert off.getpixel((0, 0))[3] < 255, "rounded corner"
    assert any(on.getpixel((x, y))[:3] == (255, 255, 255) for x in range(16) for y in range(16)), "the tick"
    assert near(on.getpixel((8, 2)), (0x00, 0x5f, 0xb8)), "filled, clear of the tick"


def test_switch(root):
    off = icons.switch(34, 18, "#ffffff", "#5d5d5d", "#5d5d5d", False)
    on = icons.switch(34, 18, "#005fb8", "#005fb8", "#ffffff", True)
    assert off.size == on.size == (34, 18)
    assert off.getpixel((9, 9))[:3] == (0x5d, 0x5d, 0x5d), "knob at the left when off"
    assert off.getpixel((25, 9))[:3] == (255, 255, 255)
    assert on.getpixel((25, 9))[:3] == (255, 255, 255), "knob at the right when on"
    assert on.getpixel((9, 9))[:3] == (0x00, 0x5f, 0xb8)
    assert off.getpixel((0, 0))[3] == 0, "rounded ends"


# ---- glyphs ------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["device", "log", "more", "traffic", "upload", "shield"])
def test_rail_and_menu_glyphs_exist(name):
    assert name in icons.GLYPHS


def test_unknown_glyph(root):
    with pytest.raises(ValueError):
        icons.glyph(root, "kettle", 16, "#000000")


@needs_font
def test_glyph(root):
    g = icons.glyph(root, "upload", 16, "#1c1c1c")
    assert (g.width(), g.height()) == (16, 16)
    img = pixels(g)
    assert any(img.getpixel((x, y))[3] for x in range(16) for y in range(16)), "something drawn"
    assert icons.glyph(root, "upload", 16, "#1c1c1c") is g


@needs_font
@pytest.mark.parametrize("size", [16, 20, 24, 30])
def test_every_glyph_is_whole_and_centred(root, size):
    """The ink, measured on the rendered pixels, fills its box with even
    margins: centring on Pillow's textbbox() (a pixel below the ink's top for
    the icon fonts) cut the top row of Files, ECU, Device, Scan, Connect, …"""
    for name in icons.GLYPHS:
        img = pixels(icons.glyph(root, name, size, "#000000"))
        assert img.size == (size, size), name
        l, t, r, b = img.getchannel("A").getbbox()
        assert abs(l - (size - r)) <= 1 and abs(t - (size - b)) <= 1, f"{name} at {size}: not centred"
        free = icons._glyph_ink(name, size)
        if free.width <= size and free.height <= size:
            assert (r - l, b - t) == free.size, f"{name} at {size}: ink cut"
        else:
            assert l == 0 or r == size or t == 0 or b == size, f"{name} at {size}: shrunk to fit, no more"


@needs_font
def test_button_spec(root):
    t = th.Theme(mode=th.DARK)
    spec = icons.button_spec(root, t, "save")
    normal, state, dimmed = spec
    assert state == "disabled" and normal is not dimmed
    accent = icons.button_spec(root, t, "save", accent=True)
    assert accent[0] is not normal, "on_accent colour on an accent button"


@needs_font
def test_button_spec_for_the_rail(root):
    """A rail button: dimmed glyph, accent when selected, full colour on hover."""
    t = th.Theme(mode=th.LIGHT)
    spec = icons.button_spec(root, t, "log", size=20, selected="accent")
    assert spec[1::2] == ("selected", "active", "disabled")
    assert spec[0].width() == 20
    assert len({id(i) for i in spec[0::2]}) == 3, "normal, selected and active differ"
    badged = icons.button_spec(root, t, "log", size=20, selected="accent", badge="#c42b1c")
    assert badged[0] is not spec[0], "the badge is another image"


@needs_font
def test_badged_glyph(root):
    plain = pixels(icons.glyph(root, "log", 20, "#5d5d5d"))
    dot = pixels(icons.badged(root, "log", 20, "#5d5d5d", "#c42b1c"))
    assert near(dot.getpixel((17, 2)), (0xc4, 0x2b, 0x1c)), "a dot at the top right"
    assert plain.getpixel((17, 2)) != dot.getpixel((17, 2))
    assert icons.badged(root, "log", 20, "#5d5d5d", "#c42b1c") is icons.badged(
        root, "log", 20, "#5d5d5d", "#c42b1c"), "cached"
    with pytest.raises(ValueError):
        icons.badged(root, "kettle", 20, "#000000", "#ff0000")


def test_without_an_icon_font_there_are_no_glyphs(root, monkeypatch):
    monkeypatch.setattr(icons, "FONT_FILES", ["/nonexistent/SegoeIcons.ttf"])
    icons.clear_cache()
    assert not icons.has_glyphs()
    assert icons.glyph(root, "upload", 16, "#000000") is None
    assert icons.button_spec(root, th.Theme(), "upload") == ""
    assert icons.app_icon(root, sizes=(16,))[0].width() == 16, "the icon, without its mark"


def test_without_pillow_there_are_no_images(root, monkeypatch):
    monkeypatch.setattr(icons, "Image", None)
    assert not icons.available() and not icons.has_glyphs()
    assert icons.pill(root, 80, 22, "#ffffff") is None
    assert icons.step_marker(root, "done", 18, "#005fb8") is None
    assert icons.glyph(root, "upload", 16, "#000000") is None
    assert icons.app_icon(root) == []
    assert icons.check_box(16, "#ffffff", "#000000") is None
    assert icons.switch(34, 18, "#ffffff", "#000000", "#000000", True) is None
    assert icons.badged(root, "log", 20, "#000000", "#ff0000") is None


# ---- window icon ---------------------------------------------------------------------
def test_app_icon_sizes(root):
    imgs = icons.app_icon(root, "#005fb8")
    assert [i.width() for i in imgs] == list(icons.APP_ICON_SIZES)
    big = pixels(imgs[-1])
    assert big.getpixel((0, 0))[3] == 0, "rounded corner"
    assert big.getpixel((20, 128))[:3] == (0x00, 0x5f, 0xb8)
    root.iconphoto(False, *imgs)
