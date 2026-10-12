"""Anti-aliased images for the GUI, drawn with Pillow: pill backgrounds, step
markers, glyphs from Windows' icon font, and the window icon.

Tk's Canvas draws ovals and rounded ends without anti-aliasing, and Unicode
symbols come from whichever fallback font has them. Here shapes are drawn at
SS times their size and scaled down (LANCZOS), and button icons are glyphs of
Segoe Fluent Icons (Windows 11; Segoe MDL2 Assets on Windows 10), so both
stay smooth at any display scale.

    img = icons.pill(widget, w, h, "#dff6dd")                # PhotoImage
    img = icons.glyph(widget, "upload", 16, "#1c1c1c")       # or None
    img = icons.badged(widget, "log", 20, "#5d5d5d", "#c42b1c")  # glyph + dot, or None
    spec = icons.button_spec(widget, theme, "upload")        # for image=, or ""

Every image is cached by what it shows, so a redraw with the same arguments
reuses it, and the cache holds the reference Tk needs to keep it alive.
Sizes are in pixels at the display's scale: pass theme.px(n). Without Pillow,
or without an icon font (Linux), glyph() returns None and button_spec() "",
so a button keeps its text and loses only the icon.
"""

import os

try:
    from PIL import Image, ImageDraw, ImageFont, ImageTk
except ImportError:                                  # optional: plain shapes without it
    Image = None

SS = 4                                               # supersampling factor

# Segoe Fluent Icons / Segoe MDL2 Assets code points (same in both fonts)
GLYPHS = {
    "sun": "\uE706", "moon": "\uE708",
    "chevron_right": "\uE76C", "chevron_down": "\uE70D",
    "bluetooth": "\uE702", "search": "\uE721", "connect": "\uE71B", "disconnect": "\uE711",
    "info": "\uE946", "refresh": "\uE72C",
    "upload": "\uE898", "stop": "\uE733", "folder": "\uE838",
    "certificate": "\uEB95", "shield": "\uEA18", "save": "\uE74E", "delete": "\uE74D",
    "clear": "\uE75C", "traffic": "\uE9D9", "add": "\uE710", "pause": "\uE769",
    "device": "\uE772", "log": "\uE7C3", "more": "\uE712", "pair": "\uE72E",
    "files": "\uE8B7", "download": "\uE896", "play": "\uE768", "car": "\uE804",
}

_FONT_DIR = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts")
FONT_FILES = [os.path.join(_FONT_DIR, n) for n in ("SegoeIcons.ttf", "segmdl2.ttf")]

_cache = {}
_fonts = {}


def available() -> bool:
    """True when Pillow is installed (shapes are drawn smooth)."""
    return Image is not None


def clear_cache():
    """Forget every image (tests; a new Tk root)."""
    _cache.clear()
    _fonts.clear()


def _rgb(colour: str):
    return tuple(int(colour[i:i + 2], 16) for i in (1, 3, 5))


def _photo(master, key, draw):
    """The cached PhotoImage for key, or draw() -> PIL image, then cache it."""
    photo = _cache.get(key)
    if photo is None:
        photo = ImageTk.PhotoImage(draw(), master=master)
        _cache[key] = photo
    return photo


def _supersampled(w, h, paint):
    """paint(draw, k) on an SS-times larger transparent canvas, scaled down."""
    big = Image.new("RGBA", (w * SS, h * SS), (0, 0, 0, 0))
    paint(ImageDraw.Draw(big), SS)
    return big.resize((w, h), Image.LANCZOS)


# ---- shapes ------------------------------------------------------------------------
def pill(master, w: int, h: int, fill: str, dot: str = None, dot_d: int = 0, dot_x: int = 0):
    """A rounded bar w x h in fill, with an optional dot (diameter dot_d at
    x = dot_x, centred vertically). None without Pillow."""
    if not available():
        return None

    def paint(d, k):
        d.rounded_rectangle((0, 0, w * k - 1, h * k - 1), radius=h * k // 2, fill=_rgb(fill))
        if dot and dot_d:
            y = (h - dot_d) * k / 2
            d.ellipse((dot_x * k, y, (dot_x + dot_d) * k - 1, y + dot_d * k - 1), fill=_rgb(dot))
    return _photo(master, ("pill", w, h, fill, dot, dot_d, dot_x), lambda: _supersampled(w, h, paint))


MARKERS = ("done", "current", "failed", "pending")


def step_marker(master, kind: str, d: int, colour: str, mark: str = "#ffffff"):
    """A step-list marker, d x d: "done" (filled, tick in mark), "current"
    (ring and centre dot), "failed" (filled, cross in mark) or "pending"
    (ring). None without Pillow."""
    if not available():
        return None
    if kind not in MARKERS:
        raise ValueError(f"unknown marker {kind!r}")

    def paint(dr, k):
        s = d * k
        ring = max(k, round(s * 0.11))
        c, m = _rgb(colour), _rgb(mark)
        if kind in ("done", "failed"):
            dr.ellipse((0, 0, s - 1, s - 1), fill=c)
        else:
            dr.ellipse((ring / 2, ring / 2, s - 1 - ring / 2, s - 1 - ring / 2), outline=c, width=ring)
        if kind == "current":
            r = s * 0.22
            dr.ellipse((s / 2 - r, s / 2 - r, s / 2 + r, s / 2 + r), fill=c)
        elif kind == "done":
            dr.line([(s * 0.28, s * 0.52), (s * 0.44, s * 0.67), (s * 0.73, s * 0.36)],
                    fill=m, width=ring, joint="curve")
        elif kind == "failed":
            a, b = s * 0.33, s * 0.67
            dr.line([(a, a), (b, b)], fill=m, width=ring)
            dr.line([(b, a), (a, b)], fill=m, width=ring)
    return _photo(master, ("marker", kind, d, colour, mark), lambda: _supersampled(d, d, paint))


def check_box(d: int, fill: str, border: str, mark: str = None):
    """A check box indicator, d x d: a rounded square in fill with a 1-pixel
    border, ticked in mark when given. A PIL image (the theme draws it into a
    PhotoImage it keeps), or None without Pillow."""
    if not available():
        return None

    def paint(dr, k):
        s = d * k
        dr.rounded_rectangle((0, 0, s - 1, s - 1), radius=s * 0.22, fill=_rgb(border))
        dr.rounded_rectangle((k, k, s - 1 - k, s - 1 - k), radius=s * 0.22 - k, fill=_rgb(fill))
        if mark:
            dr.line([(s * 0.26, s * 0.52), (s * 0.43, s * 0.68), (s * 0.75, s * 0.34)],
                    fill=_rgb(mark), width=max(k, round(s * 0.11)), joint="curve")
    return _supersampled(d, d, paint)


def switch(w: int, h: int, track: str, border: str, knob: str, on: bool):
    """A switch indicator, w x h: a rounded track in track with a border, and
    the knob at the right when on. A PIL image, or None without Pillow."""
    if not available():
        return None

    def paint(dr, k):
        W, H = w * k, h * k
        dr.rounded_rectangle((0, 0, W - 1, H - 1), radius=H / 2, fill=_rgb(border))
        dr.rounded_rectangle((k, k, W - 1 - k, H - 1 - k), radius=H / 2 - k, fill=_rgb(track))
        r = H * 0.26
        cx = W - H / 2 if on else H / 2
        dr.ellipse((cx - r, H / 2 - r, cx + r, H / 2 + r), fill=_rgb(knob))
    return _supersampled(w, h, paint)


# ---- glyphs ------------------------------------------------------------------------
def _icon_font(size: int):
    """The first icon font found, at size pixels, or None."""
    if size not in _fonts:
        _fonts[size] = None
        for path in FONT_FILES:
            if os.path.exists(path):
                try:
                    _fonts[size] = ImageFont.truetype(path, size)
                    break
                except OSError:
                    continue
    return _fonts[size]


def has_glyphs() -> bool:
    """True when glyph() can draw (Pillow and an icon font)."""
    return available() and _icon_font(16) is not None


def _glyph_image(name: str, size: int, colour: str, box: int = None):
    """The glyph centred in a box x box (default size) transparent image."""
    box = box or size
    font = _icon_font(size)
    img = Image.new("RGBA", (box, box), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    l, t, r, b = d.textbbox((0, 0), GLYPHS[name], font=font)
    d.text(((box - (r - l)) / 2 - l, (box - (b - t)) / 2 - t), GLYPHS[name], font=font,
           fill=_rgb(colour))
    return img


def glyph(master, name: str, size: int, colour: str):
    """The icon glyph name (see GLYPHS) in a size x size image, or None
    without Pillow or an icon font."""
    if name not in GLYPHS:
        raise ValueError(f"unknown glyph {name!r}")
    if not has_glyphs():
        return None
    return _photo(master, ("glyph", name, size, colour), lambda: _glyph_image(name, size, colour))


def badged(master, name: str, size: int, colour: str, dot: str):
    """glyph() with a small dot in dot's colour at its top right (something
    new behind a navigation button), or None like glyph()."""
    if name not in GLYPHS:
        raise ValueError(f"unknown glyph {name!r}")
    if not has_glyphs():
        return None

    def draw():
        img = _glyph_image(name, size, colour)
        d = max(4, size // 3)
        img.alpha_composite(_supersampled(d, d, lambda dr, k: dr.ellipse(
            (0, 0, d * k - 1, d * k - 1), fill=_rgb(dot))), (size - d, 0))
        return img
    return _photo(master, ("badged", name, size, colour, dot), draw)


def button_spec(master, theme, name: str, accent: bool = False, size: int = 16,
                selected: str = None, badge: str = None):
    """A ttk image spec for a button showing glyph name: (normal, "disabled",
    dimmed) in the theme's colours (on_accent for an Accent.TButton), or ""
    when glyphs are not available. selected: a palette key for the glyph's
    colour in the "selected" state (a navigation button); badge: a colour for
    a dot on the normal and selected glyphs. size in pixels at 100 %. Ask
    again after a theme switch."""
    p = theme.palette
    px = theme.px(size)

    def image(colour):
        if badge:
            return badged(master, name, px, colour, badge)
        return glyph(master, name, px, colour)
    normal = image(p["on_accent"] if accent else (p["sub"] if selected else p["fg"]))
    if normal is None:
        return ""
    spec = [normal]
    if selected:
        spec += ["selected", image(p[selected]), "active", image(p["fg"])]
    spec += ["disabled", glyph(master, name, px, p["sub"])]
    return tuple(spec)


# ---- window icon ---------------------------------------------------------------------
APP_ICON_SIZES = (16, 32, 48, 256)


def app_icon(master, accent: str = "#005fb8", sizes=APP_ICON_SIZES):
    """The window icon (a rounded accent square with the Bluetooth glyph) in
    each size, for root.iconphoto(True, *images). [] without Pillow."""
    if not available():
        return []

    def draw(n):
        img = _supersampled(n, n, lambda d, k: d.rounded_rectangle(
            (0, 0, n * k - 1, n * k - 1), radius=n * k * 0.22, fill=_rgb(accent)))
        if _icon_font(max(8, int(n * 0.62))) is not None:
            mark = _glyph_image("bluetooth", max(8, int(n * 0.62)), "#ffffff", box=n)
            img.alpha_composite(mark)
        return img
    return [_photo(master, ("app", n, accent), lambda n=n: draw(n)) for n in sizes]
