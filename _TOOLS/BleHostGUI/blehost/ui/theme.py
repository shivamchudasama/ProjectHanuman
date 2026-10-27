"""Look and feel: a flat Windows 11-like ttk theme in light or dark mode, built
on ttk's "clam", plus the few styles and colours the panels share.

    theme = Theme(root)          # MainWindow does this and puts it in ctx.theme
    theme.apply("dark")          # or theme.toggle()
    theme.on_change(fn)          # fn(palette) now and after every switch

Every element is drawn with Tk primitives (rectangles and text), no images.
Image themes (sv-ttk, used before) draw each button, entry, tab and
scrollbar as a stretched alpha-blended PNG, which Tk on Windows blends in
software on every redraw: a theme switch took 400-750 ms, a tab switch about
200 ms and a window resize up to 1.5 s. Here they take about 80, 30 and 150 ms.

ttk widgets follow the theme by themselves. Classic Tk widgets (Text, Canvas,
Menu) and Treeview row tags do not: a panel registers an on_change callback
that recolours them. Sizes in pixels go through px(), so they follow the
display scale.

A panel built without a window theme (a test building one tab) gets the
passive light theme from of(ctx): on_change still calls back once, apply does
nothing.
"""

import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

LIGHT, DARK = "light", "dark"

# Status tones: (foreground, background) per mode. Foregrounds keep 4.5:1 on
# their background and on the window background.
PALETTES = {
    LIGHT: {
        "bg": "#fafafa", "fg": "#1c1c1c", "sub": "#5d5d5d", "border": "#e5e5e5",
        "accent": "#005fb8", "accent_hover": "#1a6fc0", "on_accent": "#ffffff", "track": "#d6d6d6",
        "log_bg": "#ffffff", "log_fg": "#1c1c1c",
        "btn": "#ffffff", "btn_border": "#d1d1d1", "hover": "#f0f0f0", "pressed": "#e6e6e6",
        "rail": "#f0f0f0", "sel": "#dce9f7",
        "ok": ("#0e700e", "#dff6dd"), "info": ("#005fb8", "#e5f0fb"),
        "warn": ("#8a5300", "#fff4ce"), "err": ("#c42b1c", "#fde7e9"),
        "idle": ("#5d5d5d", "#ebebeb"),
    },
    DARK: {
        "bg": "#1c1c1c", "fg": "#fafafa", "sub": "#c5c5c5", "border": "#3a3a3a",
        "accent": "#57c8ff", "accent_hover": "#4cb6e8", "on_accent": "#000000", "track": "#4a4a4a",
        "log_bg": "#232323", "log_fg": "#e6e6e6",
        "btn": "#2d2d2d", "btn_border": "#454545", "hover": "#383838", "pressed": "#262626",
        "rail": "#202020", "sel": "#16384a",
        "ok": ("#6ccb5f", "#1f3a1d"), "info": ("#99ebff", "#0e3a4f"),
        "warn": ("#fce100", "#433519"), "err": ("#ff99a4", "#442726"),
        "idle": ("#c5c5c5", "#2d2d2d"),
    },
}
TONES = ("ok", "info", "warn", "err", "idle")

# The traffic monitor stays a dark terminal in both modes
TERMINAL = {"bg": "#1e1e1e", "fg": "#d4d4d4", "tx": "#4fc1ff", "rx": "#b5cea8", "info": "#9d9d9d"}

# Spacing scale (pixels at 100 %); use Theme.sp() for the display's scale
SP = {"xs": 4, "s": 8, "m": 12, "l": 16}

UI = ("Segoe UI Variable Text", "Segoe UI", "Cantarell", "DejaVu Sans")
MONO = ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Courier New")

# Tk's named fonts -> our font that replaces them (classic and ttk widgets)
NAMED_FONTS = {"TkDefaultFont": "body", "TkTextFont": "body", "TkMenuFont": "body",
               "TkHeadingFont": "strong", "TkCaptionFont": "strong", "TkTooltipFont": "caption",
               "TkSmallCaptionFont": "caption", "TkIconFont": "body"}

BASE_THEME = "clam"


def system_mode() -> str:
    """Windows' app mode (Settings > Personalization > Colors); light elsewhere."""
    if sys.platform != "win32":
        return LIGHT
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return LIGHT if winreg.QueryValueEx(k, "AppsUseLightTheme")[0] else DARK
    except OSError:
        return LIGHT


def _family(root, names, default):
    try:
        have = set(tkfont.families(root))
    except tk.TclError:
        return default
    return next((n for n in names if n in have), default)


# DWM window attributes (Windows 10 20H1+ / 11)
_DWMWA_USE_IMMERSIVE_DARK_MODE, _DWMWA_CAPTION_COLOR = 20, 35


def _colorref(colour: str) -> int:
    """'#rrggbb' as a Win32 COLORREF (0x00bbggrr)."""
    r, g, b = (int(colour[i:i + 2], 16) for i in (1, 3, 5))
    return r | g << 8 | b << 16


class Theme:
    def __init__(self, root=None, mode: str = LIGHT):
        self.root = root
        self.mode = mode if mode in PALETTES else LIGHT
        self._listeners = []
        self._based = False
        try:
            self.scale = root.winfo_fpixels("1i") / 96 if root else 1.0
        except tk.TclError:
            self.scale = 1.0
        ui = _family(root, UI, "TkDefaultFont") if root else "Segoe UI"
        mono = _family(root, MONO, "TkFixedFont") if root else "Consolas"
        self.fonts = {
            "body": (ui, 10), "caption": (ui, 9), "strong": (ui, 10, "bold"),
            "title": (ui, 12, "bold"), "value": (ui, 15, "bold"), "mono": (mono, 9),
        }

    @property
    def available(self) -> bool:
        """Dark mode is available (always: the theme is drawn here)."""
        return True

    @property
    def palette(self) -> dict:
        return PALETTES[self.mode]

    def tone(self, name: str):
        """(foreground, background) of a status tone."""
        return self.palette.get(name, self.palette["idle"])

    def px(self, n) -> int:
        """n pixels at 100 % in pixels at the display's scale (at least 1)."""
        return max(1, round(n * self.scale))

    def sp(self, name: str) -> int:
        """A step of the spacing scale SP, scaled."""
        return self.px(SP[name])

    # ---- switching -----------------------------------------------------------
    def apply(self, mode: str = None):
        """Switch to mode (default: the current one). Tk thread."""
        if mode in PALETTES:
            self.mode = mode
        if self.root is None:
            return
        if not self._based:                      # once: a theme_use re-lays out everything
            ttk.Style(self.root).theme_use(BASE_THEME)
            self._named_fonts()
            self._based = True
        self._configure_styles()
        self.root.configure(background=self.palette["bg"])
        self.title_bar()
        self._notify()

    def toggle(self):
        self.apply(DARK if self.mode == LIGHT else LIGHT)

    def on_change(self, fn):
        """fn(palette) now and after every switch. Tk thread."""
        self._listeners.append(fn)
        fn(self.palette)

    def _notify(self):
        for fn in list(self._listeners):
            try:
                fn(self.palette)
            except tk.TclError:                      # widget already destroyed
                self._listeners.remove(fn)

    # ---- styles ----------------------------------------------------------------
    def _named_fonts(self):
        """Tk's named fonts in our families and sizes: classic widgets, menus,
        entries and tree headings pick them up."""
        for name, ours in NAMED_FONTS.items():
            try:
                f = tkfont.nametofont(name, root=self.root)
            except tk.TclError:
                continue
            family, size, *style = self.fonts[ours]
            f.configure(family=family, size=size, weight="bold" if "bold" in style else "normal")

    def _configure_styles(self):
        """Every style the panels use, in the current palette."""
        p, f, px = self.palette, self.fonts, self.px
        s = ttk.Style(self.root)
        bg, fg, sub = p["bg"], p["fg"], p["sub"]

        def flat(style, colour, **kw):
            """A border-less look: clam's 3-D edges in the fill colour."""
            s.configure(style, background=colour, bordercolor=kw.pop("border", colour),
                        lightcolor=colour, darkcolor=colour, **kw)

        def states(style, **colours):
            """Map background (and its clam edges) and foreground per state."""
            fills = colours.pop("background", None)
            if fills:
                s.map(style, background=fills, lightcolor=fills, darkcolor=fills)
            if colours:
                s.map(style, **colours)

        s.configure(".", background=bg, foreground=fg, troughcolor=p["track"],
                    fieldbackground=p["log_bg"], selectbackground=p["accent"],
                    selectforeground=p["on_accent"], insertcolor=fg, focuscolor=p["accent"],
                    bordercolor=p["border"], lightcolor=bg, darkcolor=bg, font=f["body"])
        s.map(".", foreground=[("disabled", sub)])

        # Frames, labels, separators
        s.configure("TFrame", background=bg)
        flat("Card.TFrame", bg, border=p["border"], relief="solid", borderwidth=1)
        s.configure("TLabel", background=bg, foreground=fg)
        s.configure("Caption.TLabel", foreground=sub, font=f["caption"])
        s.configure("Strong.TLabel", font=f["strong"])
        s.configure("Title.TLabel", font=f["title"])
        s.configure("Value.TLabel", font=f["value"])
        s.configure("Mono.TLabel", font=f["mono"])
        s.configure("MonoCaption.TLabel", foreground=sub, font=f["mono"])
        s.configure("Link.TLabel", foreground=p["accent"], font=f["body"])
        s.map("Link.TLabel", foreground=[("disabled", sub), ("active", p["accent_hover"])])
        s.configure("TSeparator", background=p["border"])

        # Buttons
        pad = (px(12), px(5))
        # clam's raised relief draws the border; its bevel is in the fill colour (flat)
        # width 0: as wide as the text and icon (clam asks for 11 characters at least)
        flat("TButton", p["btn"], border=p["btn_border"], foreground=fg, relief="raised",
             padding=pad, space=px(6), anchor="center", focusthickness=1, width=0)
        states("TButton", background=[("disabled", bg), ("pressed", p["pressed"]),
                                      ("active", p["hover"])])
        flat("Accent.TButton", p["accent"], border=p["accent"], foreground=p["on_accent"])
        states("Accent.TButton",
               background=[("disabled", p["btn"]), ("pressed", p["accent"]),
                           ("active", p["accent_hover"])],
               bordercolor=[("disabled", p["btn_border"])],
               foreground=[("disabled", sub)])
        s.configure("Danger.TButton", foreground=p["err"][0])
        flat("Toggle.TButton", p["btn"], border=p["btn_border"], padding=pad, space=px(6), width=0)
        states("Toggle.TButton",
               background=[("disabled", bg), ("selected", p["sel"]), ("pressed", p["pressed"]),
                           ("active", p["hover"])],
               bordercolor=[("selected", p["accent"])],
               foreground=[("disabled", sub), ("selected", p["accent"])])
        flat("Toolbutton", bg, relief="flat", padding=(px(8), px(4)), space=px(6))
        states("Toolbutton", background=[("disabled", bg), ("pressed", p["pressed"]),
                                         ("selected", p["sel"]), ("active", p["hover"])])
        s.configure("TMenubutton", padding=pad, arrowcolor=fg, arrowsize=px(4), width=0)
        flat("TMenubutton", p["btn"], border=p["btn_border"])
        states("TMenubutton", background=[("disabled", bg), ("pressed", p["pressed"]),
                                          ("active", p["hover"])],
               arrowcolor=[("disabled", sub)])

        # Navigation rail
        s.configure("Rail.TFrame", background=p["rail"])
        s.configure("Rail.TLabel", background=p["rail"])
        flat("Rail.Toolbutton", p["rail"], foreground=sub, font=f["caption"], relief="flat",
             padding=(px(6), px(8)), anchor="center")
        states("Rail.Toolbutton",
               background=[("selected", p["sel"]), ("pressed", p["pressed"]), ("active", p["hover"])],
               foreground=[("selected", p["accent"]), ("active", fg)])

        # Check buttons: clam's indicator in the accent when on, replaced by
        # a drawn check box and switch where Pillow is installed
        ind = dict(indicatorbackground=p["btn"], indicatorforeground=p["on_accent"],
                   upperbordercolor=p["btn_border"], lowerbordercolor=p["btn_border"],
                   indicatormargin=(0, 0, px(6), 0), indicatorsize=px(14))
        for style in ("TCheckbutton", "Switch.TCheckbutton", "TRadiobutton"):
            s.configure(style, background=bg, foreground=fg, **ind)
            s.map(style, indicatorbackground=[("disabled", bg), ("selected", p["accent"]),
                                              ("active", p["hover"])],
                  upperbordercolor=[("selected", p["accent"])],
                  lowerbordercolor=[("selected", p["accent"])],
                  background=[("active", bg)])
        self._indicators(s)

        # Fields
        field = dict(fieldbackground=p["log_bg"], foreground=fg, bordercolor=p["btn_border"],
                     lightcolor=p["log_bg"], darkcolor=p["log_bg"], insertcolor=fg,
                     padding=(px(6), px(4)))
        for style in ("TEntry", "TCombobox", "TSpinbox"):
            s.configure(style, **field)
            s.map(style, bordercolor=[("focus", p["accent"])], lightcolor=[("focus", p["accent"])],
                  fieldbackground=[("disabled", bg), ("readonly", p["log_bg"])],
                  foreground=[("disabled", sub)])
        s.configure("TCombobox", background=p["btn"], arrowcolor=fg, arrowsize=px(12))
        s.map("TCombobox", background=[("active", p["hover"])],
              selectbackground=[("readonly", p["log_bg"])], selectforeground=[("readonly", fg)])
        for opt, value in (("background", p["log_bg"]), ("foreground", fg),
                           ("selectBackground", p["accent"]), ("selectForeground", p["on_accent"])):
            self.root.option_add(f"*TCombobox*Listbox.{opt}", value)

        # Lists
        line = tkfont.Font(root=self.root, font=f["body"]).metrics("linespace")
        s.configure("Treeview", background=p["log_bg"], fieldbackground=p["log_bg"], foreground=fg,
                    bordercolor=p["border"], lightcolor=p["log_bg"], darkcolor=p["log_bg"],
                    rowheight=int(line * 1.9))
        s.map("Treeview", background=[("selected", p["sel"])], foreground=[("selected", fg)])
        flat("Treeview.Heading", bg, border=p["border"], foreground=sub, font=f["caption"],
             relief="flat", padding=(px(6), px(4)))
        states("Treeview.Heading", background=[("active", p["hover"])])

        # Scrollbars: a thumb in a trough, no arrows
        for orient, sticky in (("Vertical", "ns"), ("Horizontal", "ew")):
            style = f"{orient}.TScrollbar"
            s.layout(style, [(f"{orient}.Scrollbar.trough", {"sticky": sticky, "children": [
                (f"{orient}.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
            flat(style, p["track"], troughcolor=bg, arrowsize=px(8), gripcount=0)
            s.configure(style, bordercolor=bg)
            states(style, background=[("pressed", sub), ("active", sub)])

        # Progress
        for orient in ("Horizontal", "Vertical"):
            flat(f"{orient}.TProgressbar", p["accent"], troughcolor=p["track"],
                 border=p["track"], thickness=px(6))

        # Notebook (not used by the window; kept consistent for a panel that wants one)
        s.configure("TNotebook", background=bg, bordercolor=p["border"])
        flat("TNotebook.Tab", bg, padding=(self.sp("l"), px(6)))
        states("TNotebook.Tab", background=[("selected", p["btn"]), ("active", p["hover"])])

        # Classic widgets created from now on (menus, tooltips)
        for opt, value in (("Menu.background", p["btn"]), ("Menu.foreground", fg),
                           ("Menu.activeBackground", p["sel"]), ("Menu.activeForeground", fg),
                           ("Menu.disabledForeground", sub), ("Menu.selectColor", p["accent"]),
                           ("Menu.relief", "flat"), ("Menu.borderWidth", 1)):
            self.root.option_add(f"*{opt}", value)

    def _indicators(self, s):
        """A rounded check box (TCheckbutton) and a switch (Switch.TCheckbutton)
        drawn with Pillow. Fixed-size images, unlike sv-ttk's stretched ones,
        cost nothing to draw. The elements are made once per Tk root, and
        their images are redrawn in place on every switch. Without Pillow,
        clam's indicator stays."""
        from . import icons
        if not icons.available():
            return
        from PIL import ImageTk
        p = self.palette
        d, w, h = self.px(16), self.px(34), self.px(18)
        drawn = {
            "check_off": icons.check_box(d, p["btn"], p["sub"]),
            "check_hover": icons.check_box(d, p["hover"], p["fg"]),
            "check_on": icons.check_box(d, p["accent"], p["accent"], p["on_accent"]),
            "check_dis": icons.check_box(d, p["bg"], p["border"]),
            "check_dis_on": icons.check_box(d, p["track"], p["track"], p["bg"]),
            "switch_off": icons.switch(w, h, p["btn"], p["sub"], p["sub"], False),
            "switch_hover": icons.switch(w, h, p["hover"], p["fg"], p["fg"], False),
            "switch_on": icons.switch(w, h, p["accent"], p["accent"], p["on_accent"], True),
            "switch_dis": icons.switch(w, h, p["bg"], p["border"], p["border"], False),
            "switch_dis_on": icons.switch(w, h, p["track"], p["track"], p["bg"], True),
        }
        gap = self.px(8)                                 # between the indicator and its text
        for k, img in drawn.items():
            wide = icons.Image.new("RGBA", (img.width + gap, img.height), (0, 0, 0, 0))
            wide.paste(img, (0, 0))
            drawn[k] = wide
        images = getattr(self.root, "_blehost_indicators", None)
        if images is None:
            images = {k: ImageTk.PhotoImage(img, master=self.root) for k, img in drawn.items()}
            self.root._blehost_indicators = images      # kept with the root they belong to
        else:
            for k, img in drawn.items():
                images[k].paste(img)
        names = s.element_names()
        for kind, style in (("check", "TCheckbutton"), ("switch", "Switch.TCheckbutton")):
            element = f"{kind.capitalize()}.indicator"
            if element not in names:
                s.element_create(element, "image", images[f"{kind}_off"],
                                 ("disabled selected", images[f"{kind}_dis_on"]),
                                 ("disabled", images[f"{kind}_dis"]),
                                 ("selected", images[f"{kind}_on"]),
                                 ("active", images[f"{kind}_hover"]),
                                 sticky="")
            s.layout(style, [("Checkbutton.padding", {"sticky": "nswe", "children": [
                (element, {"side": "left", "sticky": ""}),
                ("Checkbutton.focus", {"side": "left", "sticky": "w", "children": [
                    ("Checkbutton.label", {"sticky": "nswe"})]})]})])

    def title_bar(self):
        """Windows 10 20H1+: dark caption in dark mode; Windows 11: the caption
        in the window's background colour. Works on a withdrawn window too, so
        it is set before the window is first shown."""
        if sys.platform != "win32" or self.root is None:
            return
        try:
            import ctypes
            self.root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            set_attr = ctypes.windll.dwmapi.DwmSetWindowAttribute
            for attr, v in ((_DWMWA_USE_IMMERSIVE_DARK_MODE, 1 if self.mode == DARK else 0),
                            (_DWMWA_CAPTION_COLOR, _colorref(self.palette["bg"]))):
                value = ctypes.c_int(v)
                set_attr(hwnd, attr, ctypes.byref(value), ctypes.sizeof(value))
        except (AttributeError, OSError, tk.TclError):
            pass


_PASSIVE = Theme()


def of(ctx) -> Theme:
    """The window's theme, or the passive light one (a tab built on its own)."""
    return getattr(ctx, "theme", None) or _PASSIVE


def style_text(widget: tk.Text, palette: dict, terminal: bool = False):
    """Colours of a read-only log Text, and its warn / error tags."""
    if terminal:
        widget.configure(background=TERMINAL["bg"], foreground=TERMINAL["fg"],
                         insertbackground=TERMINAL["fg"], selectbackground="#264f78",
                         highlightthickness=0, borderwidth=0)
        return
    widget.configure(background=palette["log_bg"], foreground=palette["log_fg"],
                     insertbackground=palette["log_fg"], highlightthickness=1,
                     highlightbackground=palette["border"], highlightcolor=palette["border"],
                     selectbackground=palette["sel"], selectforeground=palette["log_fg"],
                     borderwidth=0)
    widget.tag_configure("warn", foreground=palette["warn"][0])
    widget.tag_configure("error", foreground=palette["err"][0])
    widget.tag_configure("time", foreground=palette["sub"])


def style_menu(menu: tk.Menu, palette: dict):
    """Colours of a classic Menu (created before a switch: the option
    database only reaches menus made afterwards)."""
    menu.configure(background=palette["btn"], foreground=palette["fg"],
                   activebackground=palette["sel"], activeforeground=palette["fg"],
                   disabledforeground=palette["sub"], selectcolor=palette["accent"])


def style_combobox(combobox, palette: dict):
    """Colours of a combobox's drop-down list (a classic Listbox Tk makes on
    first use, which then keeps the colours it was made with)."""
    try:
        popdown = combobox.tk.eval(f"ttk::combobox::PopdownWindow {combobox}")
        combobox.tk.call(f"{popdown}.f.l", "configure", "-background", palette["log_bg"],
                         "-foreground", palette["fg"], "-selectbackground", palette["accent"],
                         "-selectforeground", palette["on_accent"])
    except tk.TclError:
        pass
