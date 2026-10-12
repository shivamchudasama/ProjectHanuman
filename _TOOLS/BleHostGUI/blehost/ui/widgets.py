"""Small display widgets shared by the panels: cards, status pills, stat tiles,
a step list, a collapsible section, a "More" menu button, tooltips and button
icons. Display only:
they hold no state the features depend on, and they follow the theme
(ui/theme.py).

They redraw only when what they show changes: a timer or a progress callback
may call set() / show() as often as it likes. Shapes are drawn smooth with
Pillow (ui/icons.py) and sized with theme.px(), so they follow the display
scale.
"""

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

from . import icons
from . import theme as th


def set_var(var, value):
    """var.set(value) only if it differs: no trace, no redraw otherwise."""
    if var.get() != value:
        var.set(value)


def card(parent, title=None, padding=(14, 10)):
    """A bordered section. Returns (frame, header); header is None without a
    title, else a frame whose column 2 is free for widgets on the right."""
    frame = ttk.Frame(parent, style="Card.TFrame", padding=padding)
    header = None
    if title:
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 6))
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text=title, style="Strong.TLabel").grid(row=0, column=0, sticky="w")
    return frame, header


def set_icon(button, theme, name: str, accent: bool = False):
    """Give a ttk button (or checkbutton) the icon glyph name to the left of
    its text, recoloured on every theme switch. Without glyphs (no Pillow or
    icon font) the button keeps its text only."""
    def apply(_palette):
        spec = icons.button_spec(button, theme, name, accent)
        button.configure(image=spec, compound="left" if spec else "none")
    theme.on_change(apply)


class Pill(tk.Canvas):
    """A rounded status label: pill.set("Connected", "ok"). Tones: theme.TONES."""

    def __init__(self, parent, theme, text="", tone="idle", dot=True):
        super().__init__(parent, height=1, width=1, highlightthickness=0, borderwidth=0)
        self._theme = theme
        self._text, self._tone, self._dot = text, tone, dot
        self._font = tkfont.Font(root=self, font=theme.fonts["caption"] + ("bold",))
        self._size = None
        self._items = None
        self.redraws = 0                             # drawn this many times (tests)
        theme.on_change(lambda _p: self._draw())

    @property
    def text(self) -> str:
        return self._text

    @property
    def tone(self) -> str:
        return self._tone

    def set(self, text: str, tone: str = None):
        tone = tone or self._tone
        if (text, tone) == (self._text, self._tone):
            return
        self._text, self._tone = text, tone
        self._draw()

    def _draw(self):
        self.redraws += 1
        t = self._theme
        fg, bg = t.tone(self._tone)
        h = self._font.metrics("linespace") + t.px(6)
        dot = h // 3 if self._dot else 0
        pad = h // 2
        gap = t.px(6) if dot else 0
        w = pad * 2 + self._font.measure(self._text) + dot + gap
        if self._size != (w, h):
            self._size = (w, h)
            self.configure(width=w, height=h)
        self.configure(background=t.palette["bg"])
        img = icons.pill(self, w, h, bg, fg if dot else None, dot, pad)
        if self._items is None:
            self._items = (self.create_image(0, 0, anchor="nw"),
                           self.create_text(0, 0, anchor="w", font=self._font))
            self._shapes = []
        back, label = self._items
        for item in self._shapes:                    # fallback shapes from a previous draw
            self.delete(item)
        self._shapes = []
        if img is not None:
            self.itemconfigure(back, image=img)
        else:                                        # no Pillow: Tk shapes
            r = h // 2
            self._shapes = [self.create_oval(0, 0, h, h, fill=bg, outline=bg),
                            self.create_oval(w - h, 0, w, h, fill=bg, outline=bg),
                            self.create_rectangle(r, 0, w - r, h, fill=bg, outline=bg)]
            if dot:
                y = (h - dot) // 2
                self._shapes.append(self.create_oval(pad, y, pad + dot, y + dot, fill=fg, outline=fg))
            self.tag_raise(label)
        self.coords(label, pad + dot + gap, h // 2)
        self.itemconfigure(label, text=self._text, fill=fg)


class StatTile(ttk.Frame):
    """A card with a caption, a large value and a note. The labels ask for a
    fixed width, so a new value never re-lays out the row of tiles."""

    def __init__(self, parent, caption: str, value: str = "–", note: str = ""):
        super().__init__(parent, style="Card.TFrame", padding=(14, 8))
        self.value_var = tk.StringVar(value=value)
        self.note_var = tk.StringVar(value=note)
        for text, var, style in ((caption.upper(), None, "Caption.TLabel"),
                                 (None, self.value_var, "Value.TLabel"),
                                 (None, self.note_var, "Caption.TLabel")):
            label = ttk.Label(self, style=style, width=1, anchor="w")
            label.configure(**({"text": text} if var is None else {"textvariable": var}))
            label.pack(anchor="w", fill="x")

    def set(self, value: str, note: str = None):
        set_var(self.value_var, value)
        if note is not None:
            set_var(self.note_var, note)


class Stepper(tk.Canvas):
    """A vertical list of steps: done ones ticked, the current one ringed, a
    failed one crossed. stepper.show(current, state) with state one of
    "idle" (nothing run), "running", "done", "failed", "aborted"."""

    ROW, MARK = 28, 18                               # pixels at 100 %

    def __init__(self, parent, theme, steps):
        self._theme = theme
        self.steps = list(steps)
        self.row, self.mark = theme.px(self.ROW), theme.px(self.MARK)
        super().__init__(parent, highlightthickness=0, borderwidth=0,
                         height=self.row * len(self.steps), width=theme.px(260))
        self.current, self.state = 0, "idle"
        self._font = tkfont.Font(root=self, font=theme.fonts["body"])
        self._bold = tkfont.Font(root=self, font=theme.fonts["strong"])
        self.redraws = 0                             # drawn this many times (tests)
        theme.on_change(lambda _p: self._draw())

    def set_steps(self, steps):
        """Replace the list of steps (nothing run yet); redraws only when it changed."""
        steps = list(steps)
        if steps == self.steps:
            return
        self.steps = steps
        self.current, self.state = 0, "idle"
        self.configure(height=self.row * len(self.steps))
        self._draw()

    def show(self, current: int, state: str):
        current = max(0, min(current, len(self.steps) - 1))
        if (current, state) == (self.current, self.state):
            return
        self.current, self.state = current, state
        self._draw()

    def _marker(self, i):
        """(kind, colour) of step i's marker, and whether the step is done / current."""
        p = self._theme.palette
        done = self.state == "done" or (self.state != "idle" and i < self.current)
        here = self.state != "idle" and i == self.current and self.state != "done"
        if done:
            return "done", p["accent"], done, here
        if here and self.state == "failed":
            return "failed", p["err"][0], done, here
        if here:
            return "current", p["warn"][0] if self.state == "aborted" else p["accent"], done, here
        return "pending", p["track"], done, here

    def _draw(self):
        self.redraws += 1
        p = self._theme.palette
        self.configure(background=p["bg"])
        self.delete("all")
        d, row, line = self.mark, self.row, self._theme.px(2)
        x0 = self._theme.px(1)
        for i, label in enumerate(self.steps):
            y = i * row + (row - d) // 2
            kind, colour, done, here = self._marker(i)
            if i < len(self.steps) - 1:                  # connector to the next step
                cx = x0 + d // 2
                self.create_line(cx, y + d, cx, y + row, fill=p["accent"] if done else p["track"],
                                 width=line)
            img = icons.step_marker(self, kind, d, colour, p["on_accent"] if kind == "done" else p["bg"])
            if img is not None:
                self.create_image(x0, y, anchor="nw", image=img)
            else:                                        # no Pillow: Tk shapes
                fill = colour if kind in ("done", "failed") else ""
                self.create_oval(x0, y, x0 + d, y + d, fill=fill, outline=colour, width=line)
            self.create_text(x0 + d + self._theme.px(12), y + d // 2, anchor="w", text=label,
                             font=self._bold if here else self._font,
                             fill=p["fg"] if done or here else p["sub"])


class Disclosure(ttk.Frame):
    """A titled section that opens and closes: put widgets in .body. With
    fill="both" the open body takes the height the section is given (pack
    the section with fill="both", expand=True)."""

    def __init__(self, parent, title: str, open_: bool = False, theme=None, fill: str = "x"):
        super().__init__(parent)
        self._title = title
        self._fill = fill
        self._theme = theme
        self._open = tk.BooleanVar(value=open_)
        self.toggle_btn = ttk.Button(self, style="Link.TLabel", command=self.toggle,
                                     takefocus=True, cursor="hand2")
        self.toggle_btn.pack(anchor="w")
        self.body = ttk.Frame(self)
        if theme is not None:
            theme.on_change(lambda _p: self._apply())
        else:
            self._apply()

    @property
    def is_open(self) -> bool:
        return self._open.get()

    @property
    def title(self) -> str:
        return self._title

    def set_title(self, title: str):
        """A new title (a count in it, say); nothing is redrawn if unchanged."""
        if title != self._title:
            self._title = title
            self._apply()

    def toggle(self):
        self._open.set(not self._open.get())
        self._apply()

    def set_open(self, open_: bool):
        self._open.set(open_)
        self._apply()

    def _apply(self):
        t = self._theme
        img = None
        if t is not None:
            img = icons.glyph(self, "chevron_down" if self.is_open else "chevron_right",
                              t.px(12), t.palette["accent"])
        if img is not None:
            self.toggle_btn.configure(image=img, compound="left", text=" " + self._title)
        else:
            self.toggle_btn.configure(image="", text=("▾  " if self.is_open else "▸  ") + self._title)
        if self.is_open:
            self.body.pack(fill=self._fill, expand=self._fill == "both", pady=(6, 0))
        else:
            self.body.pack_forget()


class MenuEntry:
    """One command of a MoreMenu, enabled and disabled like a ttk button:
    entry.state(["disabled"]) / entry.state(["!disabled"])."""

    def __init__(self, menu: tk.Menu, index: int):
        self._menu, self._index = menu, index

    @property
    def enabled(self) -> bool:
        return str(self._menu.entrycget(self._index, "state")) != "disabled"

    def state(self, spec):
        self._menu.entryconfigure(self._index, state="disabled" if "disabled" in spec else "normal")


class MoreMenu(ttk.Menubutton):
    """A "More" button that drops down a menu of less used commands:
    entry = more.add("Save…", command) returns a MenuEntry."""

    def __init__(self, parent, theme, text: str = "More"):
        super().__init__(parent, text=text, takefocus=True)
        self.menu = tk.Menu(self, tearoff=False)
        self.configure(menu=self.menu)
        theme.on_change(lambda p: th.style_menu(self.menu, p))
        set_icon(self, theme, "more")

    def add(self, label: str, command) -> MenuEntry:
        self.menu.add_command(label=label, command=command)
        return MenuEntry(self.menu, self.menu.index("end"))


class Tooltip:
    """A small label that appears after a short hover; needed for buttons that
    show only an icon. tooltip.text can be changed at any time."""

    DELAY_MS = 500

    def __init__(self, widget, text: str, theme=None):
        self.widget, self.text, self._theme = widget, text, theme
        self._tip = None
        self._after = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<ButtonPress>", self.hide, add="+")

    def _schedule(self, _e=None):
        self._cancel()
        self._after = self.widget.after(self.DELAY_MS, self.show)

    def _cancel(self):
        if self._after is not None:
            self.widget.after_cancel(self._after)
            self._after = None

    @property
    def shown(self) -> bool:
        return self._tip is not None

    def show(self):
        self._after = None
        if self._tip is not None or not self.text:
            return
        t = self._theme
        p = t.palette if t else {"fg": "#1c1c1c", "bg": "#fafafa", "border": "#e5e5e5"}
        tip = tk.Toplevel(self.widget)
        tip.overrideredirect(True)
        tk.Label(tip, text=self.text, background=p["bg"], foreground=p["fg"],
                 highlightthickness=1, highlightbackground=p["border"], borderwidth=0,
                 padx=8, pady=4, font=t.fonts["caption"] if t else None).pack()
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        tip.geometry(f"+{x}+{y}")
        self._tip = tip

    def hide(self, _e=None):
        self._cancel()
        if self._tip is not None:
            self._tip.destroy()
            self._tip = None
