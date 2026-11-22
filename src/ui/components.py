"""Reusable UI components for LootCheck."""

import tkinter as tk


def create_card(parent, bg_color="#16213E", border_color="#2A2A4A", padx=20, pady=15, **kwargs):
    """Create a styled card frame."""
    outer = tk.Frame(parent, bg=border_color, **kwargs)
    inner = tk.Frame(outer, bg=bg_color, padx=padx, pady=pady)
    inner.pack(fill="both", expand=True, padx=1, pady=1)
    return outer, inner


def create_button(parent, text, command, style="primary", width=None, **kwargs):
    """Create a styled button."""
    from src.ui.theme import COLORS, FONTS

    styles = {
        "primary": {
            "bg": COLORS["btn_primary_bg"],
            "fg": COLORS["btn_primary_fg"],
            "hover_bg": COLORS["btn_primary_hover"],
            "active_bg": COLORS["btn_primary_hover"],
        },
        "secondary": {
            "bg": COLORS["btn_secondary_bg"],
            "fg": COLORS["btn_secondary_fg"],
            "hover_bg": COLORS["btn_secondary_hover"],
            "active_bg": COLORS["btn_secondary_hover"],
        },
        "danger": {
            "bg": COLORS["btn_danger_bg"],
            "fg": COLORS["btn_danger_fg"],
            "hover_bg": COLORS["btn_danger_hover"],
            "active_bg": COLORS["btn_danger_hover"],
        },
    }

    s = styles.get(style, styles["primary"])

    btn = tk.Button(
        parent,
        text=text,
        command=command,
        font=FONTS["button"],
        bg=s["bg"],
        fg=s["fg"],
        activebackground=s["active_bg"],
        activeforeground=s["fg"],
        relief="flat",
        cursor="hand2",
        padx=20,
        pady=8,
        borderwidth=0,
        highlightthickness=0,
        **kwargs,
    )

    if width:
        btn.config(width=width)

    def on_enter(e):
        btn.config(bg=s["hover_bg"])

    def on_leave(e):
        btn.config(bg=s["bg"])

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)

    return btn


def create_label(parent, text, font_key="body", color_key="text_primary", **kwargs):
    """Create a styled label."""
    from src.ui.theme import COLORS, FONTS
    return tk.Label(
        parent,
        text=text,
        font=FONTS.get(font_key, FONTS["body"]),
        fg=COLORS.get(color_key, COLORS["text_primary"]),
        bg=kwargs.pop("bg", parent.cget("bg")),
        **kwargs,
    )


def create_separator(parent, color="#2A2A4A", height=1):
    """Create a horizontal separator line."""
    sep = tk.Frame(parent, bg=color, height=height)
    sep.pack(fill="x", pady=5)
    return sep


class CollapsibleSection(tk.Frame):
    """A section that can be collapsed/expanded."""

    def __init__(self, parent, title="Details", bg="#16213E", **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        from src.ui.theme import COLORS, FONTS

        self._is_expanded = False

        # Header button
        self._header = tk.Button(
            self,
            text=f"▶ {title}",
            font=FONTS["heading_small"],
            fg=COLORS["text_secondary"],
            bg=bg,
            activebackground=bg,
            activeforeground=COLORS["text_primary"],
            relief="flat",
            cursor="hand2",
            anchor="w",
            borderwidth=0,
            highlightthickness=0,
            command=self.toggle,
        )
        self._header.pack(fill="x", pady=(5, 0))

        # Content frame
        self._content = tk.Frame(self, bg=bg)
        self._title = title

    @property
    def content(self):
        return self._content

    def toggle(self):
        from src.ui.theme import COLORS
        if self._is_expanded:
            self._content.pack_forget()
            self._header.config(text=f"▶ {self._title}", fg=COLORS["text_secondary"])
            self._is_expanded = False
        else:
            self._content.pack(fill="both", expand=True, pady=(5, 0))
            self._header.config(text=f"▼ {self._title}", fg=COLORS["text_primary"])
            self._is_expanded = True

    def expand(self):
        if not self._is_expanded:
            self.toggle()

    def collapse(self):
        if self._is_expanded:
            self.toggle()


class ScrollableFrame(tk.Frame):
    """A scrollable frame."""

    def __init__(self, parent, bg="#16213E", max_height=300, **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        from src.ui.theme import COLORS

        self._canvas = tk.Canvas(
            self, bg=bg, highlightthickness=0, height=max_height
        )
        self._scrollbar = tk.Scrollbar(
            self, orient="vertical", command=self._canvas.yview
        )
        self.scrollable = tk.Frame(self._canvas, bg=bg)

        self.scrollable.bind(
            "<Configure>",
            lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        )

        self._window = self._canvas.create_window((0, 0), window=self.scrollable, anchor="nw")
        self._canvas.configure(yscrollcommand=self._scrollbar.set)

        self._canvas.pack(side="left", fill="both", expand=True)
        self._scrollbar.pack(side="right", fill="y")

        # Bind mousewheel
        self._canvas.bind("<Enter>", self._bind_mousewheel)
        self._canvas.bind("<Leave>", self._unbind_mousewheel)

        # Resize inner frame width with canvas
        self._canvas.bind("<Configure>", self._on_canvas_configure)

    def _on_canvas_configure(self, event):
        self._canvas.itemconfig(self._window, width=event.width)

    def _bind_mousewheel(self, event):
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_mousewheel(self, event):
        self._canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
