"""Drop zone widget for file drag-and-drop."""

import tkinter as tk
from tkinter import filedialog
import logging

from src.ui.theme import COLORS, FONTS

logger = logging.getLogger('LootCheck')


class DropZone(tk.Frame):
    """Large drag-and-drop area for file selection."""

    def __init__(self, parent, on_file_selected, **kwargs):
        super().__init__(parent, bg=COLORS["bg_primary"], **kwargs)
        self._on_file_selected = on_file_selected
        self._dnd_available = False

        self._setup_ui()
        self._setup_dnd()

    def _setup_ui(self):
        """Build the drop zone UI."""
        # Outer border frame with generous height for a large drop surface
        self._border_frame = tk.Frame(
            self,
            bg=COLORS["drop_zone_border"],
            height=310,
        )
        self._border_frame.pack(fill="x", padx=20, pady=(15, 15))
        self._border_frame.pack_propagate(False)

        # Inner frame spanning the entire border area
        self._inner = tk.Frame(
            self._border_frame,
            bg=COLORS["drop_zone_bg"],
            cursor="hand2",
        )
        self._inner.pack(fill="both", expand=True, padx=2, pady=2)

        # Centered content container
        content_frame = tk.Frame(self._inner, bg=COLORS["drop_zone_bg"])
        content_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Large icon
        self._icon_label = tk.Label(
            content_frame,
            text="📁",
            font=("Segoe UI", 48),
            bg=COLORS["drop_zone_bg"],
            fg=COLORS["text_primary"],
        )
        self._icon_label.pack(pady=(0, 12))

        # Title
        self._title_label = tk.Label(
            content_frame,
            text="DROP YOUR FILE HERE",
            font=("Segoe UI", 18, "bold"),
            fg=COLORS["accent_green"],
            bg=COLORS["drop_zone_bg"],
        )
        self._title_label.pack(pady=(0, 4))

        # Subtitle
        self._subtitle_label = tk.Label(
            content_frame,
            text="or click anywhere in this box to browse your PC",
            font=("Segoe UI", 11),
            fg=COLORS["text_secondary"],
            bg=COLORS["drop_zone_bg"],
        )
        self._subtitle_label.pack(pady=(0, 14))

        # File types badge
        types_badge = tk.Frame(
            content_frame,
            bg=COLORS["bg_card"],
            padx=14,
            pady=6,
        )
        types_badge.pack()

        self._types_label = tk.Label(
            types_badge,
            text="Supported: .exe  .dll  .zip  .bat  .msi  .apk  .7z  .rar  .ps1  and all other file types",
            font=FONTS["body_small"],
            fg=COLORS["text_muted"],
            bg=COLORS["bg_card"],
        )
        self._types_label.pack()

        # Click binding for file browser on all elements
        for widget in [self._inner, self._icon_label, self._title_label,
                       self._subtitle_label, self._types_label, types_badge, content_frame]:
            widget.bind("<Button-1>", self._browse_file)

        # Hover effects
        self._inner.bind("<Enter>", self._on_hover_enter)
        self._inner.bind("<Leave>", self._on_hover_leave)

    def _setup_dnd(self):
        """Set up drag-and-drop if tkinterdnd2 is available."""
        try:
            # The root window must be TkinterDnD.Tk for DnD to work
            root = self.winfo_toplevel()
            if hasattr(root, 'drop_target_register'):
                self._inner.drop_target_register('DND_Files')
                self._inner.dnd_bind('<<Drop>>', self._on_drop)
                self._inner.dnd_bind('<<DragEnter>>', self._on_drag_enter)
                self._inner.dnd_bind('<<DragLeave>>', self._on_drag_leave)
                self._dnd_available = True
                logger.info("Drag-and-drop enabled via tkinterdnd2")
            else:
                # Try to register on the frame itself
                self.drop_target_register('DND_Files')
                self.dnd_bind('<<Drop>>', self._on_drop)
                self.dnd_bind('<<DragEnter>>', self._on_drag_enter)
                self.dnd_bind('<<DragLeave>>', self._on_drag_leave)
                self._dnd_available = True
                logger.info("Drag-and-drop enabled on frame")
        except Exception as e:
            logger.warning("Drag-and-drop not available: %s. Using file browser fallback.", e)
            self._dnd_available = False
            self._title_label.config(text="CLICK TO SELECT YOUR FILE")
            self._subtitle_label.config(text="Drag-and-drop unavailable — use the file browser")

    def _on_drop(self, event):
        """Handle file drop event."""
        file_path = event.data
        if file_path:
            # Clean up path
            file_path = file_path.strip()
            # Handle tkinterdnd2 path formats
            if file_path.startswith('{') and file_path.endswith('}'):
                file_path = file_path[1:-1]
            # Handle multiple files (take only the first)
            if '\n' in file_path:
                file_path = file_path.split('\n')[0].strip()
            # Remove surrounding quotes
            file_path = file_path.strip('"').strip("'")

            logger.info("File dropped: %s", file_path[:50])
            self._reset_visual()
            self._on_file_selected(file_path)

    def _on_drag_enter(self, event):
        """Visual feedback when dragging over."""
        self._border_frame.config(bg=COLORS["drop_zone_hover_border"])
        self._inner.config(bg=COLORS["drop_zone_hover_bg"])
        for widget in [self._icon_label, self._title_label,
                       self._subtitle_label, self._types_label]:
            widget.config(bg=COLORS["drop_zone_hover_bg"])
        # Update children in content_frame
        for child in self._inner.winfo_children():
            try:
                child.config(bg=COLORS["drop_zone_hover_bg"])
                for grandchild in child.winfo_children():
                    try:
                        grandchild.config(bg=COLORS["drop_zone_hover_bg"])
                    except tk.TclError:
                        pass
            except tk.TclError:
                pass

    def _on_drag_leave(self, event):
        """Reset visual when drag leaves."""
        self._reset_visual()

    def _reset_visual(self):
        """Reset to default visual state."""
        self._border_frame.config(bg=COLORS["drop_zone_border"])
        self._inner.config(bg=COLORS["drop_zone_bg"])
        for widget in [self._icon_label, self._title_label,
                       self._subtitle_label, self._types_label]:
            widget.config(bg=COLORS["drop_zone_bg"])
        for child in self._inner.winfo_children():
            try:
                child.config(bg=COLORS["drop_zone_bg"])
                for grandchild in child.winfo_children():
                    try:
                        grandchild.config(bg=COLORS["drop_zone_bg"])
                    except tk.TclError:
                        pass
            except tk.TclError:
                pass

    def _on_hover_enter(self, event):
        """Subtle hover effect."""
        self._border_frame.config(bg=COLORS["border_hover"])

    def _on_hover_leave(self, event):
        """Reset hover effect."""
        self._border_frame.config(bg=COLORS["drop_zone_border"])

    def _browse_file(self, event=None):
        """Open file browser dialog."""
        file_path = filedialog.askopenfilename(
            title="Select a file to scan",
            filetypes=[
                ("All files", "*.*"),
                ("Executables", "*.exe *.msi *.bat *.cmd *.com *.scr *.pif"),
                ("Libraries", "*.dll *.sys *.ocx"),
                ("Archives", "*.zip *.rar *.7z *.tar *.gz"),
                ("Scripts", "*.ps1 *.vbs *.js *.py *.bat"),
                ("Documents", "*.doc *.docx *.pdf *.xls *.xlsx"),
            ]
        )
        if file_path:
            logger.info("File selected via browser: %s", file_path[:50])
            self._on_file_selected(file_path)

    @property
    def dnd_available(self) -> bool:
        return self._dnd_available
