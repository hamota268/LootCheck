"""Main application window for LootCheck."""

import tkinter as tk
import threading
import logging

from src.ui.theme import COLORS, FONTS, WINDOW_WIDTH, WINDOW_HEIGHT
from src.ui.components import create_button, create_card, create_separator
from src.ui.drop_zone import DropZone
from src.ui.result_panel import ResultPanel
from src.ui.settings_window import SettingsWindow
from src.security.credential_storage import CredentialStorage
from src.core.scanner import ScanOrchestrator
from src.core.file_validation import validate_file, is_uploadable
from src.api.models import RiskLevel
from src.utils.constants import APP_NAME, APP_VERSION, APP_TAGLINE

logger = logging.getLogger('LootCheck')


class MainWindow:
    """Main application window."""

    def __init__(self, root):
        self._root = root
        self._credential_storage = CredentialStorage()
        self._current_file = None
        self._current_file_info = None
        self._scan_result = None
        self._scanning = False

        self._setup_window()
        self._build_ui()
        self._update_api_status()

    def _setup_window(self):
        """Configure the main window."""
        self._root.title(f"{APP_NAME} — {APP_TAGLINE}")
        self._root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self._root.configure(bg=COLORS["bg_primary"])
        self._root.minsize(800, 600)

        # Try to set icon
        try:
            from src.utils.constants import get_resource_path
            import os
            icon_path = get_resource_path(os.path.join("assets", "icon.ico"))
            if os.path.exists(icon_path):
                self._root.iconbitmap(icon_path)
        except Exception:
            pass

    def _build_ui(self):
        """Build the main UI layout."""
        # === HEADER ===
        header = tk.Frame(self._root, bg=COLORS["bg_secondary"], height=70)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Left side: logo and tagline
        logo_frame = tk.Frame(header, bg=COLORS["bg_secondary"])
        logo_frame.pack(side="left", padx=20, pady=10)

        tk.Label(
            logo_frame,
            text=f"🛡 {APP_NAME}",
            font=FONTS["title"],
            fg=COLORS["accent_green"],
            bg=COLORS["bg_secondary"],
        ).pack(side="left")

        tk.Label(
            logo_frame,
            text=f"  {APP_TAGLINE}",
            font=FONTS["subtitle"],
            fg=COLORS["text_secondary"],
            bg=COLORS["bg_secondary"],
        ).pack(side="left", padx=(10, 0), pady=(8, 0))

        # Right side: status and settings
        controls_frame = tk.Frame(header, bg=COLORS["bg_secondary"])
        controls_frame.pack(side="right", padx=20, pady=10)

        # API status
        self._api_status_frame = tk.Frame(controls_frame, bg=COLORS["bg_secondary"])
        self._api_status_frame.pack(side="left", padx=(0, 15))

        self._api_status_dot = tk.Label(
            self._api_status_frame,
            text="●",
            font=("Segoe UI", 10),
            fg=COLORS["status_unknown"],
            bg=COLORS["bg_secondary"],
        )
        self._api_status_dot.pack(side="left")

        self._api_status_text = tk.Label(
            self._api_status_frame,
            text="Checking...",
            font=FONTS["body_small"],
            fg=COLORS["text_muted"],
            bg=COLORS["bg_secondary"],
        )
        self._api_status_text.pack(side="left", padx=(3, 0))

        # Settings button
        settings_btn = tk.Button(
            controls_frame,
            text="⚙ Settings",
            font=FONTS["body"],
            fg=COLORS["text_secondary"],
            bg=COLORS["bg_secondary"],
            activebackground=COLORS["bg_hover"],
            activeforeground=COLORS["text_primary"],
            relief="flat",
            cursor="hand2",
            borderwidth=0,
            command=self._open_settings,
        )
        settings_btn.pack(side="left")

        # === MAIN CONTENT (Scrollable) ===
        self._main_canvas = tk.Canvas(
            self._root, bg=COLORS["bg_primary"], highlightthickness=0
        )
        self._main_scrollbar = tk.Scrollbar(
            self._root, orient="vertical", command=self._main_canvas.yview
        )
        self._main_content = tk.Frame(self._main_canvas, bg=COLORS["bg_primary"])

        self._main_content.bind(
            "<Configure>",
            lambda e: self._main_canvas.configure(scrollregion=self._main_canvas.bbox("all"))
        )

        self._content_window = self._main_canvas.create_window(
            (0, 0), window=self._main_content, anchor="nw"
        )
        self._main_canvas.configure(yscrollcommand=self._main_scrollbar.set)

        self._main_canvas.pack(side="left", fill="both", expand=True)
        self._main_scrollbar.pack(side="right", fill="y")

        # Resize content width with canvas
        self._main_canvas.bind("<Configure>", self._on_canvas_configure)

        # Mousewheel scrolling
        self._main_canvas.bind("<Enter>", lambda e: self._main_canvas.bind_all("<MouseWheel>", self._on_mousewheel))
        self._main_canvas.bind("<Leave>", lambda e: self._main_canvas.unbind_all("<MouseWheel>"))

        # === DROP ZONE ===
        self._drop_zone = DropZone(self._main_content, on_file_selected=self._on_file_selected)
        self._drop_zone.pack(fill="x", pady=(10, 0))

        # === FILE INFO CARD (hidden initially) ===
        self._file_info_frame = tk.Frame(self._main_content, bg=COLORS["bg_primary"])

        # === SCAN BUTTON (hidden initially) ===
        self._scan_btn_frame = tk.Frame(self._main_content, bg=COLORS["bg_primary"])

        # === STATUS / PROGRESS ===
        self._status_frame = tk.Frame(self._main_content, bg=COLORS["bg_primary"])

        # === RESULT PANEL ===
        self._result_panel = ResultPanel(self._main_content)

        # === UPLOAD PROMPT (hidden) ===
        self._upload_frame = tk.Frame(self._main_content, bg=COLORS["bg_primary"])

        # === FOOTER ===
        footer = tk.Frame(self._root, bg=COLORS["bg_secondary"], height=35)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        tk.Label(
            footer,
            text=(f"LootCheck v{APP_VERSION} • Powered by VirusTotal • "
                  "Results are informational only — not a safety guarantee"),
            font=FONTS["body_small"],
            fg=COLORS["text_muted"],
            bg=COLORS["bg_secondary"],
        ).pack(expand=True)

    def _on_canvas_configure(self, event):
        self._main_canvas.itemconfig(self._content_window, width=event.width)

    def _on_mousewheel(self, event):
        self._main_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_file_selected(self, file_path: str):
        """Handle file selection from drop zone or browser."""
        if self._scanning:
            return

        # Clear previous results
        self._clear_results()

        # Validate file
        validation = validate_file(file_path)
        if not validation["valid"]:
            self._show_error(validation["error"])
            return

        self._current_file = file_path
        self._current_file_info = validation["file_info"]

        # Show file info
        self._show_file_info(validation["file_info"])

        # Show scan button
        self._show_scan_button()

    def _show_file_info(self, file_info: dict):
        """Display selected file information."""
        # Clear and rebuild
        for widget in self._file_info_frame.winfo_children():
            widget.destroy()

        from src.ui.components import create_card
        outer, inner = create_card(self._file_info_frame)
        outer.pack(fill="x", padx=20, pady=5)

        tk.Label(
            inner, text="SELECTED FILE", font=FONTS["heading_small"],
            fg=COLORS["accent_green"], bg=COLORS["bg_card"], anchor="w"
        ).pack(fill="x", pady=(0, 8))

        info_items = [
            ("📄 Filename:", file_info["name"]),
            ("📏 Size:", file_info["size_display"]),
            ("📋 Extension:", file_info["extension"]),
        ]

        if file_info.get("is_empty"):
            info_items.append(("⚠ Warning:", "This file is empty (0 bytes)"))

        for icon_label, value in info_items:
            row = tk.Frame(inner, bg=COLORS["bg_card"])
            row.pack(fill="x", pady=2)

            tk.Label(
                row, text=icon_label, font=FONTS["body"],
                fg=COLORS["text_muted"], bg=COLORS["bg_card"],
                width=14, anchor="w"
            ).pack(side="left")

            tk.Label(
                row, text=value, font=FONTS["body"],
                fg=COLORS["text_primary"], bg=COLORS["bg_card"],
                anchor="w"
            ).pack(side="left", fill="x")

        # New file / clear button
        clear_btn = create_button(
            inner, "✕ Clear", self._clear_all, style="secondary"
        )
        clear_btn.pack(anchor="e", pady=(10, 0))

        self._file_info_frame.pack(fill="x", after=self._drop_zone)

    def _show_scan_button(self):
        """Show the scan button."""
        for widget in self._scan_btn_frame.winfo_children():
            widget.destroy()

        # Check for API key
        if not self._credential_storage.has_api_key():
            tk.Label(
                self._scan_btn_frame,
                text="⚠ No API key configured. Go to Settings to add your VirusTotal API key.",
                font=FONTS["body"],
                fg=COLORS["accent_yellow"],
                bg=COLORS["bg_primary"],
                wraplength=700,
            ).pack(pady=10)

            settings_btn = create_button(
                self._scan_btn_frame,
                "Open Settings",
                self._open_settings,
                style="secondary",
            )
            settings_btn.pack(pady=5)
        else:
            self._scan_button = create_button(
                self._scan_btn_frame,
                "🔍  SCAN MY FILE",
                self._start_scan,
                style="primary",
            )
            self._scan_button.config(font=FONTS["button_large"], padx=40, pady=12)
            self._scan_button.pack(pady=15)

        self._scan_btn_frame.pack(fill="x", after=self._file_info_frame)

    def _start_scan(self):
        """Start the scanning process in a background thread."""
        if self._scanning or not self._current_file:
            return

        self._scanning = True

        # Hide scan button, show progress
        self._scan_btn_frame.pack_forget()
        self._result_panel.clear()
        self._result_panel.pack_forget()
        self._upload_frame.pack_forget()

        self._show_status("🔍 Starting scan...")

        api_key = self._credential_storage.get_api_key()
        if not api_key:
            self._show_error("No API key configured. Go to Settings to add your VirusTotal API key.")
            self._scanning = False
            self._show_scan_button()
            return

        def do_scan():
            try:
                orchestrator = ScanOrchestrator(api_key)
                result = orchestrator.scan_file(
                    self._current_file,
                    status_callback=lambda msg: self._root.after(0, self._show_status, msg),
                )

                self._scan_result = result
                self._root.after(0, self._on_scan_complete, result)

            except Exception as e:
                logger.exception("Scan error")
                self._root.after(0, self._show_error, f"Scan failed: {e}")
                self._root.after(0, self._on_scan_finished)

        threading.Thread(target=do_scan, daemon=True).start()

    def _on_scan_complete(self, result):
        """Handle scan completion on the main thread."""
        self._scanning = False
        self._hide_status()

        # Check if file was not found on VT — offer upload
        if result.error == "not_found":
            self._show_upload_prompt(result)
        else:
            self._show_results(result)

    def _show_upload_prompt(self, result):
        """Show upload consent prompt when file not found on VT."""
        for widget in self._upload_frame.winfo_children():
            widget.destroy()

        from src.ui.components import create_card
        outer, inner = create_card(
            self._upload_frame,
            bg_color=COLORS["bg_card"],
            border_color=COLORS["accent_blue"],
        )
        outer.pack(fill="x", padx=20, pady=10)

        tk.Label(
            inner, text="❓ FILE NOT FOUND IN DATABASE",
            font=FONTS["heading_small"],
            fg=COLORS["accent_blue"], bg=COLORS["bg_card"], anchor="w"
        ).pack(fill="x", pady=(0, 10))

        tk.Label(
            inner, text=(
                "This file has never been scanned by VirusTotal. "
                "Would you like to upload it for analysis?"
            ),
            font=FONTS["body"],
            fg=COLORS["text_primary"], bg=COLORS["bg_card"],
            wraplength=700, justify="left", anchor="w"
        ).pack(fill="x", pady=(0, 10))

        # Privacy warning
        warning_frame = tk.Frame(inner, bg="#2A1A0A")
        warning_frame.pack(fill="x", pady=(0, 10), ipady=8, ipadx=10)

        tk.Label(
            warning_frame, text="⚠ PRIVACY WARNING",
            font=FONTS["heading_small"],
            fg=COLORS["accent_orange"], bg="#2A1A0A", anchor="w"
        ).pack(fill="x", padx=10, pady=(5, 3))

        tk.Label(
            warning_frame, text=(
                "Uploading this file submits it to VirusTotal for analysis. "
                "Uploaded samples may be shared with security partners and researchers. "
                "Do not upload private, confidential, personal, or proprietary files."
            ),
            font=FONTS["body_small"],
            fg=COLORS["accent_yellow"], bg="#2A1A0A",
            wraplength=680, justify="left", anchor="w"
        ).pack(fill="x", padx=10)

        # Check if uploadable
        upload_check = is_uploadable(self._current_file)

        btn_row = tk.Frame(inner, bg=COLORS["bg_card"])
        btn_row.pack(fill="x", pady=(5, 0))

        if upload_check["can_upload"]:
            upload_btn = create_button(
                btn_row, "📤 Upload and Scan", self._start_upload, style="primary"
            )
            upload_btn.pack(side="left", padx=(0, 10))
        else:
            tk.Label(
                btn_row, text=f"❌ {upload_check['error']}",
                font=FONTS["body"], fg=COLORS["accent_red"],
                bg=COLORS["bg_card"], anchor="w"
            ).pack(side="left")

        cancel_btn = create_button(
            btn_row, "Cancel", lambda: self._show_results(result), style="secondary"
        )
        cancel_btn.pack(side="left")

        self._upload_frame.pack(fill="x")

        # Also show the unknown result below
        self._show_results(result)

    def _start_upload(self):
        """Upload file to VirusTotal after consent."""
        if self._scanning or not self._current_file:
            return

        self._scanning = True
        self._upload_frame.pack_forget()
        self._result_panel.clear()
        self._result_panel.pack_forget()

        self._show_status("📤 Uploading file to VirusTotal...")

        api_key = self._credential_storage.get_api_key()

        def do_upload():
            try:
                orchestrator = ScanOrchestrator(api_key)
                result = orchestrator.upload_and_scan(
                    self._current_file,
                    status_callback=lambda msg: self._root.after(0, self._show_status, msg),
                )
                self._scan_result = result
                self._root.after(0, self._on_scan_complete_upload, result)
            except Exception as e:
                logger.exception("Upload error")
                self._root.after(0, self._show_error, f"Upload failed: {e}")
                self._root.after(0, self._on_scan_finished)

        threading.Thread(target=do_upload, daemon=True).start()

    def _on_scan_complete_upload(self, result):
        """Handle upload+scan completion."""
        self._scanning = False
        self._hide_status()
        self._show_results(result)

    def _show_results(self, result):
        """Display scan results."""
        self._result_panel.show_result(result)
        self._result_panel.pack(fill="x", pady=(5, 20))

        # Show "Scan Again" button
        self._show_scan_again_button()

    def _show_scan_again_button(self):
        """Show button to scan again or select a new file."""
        for widget in self._scan_btn_frame.winfo_children():
            widget.destroy()

        btn_row = tk.Frame(self._scan_btn_frame, bg=COLORS["bg_primary"])
        btn_row.pack(pady=10)

        new_file_btn = create_button(
            btn_row, "📁 Scan New File", self._clear_all, style="secondary"
        )
        new_file_btn.pack(side="left", padx=5)

        if self._current_file and self._credential_storage.has_api_key():
            rescan_btn = create_button(
                btn_row, "🔄 Rescan", self._start_scan, style="primary"
            )
            rescan_btn.pack(side="left", padx=5)

        self._scan_btn_frame.pack(fill="x")

    def _show_status(self, message: str):
        """Show a status/progress message."""
        for widget in self._status_frame.winfo_children():
            widget.destroy()

        status_inner = tk.Frame(self._status_frame, bg=COLORS["bg_primary"])
        status_inner.pack(pady=15)

        # Animated dots via label
        self._status_label = tk.Label(
            status_inner,
            text=message,
            font=FONTS["body"],
            fg=COLORS["accent_green"],
            bg=COLORS["bg_primary"],
        )
        self._status_label.pack()

        # Simple progress bar
        progress_bg = tk.Frame(status_inner, bg=COLORS["border_default"], height=4)
        progress_bg.pack(fill="x", padx=100, pady=(10, 0))

        self._progress_bar = tk.Frame(progress_bg, bg=COLORS["accent_green"], height=4, width=50)
        self._progress_bar.pack(side="left")

        self._status_frame.pack(fill="x")
        self._animate_progress()

    def _animate_progress(self):
        """Simple progress bar animation."""
        if not self._scanning:
            return
        try:
            if self._progress_bar.winfo_exists():
                current = self._progress_bar.winfo_width()
                parent_width = self._progress_bar.master.winfo_width()
                if parent_width > 0:
                    new_width = (current + 5) % max(parent_width, 1)
                    self._progress_bar.config(width=max(new_width, 10))
                self._root.after(50, self._animate_progress)
        except tk.TclError:
            pass

    def _hide_status(self):
        """Hide the status message."""
        self._status_frame.pack_forget()
        for widget in self._status_frame.winfo_children():
            widget.destroy()

    def _show_error(self, message: str):
        """Show an error message."""
        self._hide_status()

        for widget in self._status_frame.winfo_children():
            widget.destroy()

        tk.Label(
            self._status_frame,
            text=f"❌ {message}",
            font=FONTS["body"],
            fg=COLORS["accent_red"],
            bg=COLORS["bg_primary"],
            wraplength=700,
        ).pack(pady=10)

        self._status_frame.pack(fill="x")

    def _clear_results(self):
        """Clear scan results."""
        self._result_panel.clear()
        self._result_panel.pack_forget()
        self._upload_frame.pack_forget()
        for widget in self._upload_frame.winfo_children():
            widget.destroy()
        self._hide_status()
        self._scan_btn_frame.pack_forget()

    def _clear_all(self):
        """Reset everything to initial state."""
        self._current_file = None
        self._current_file_info = None
        self._scan_result = None
        self._scanning = False
        self._clear_results()
        self._file_info_frame.pack_forget()
        for widget in self._file_info_frame.winfo_children():
            widget.destroy()
        self._scan_btn_frame.pack_forget()
        for widget in self._scan_btn_frame.winfo_children():
            widget.destroy()

    def _on_scan_finished(self):
        """Clean up after scan regardless of outcome."""
        self._scanning = False
        self._show_scan_button()

    def _open_settings(self):
        """Open the settings window."""
        SettingsWindow(
            self._root,
            self._credential_storage,
            on_key_changed=self._update_api_status,
        )

    def _update_api_status(self):
        """Update the API key status indicator in the header."""
        has_key = self._credential_storage.has_api_key()
        if has_key:
            self._api_status_dot.config(fg=COLORS["status_connected"])
            self._api_status_text.config(text="API key ready")
        else:
            self._api_status_dot.config(fg=COLORS["status_disconnected"])
            self._api_status_text.config(text="No API key")

        # Refresh scan button if visible
        if self._current_file and not self._scanning:
            self._show_scan_button()
