"""Settings window for LootCheck."""

import tkinter as tk
import threading
import logging

from src.ui.theme import COLORS, FONTS, SETTINGS_WIDTH, SETTINGS_HEIGHT
from src.ui.components import create_card, create_button, create_label, create_separator
from src.security.credential_storage import CredentialStorage
from src.utils.constants import APP_VERSION, APP_NAME

logger = logging.getLogger('LootCheck')


class SettingsWindow(tk.Toplevel):
    """Settings window for API key management and app configuration."""

    def __init__(self, parent, credential_storage: CredentialStorage, on_key_changed=None):
        super().__init__(parent)
        self._credential_storage = credential_storage
        self._on_key_changed = on_key_changed
        self._show_key = False

        self.title(f"{APP_NAME} — Settings")
        self.geometry(f"{SETTINGS_WIDTH}x{SETTINGS_HEIGHT}")
        self.configure(bg=COLORS["bg_primary"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        # Center on parent
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - SETTINGS_WIDTH) // 2
        y = parent.winfo_y() + (parent.winfo_height() - SETTINGS_HEIGHT) // 2
        self.geometry(f"+{x}+{y}")

        self._build_ui()

    def _build_ui(self):
        """Build the settings UI."""
        # Scrollable area
        canvas = tk.Canvas(self, bg=COLORS["bg_primary"], highlightthickness=0)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        content = tk.Frame(canvas, bg=COLORS["bg_primary"])

        content.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=content, anchor="nw", width=SETTINGS_WIDTH - 20)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # === HEADER ===
        header = tk.Frame(content, bg=COLORS["bg_primary"])
        header.pack(fill="x", padx=20, pady=(20, 10))

        tk.Label(
            header, text="⚙ Settings", font=FONTS["heading"],
            fg=COLORS["text_primary"], bg=COLORS["bg_primary"], anchor="w"
        ).pack(fill="x")

        # === API KEY SECTION ===
        api_outer, api_inner = create_card(content)
        api_outer.pack(fill="x", padx=20, pady=10)

        tk.Label(
            api_inner, text="VirusTotal API Key", font=FONTS["heading_small"],
            fg=COLORS["accent_green"], bg=COLORS["bg_card"], anchor="w"
        ).pack(fill="x", pady=(0, 5))

        tk.Label(
            api_inner, text=(
                "Get your free API key at virustotal.com.\n"
                f"Storage method: {self._credential_storage.storage_method}"
            ),
            font=FONTS["body_small"], fg=COLORS["text_muted"],
            bg=COLORS["bg_card"], anchor="w", justify="left"
        ).pack(fill="x", pady=(0, 10))

        # Status indicator
        has_key = self._credential_storage.has_api_key()
        self._status_frame = tk.Frame(api_inner, bg=COLORS["bg_card"])
        self._status_frame.pack(fill="x", pady=(0, 10))

        self._status_dot = tk.Label(
            self._status_frame,
            text="●",
            font=("Segoe UI", 12),
            fg=COLORS["status_connected"] if has_key else COLORS["status_disconnected"],
            bg=COLORS["bg_card"],
        )
        self._status_dot.pack(side="left", padx=(0, 5))

        self._status_text = tk.Label(
            self._status_frame,
            text="API key configured" if has_key else "No API key configured",
            font=FONTS["body"],
            fg=COLORS["text_primary"],
            bg=COLORS["bg_card"],
        )
        self._status_text.pack(side="left")

        # API key input
        input_frame = tk.Frame(api_inner, bg=COLORS["bg_card"])
        input_frame.pack(fill="x", pady=(0, 5))

        self._api_key_var = tk.StringVar()
        self._api_key_entry = tk.Entry(
            input_frame,
            textvariable=self._api_key_var,
            font=FONTS["mono"],
            fg=COLORS["text_primary"],
            bg=COLORS["bg_input"],
            insertbackground=COLORS["accent_green"],
            relief="flat",
            show="●",
            highlightthickness=1,
            highlightbackground=COLORS["border_default"],
            highlightcolor=COLORS["accent_green"],
        )
        self._api_key_entry.pack(side="left", fill="x", expand=True, ipady=6)

        # Load existing key
        existing_key = self._credential_storage.get_api_key()
        if existing_key:
            self._api_key_var.set(existing_key)

        # Show/hide toggle
        self._toggle_btn = tk.Button(
            input_frame, text="👁", font=("Segoe UI", 12),
            bg=COLORS["bg_input"], fg=COLORS["text_secondary"],
            relief="flat", cursor="hand2", borderwidth=0,
            command=self._toggle_key_visibility,
        )
        self._toggle_btn.pack(side="right", padx=(5, 0))

        # Action buttons
        btn_row = tk.Frame(api_inner, bg=COLORS["bg_card"])
        btn_row.pack(fill="x", pady=(10, 0))

        save_btn = create_button(btn_row, "Save API Key", self._save_key, style="primary")
        save_btn.pack(side="left", padx=(0, 10))

        validate_btn = create_button(btn_row, "Validate Key", self._validate_key, style="secondary")
        validate_btn.pack(side="left", padx=(0, 10))

        remove_btn = create_button(btn_row, "Remove Key", self._remove_key, style="danger")
        remove_btn.pack(side="left")

        # Validation result area
        self._validation_label = tk.Label(
            api_inner, text="", font=FONTS["body_small"],
            fg=COLORS["text_secondary"], bg=COLORS["bg_card"],
            anchor="w", wraplength=450,
        )
        self._validation_label.pack(fill="x", pady=(10, 0))

        # === ABOUT SECTION ===
        about_outer, about_inner = create_card(content)
        about_outer.pack(fill="x", padx=20, pady=10)

        tk.Label(
            about_inner, text="About LootCheck", font=FONTS["heading_small"],
            fg=COLORS["accent_green"], bg=COLORS["bg_card"], anchor="w"
        ).pack(fill="x", pady=(0, 10))

        about_text = (
            f"{APP_NAME} v{APP_VERSION}\n\n"
            '"Check your loot before you run it."\n\n'
            "A gamer-focused file security scanner that checks files against "
            "VirusTotal before you run them.\n\n"
            "LootCheck does NOT execute, install, modify, or extract any file you scan. "
            "It only calculates a hash and queries VirusTotal.\n\n"
            "VirusTotal is a service by Google that aggregates many antivirus engines. "
            "Detection results are informational — not a guarantee of safety.\n\n"
            "Uploading files to VirusTotal may share them with security researchers."
        )

        tk.Label(
            about_inner, text=about_text, font=FONTS["body_small"],
            fg=COLORS["text_secondary"], bg=COLORS["bg_card"],
            wraplength=450, justify="left", anchor="nw",
        ).pack(fill="x")

        # === CLOSE BUTTON ===
        close_frame = tk.Frame(content, bg=COLORS["bg_primary"])
        close_frame.pack(fill="x", padx=20, pady=20)

        close_btn = create_button(close_frame, "Close", self.destroy, style="secondary")
        close_btn.pack(side="right")

    def _toggle_key_visibility(self):
        """Toggle API key show/hide."""
        self._show_key = not self._show_key
        self._api_key_entry.config(show="" if self._show_key else "●")
        self._toggle_btn.config(text="🔒" if self._show_key else "👁")

    def _save_key(self):
        """Save the API key."""
        key = self._api_key_var.get().strip()
        if not key:
            self._show_validation("Please enter an API key.", COLORS["accent_yellow"])
            return

        if len(key) < 32:
            self._show_validation("API key seems too short. Check your key.", COLORS["accent_yellow"])
            return

        success = self._credential_storage.save_api_key(key)
        if success:
            self._show_validation("✅ API key saved successfully!", COLORS["accent_green"])
            self._update_status(True)
            if self._on_key_changed:
                self._on_key_changed()
        else:
            self._show_validation("❌ Failed to save API key.", COLORS["accent_red"])

    def _validate_key(self):
        """Validate the API key against VirusTotal."""
        key = self._api_key_var.get().strip()
        if not key:
            self._show_validation("Enter an API key first.", COLORS["accent_yellow"])
            return

        self._show_validation("Validating...", COLORS["accent_blue"])

        def do_validate():
            try:
                from src.api.virustotal import VirusTotalClient
                client = VirusTotalClient(key)
                client.validate_api_key()
                client.close()
                self.after(0, lambda: self._show_validation(
                    "✅ API key is valid!", COLORS["accent_green"]
                ))
            except Exception as e:
                self.after(0, lambda: self._show_validation(
                    f"❌ {e}", COLORS["accent_red"]
                ))

        threading.Thread(target=do_validate, daemon=True).start()

    def _remove_key(self):
        """Remove the saved API key."""
        self._credential_storage.delete_api_key()
        self._api_key_var.set("")
        self._show_validation("API key removed.", COLORS["text_secondary"])
        self._update_status(False)
        if self._on_key_changed:
            self._on_key_changed()

    def _show_validation(self, message: str, color: str):
        """Show a validation result message."""
        self._validation_label.config(text=message, fg=color)

    def _update_status(self, has_key: bool):
        """Update the API key status indicator."""
        self._status_dot.config(
            fg=COLORS["status_connected"] if has_key else COLORS["status_disconnected"]
        )
        self._status_text.config(
            text="API key configured" if has_key else "No API key configured"
        )
