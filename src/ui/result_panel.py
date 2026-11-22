"""Result panel for displaying scan results."""

import tkinter as tk
import webbrowser
import logging
from tkinter import filedialog

from src.ui.theme import COLORS, FONTS, RISK_COLORS
from src.ui.components import (
    create_card, create_button, create_label,
    create_separator, CollapsibleSection, ScrollableFrame,
)
from src.api.models import ScanResult, RiskLevel
from src.core.report import generate_json_report, generate_text_report, DISCLAIMER

logger = logging.getLogger('LootCheck')


class ResultPanel(tk.Frame):
    """Panel for displaying scan results with risk classification."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=COLORS["bg_primary"], **kwargs)
        self._scan_result = None

    def show_result(self, scan_result: ScanResult):
        """Display scan results."""
        self._scan_result = scan_result

        # Clear previous content
        for widget in self.winfo_children():
            widget.destroy()

        risk_colors = RISK_COLORS.get(scan_result.risk_level, RISK_COLORS[RiskLevel.UNKNOWN])

        # === VERDICT CARD ===
        verdict_outer, verdict_inner = create_card(
            self,
            bg_color=risk_colors["bg"],
            border_color=risk_colors["primary"],
        )
        verdict_outer.pack(fill="x", padx=20, pady=(10, 5))

        # Risk icon and title row
        title_frame = tk.Frame(verdict_inner, bg=risk_colors["bg"])
        title_frame.pack(fill="x")

        icon_label = tk.Label(
            title_frame,
            text=risk_colors["icon"],
            font=("Segoe UI", 28),
            bg=risk_colors["bg"],
        )
        icon_label.pack(side="left", padx=(0, 10))

        title_text_frame = tk.Frame(title_frame, bg=risk_colors["bg"])
        title_text_frame.pack(side="left", fill="x", expand=True)

        # Main verdict
        verdict_label = tk.Label(
            title_text_frame,
            text=scan_result.risk_title,
            font=FONTS["verdict_large"],
            fg=risk_colors["primary"],
            bg=risk_colors["bg"],
            anchor="w",
        )
        verdict_label.pack(fill="x")

        # Detection ratio
        if scan_result.statistics.total > 0:
            ratio_label = tk.Label(
                title_text_frame,
                text=f"Detection: {scan_result.statistics.detection_ratio} engines",
                font=FONTS["verdict_message"],
                fg=COLORS["text_primary"],
                bg=risk_colors["bg"],
                anchor="w",
            )
            ratio_label.pack(fill="x")

        # Detail message
        detail_label = tk.Label(
            verdict_inner,
            text=scan_result.risk_detail,
            font=FONTS["body"],
            fg=COLORS["text_secondary"],
            bg=risk_colors["bg"],
            wraplength=750,
            justify="left",
            anchor="w",
        )
        detail_label.pack(fill="x", pady=(10, 0))

        # Disclaimer for safe results
        if scan_result.risk_level == RiskLevel.SAFE:
            from src.core.classifier import RISK_MESSAGES
            disclaimer = RISK_MESSAGES[RiskLevel.SAFE].get("disclaimer", "")
            if disclaimer:
                disc_label = tk.Label(
                    verdict_inner,
                    text=f"⚠ {disclaimer}",
                    font=FONTS["body_small"],
                    fg=COLORS["accent_yellow"],
                    bg=risk_colors["bg"],
                    wraplength=750,
                    justify="left",
                    anchor="w",
                )
                disc_label.pack(fill="x", pady=(8, 0))

        # === STATISTICS CARD ===
        stats_outer, stats_inner = create_card(self)
        stats_outer.pack(fill="x", padx=20, pady=5)

        stats_title = tk.Label(
            stats_inner,
            text="SCAN STATISTICS",
            font=FONTS["heading_small"],
            fg=COLORS["text_primary"],
            bg=COLORS["bg_card"],
            anchor="w",
        )
        stats_title.pack(fill="x", pady=(0, 10))

        # Stats grid
        stats_grid = tk.Frame(stats_inner, bg=COLORS["bg_card"])
        stats_grid.pack(fill="x")

        stats_data = [
            ("Malicious", str(scan_result.statistics.malicious), COLORS["accent_red"]),
            ("Suspicious", str(scan_result.statistics.suspicious), COLORS["accent_orange"]),
            ("Harmless", str(scan_result.statistics.harmless), COLORS["accent_green"]),
            ("Undetected", str(scan_result.statistics.undetected), COLORS["text_secondary"]),
            ("Total", str(scan_result.statistics.total), COLORS["text_primary"]),
        ]

        for i, (label_text, value, color) in enumerate(stats_data):
            stat_frame = tk.Frame(stats_grid, bg=COLORS["bg_card"])
            stat_frame.grid(row=0, column=i, padx=10, pady=5, sticky="nsew")
            stats_grid.columnconfigure(i, weight=1)

            value_label = tk.Label(
                stat_frame,
                text=value,
                font=FONTS["stat_number"],
                fg=color,
                bg=COLORS["bg_card"],
            )
            value_label.pack()

            name_label = tk.Label(
                stat_frame,
                text=label_text,
                font=FONTS["stat_label"],
                fg=COLORS["text_muted"],
                bg=COLORS["bg_card"],
            )
            name_label.pack()

        # === FILE INFO ===
        info_outer, info_inner = create_card(self)
        info_outer.pack(fill="x", padx=20, pady=5)

        info_title = tk.Label(
            info_inner,
            text="FILE INFORMATION",
            font=FONTS["heading_small"],
            fg=COLORS["text_primary"],
            bg=COLORS["bg_card"],
            anchor="w",
        )
        info_title.pack(fill="x", pady=(0, 8))

        info_items = [
            ("Filename:", scan_result.file_name),
            ("Size:", f"{scan_result.file_size_display} ({scan_result.file_size:,} bytes)"),
            ("Type:", scan_result.file_type or "Unknown"),
            ("SHA-256:", scan_result.sha256),
            ("Scan Date:", scan_result.scan_timestamp or "N/A"),
            ("Status:", scan_result.analysis_status or "N/A"),
        ]

        for label_text, value in info_items:
            row = tk.Frame(info_inner, bg=COLORS["bg_card"])
            row.pack(fill="x", pady=1)

            lbl = tk.Label(
                row,
                text=label_text,
                font=FONTS["body"],
                fg=COLORS["text_muted"],
                bg=COLORS["bg_card"],
                width=12,
                anchor="w",
            )
            lbl.pack(side="left")

            if label_text == "SHA-256:":
                val = tk.Entry(
                    row,
                    font=FONTS["mono_small"],
                    fg=COLORS["text_primary"],
                    bg=COLORS["bg_secondary"],
                    readonlybackground=COLORS["bg_secondary"],
                    relief="flat",
                    borderwidth=0,
                    highlightthickness=0,
                )
                val.insert(0, value)
                val.config(state="readonly")
                val.pack(side="left", fill="x", expand=True)
            else:
                val = tk.Label(
                    row,
                    text=value,
                    font=FONTS["body"] if label_text != "SHA-256:" else FONTS["mono_small"],
                    fg=COLORS["text_primary"],
                    bg=COLORS["bg_card"],
                    anchor="w",
                )
                val.pack(side="left", fill="x", expand=True)

        # === DETECTION DETAILS (Collapsible) ===
        if scan_result.engine_results:
            details_section = CollapsibleSection(
                self, title="Show detection details", bg=COLORS["bg_primary"]
            )
            details_section.pack(fill="x", padx=20, pady=5)

            scroll = ScrollableFrame(
                details_section.content,
                bg=COLORS["bg_card"],
                max_height=250,
            )
            scroll.pack(fill="both", expand=True)

            # Header row
            header = tk.Frame(scroll.scrollable, bg=COLORS["bg_secondary"])
            header.pack(fill="x", pady=(0, 2))

            tk.Label(header, text="Engine", font=FONTS["body_small"], fg=COLORS["text_muted"],
                     bg=COLORS["bg_secondary"], width=25, anchor="w").pack(side="left", padx=5)
            tk.Label(header, text="Verdict", font=FONTS["body_small"], fg=COLORS["text_muted"],
                     bg=COLORS["bg_secondary"], width=15, anchor="w").pack(side="left", padx=5)
            tk.Label(header, text="Detection", font=FONTS["body_small"], fg=COLORS["text_muted"],
                     bg=COLORS["bg_secondary"], anchor="w").pack(side="left", fill="x", expand=True, padx=5)

            for engine in scan_result.engine_results:
                row_bg = COLORS["bg_card"]
                if engine.category == "malicious":
                    verdict_color = COLORS["accent_red"]
                elif engine.category == "suspicious":
                    verdict_color = COLORS["accent_orange"]
                elif engine.category == "harmless":
                    verdict_color = COLORS["accent_green"]
                else:
                    verdict_color = COLORS["text_muted"]

                row = tk.Frame(scroll.scrollable, bg=row_bg)
                row.pack(fill="x", pady=1)

                tk.Label(row, text=engine.engine_name, font=FONTS["body_small"],
                         fg=COLORS["text_primary"], bg=row_bg, width=25, anchor="w"
                         ).pack(side="left", padx=5)
                tk.Label(row, text=engine.category.upper(), font=FONTS["body_small"],
                         fg=verdict_color, bg=row_bg, width=15, anchor="w"
                         ).pack(side="left", padx=5)
                tk.Label(row, text=engine.result or "-", font=FONTS["body_small"],
                         fg=COLORS["text_secondary"], bg=row_bg, anchor="w"
                         ).pack(side="left", fill="x", expand=True, padx=5)

            # Auto-expand if there are detections
            if scan_result.statistics.malicious > 0 or scan_result.statistics.suspicious > 0:
                details_section.expand()

        # === ACTION BUTTONS ===
        btn_frame = tk.Frame(self, bg=COLORS["bg_primary"])
        btn_frame.pack(fill="x", padx=20, pady=(10, 5))

        if scan_result.vt_report_url:
            vt_btn = create_button(
                btn_frame,
                text="🔗 View full VirusTotal report",
                command=lambda: webbrowser.open(scan_result.vt_report_url),
                style="secondary",
            )
            vt_btn.pack(side="left", padx=(0, 10))

        export_btn = create_button(
            btn_frame,
            text="📄 Export Report",
            command=self._export_report,
            style="secondary",
        )
        export_btn.pack(side="left", padx=(0, 10))

        # === FOOTER DISCLAIMER ===
        footer = tk.Label(
            self,
            text=("Powered by VirusTotal • Results are for informational purposes only • "
                  "LootCheck does not execute scanned files"),
            font=FONTS["body_small"],
            fg=COLORS["text_muted"],
            bg=COLORS["bg_primary"],
            wraplength=800,
        )
        footer.pack(fill="x", padx=20, pady=(10, 5))

    def _export_report(self):
        """Export scan results to a file."""
        if not self._scan_result:
            return

        file_path = filedialog.asksaveasfilename(
            title="Export Scan Report",
            defaultextension=".json",
            filetypes=[
                ("JSON Report", "*.json"),
                ("Text Report", "*.txt"),
            ],
            initialfile=f"LootCheck_Report_{self._scan_result.file_name}",
        )

        if not file_path:
            return

        try:
            if file_path.endswith('.json'):
                content = generate_json_report(self._scan_result)
            else:
                content = generate_text_report(self._scan_result)

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            logger.info("Report exported to: %s", file_path)
        except (OSError, IOError) as e:
            logger.error("Failed to export report: %s", e)

    def clear(self):
        """Clear the result panel."""
        for widget in self.winfo_children():
            widget.destroy()
        self._scan_result = None
