"""Theme configuration for LootCheck — dark gaming UI."""

from src.api.models import RiskLevel

# Color palette
COLORS = {
    # Base
    "bg_primary": "#0D0D0D",
    "bg_secondary": "#1A1A2E",
    "bg_card": "#16213E",
    "bg_input": "#1A1A2E",
    "bg_hover": "#2A2A4A",

    # Text
    "text_primary": "#E8E8E8",
    "text_secondary": "#A0A0B0",
    "text_muted": "#6B6B80",
    "text_accent": "#00FF88",

    # Accent
    "accent_green": "#00FF88",
    "accent_green_dark": "#00CC6A",
    "accent_yellow": "#FFD700",
    "accent_yellow_dark": "#CCB000",
    "accent_orange": "#FF8C00",
    "accent_orange_dark": "#CC7000",
    "accent_red": "#FF3B3B",
    "accent_red_dark": "#CC2E2E",
    "accent_blue": "#4A9EFF",
    "accent_blue_dark": "#3A7ECC",
    "accent_gray": "#6B6B80",

    # Borders
    "border_default": "#2A2A4A",
    "border_accent": "#00FF88",
    "border_hover": "#4A4A6A",

    # Risk level colors
    "risk_safe": "#00FF88",
    "risk_safe_bg": "#0A2A1A",
    "risk_low": "#FFD700",
    "risk_low_bg": "#2A2A0A",
    "risk_suspicious": "#FF8C00",
    "risk_suspicious_bg": "#2A1A0A",
    "risk_dangerous": "#FF3B3B",
    "risk_dangerous_bg": "#2A0A0A",
    "risk_unknown": "#6B6B80",
    "risk_unknown_bg": "#1A1A1A",

    # Drop zone
    "drop_zone_bg": "#0E1A2B",
    "drop_zone_border": "#2A3A5A",
    "drop_zone_hover_border": "#00FF88",
    "drop_zone_hover_bg": "#0A2A1A",

    # Buttons
    "btn_primary_bg": "#00FF88",
    "btn_primary_fg": "#0D0D0D",
    "btn_primary_hover": "#00CC6A",
    "btn_secondary_bg": "#2A2A4A",
    "btn_secondary_fg": "#E8E8E8",
    "btn_secondary_hover": "#3A3A5A",
    "btn_danger_bg": "#FF3B3B",
    "btn_danger_fg": "#FFFFFF",
    "btn_danger_hover": "#CC2E2E",

    # Scrollbar
    "scrollbar_bg": "#1A1A2E",
    "scrollbar_fg": "#3A3A5A",

    # Status indicator
    "status_connected": "#00FF88",
    "status_disconnected": "#FF3B3B",
    "status_unknown": "#6B6B80",
}

# Font configuration
FONTS = {
    "title": ("Segoe UI", 24, "bold"),
    "subtitle": ("Segoe UI", 11),
    "heading": ("Segoe UI", 16, "bold"),
    "heading_small": ("Segoe UI", 13, "bold"),
    "body": ("Segoe UI", 10),
    "body_small": ("Segoe UI", 9),
    "mono": ("Consolas", 10),
    "mono_small": ("Consolas", 9),
    "button": ("Segoe UI", 11, "bold"),
    "button_large": ("Segoe UI", 14, "bold"),
    "verdict_large": ("Segoe UI", 20, "bold"),
    "verdict_message": ("Segoe UI", 12),
    "drop_zone_title": ("Segoe UI", 16, "bold"),
    "drop_zone_sub": ("Segoe UI", 10),
    "stat_number": ("Segoe UI", 28, "bold"),
    "stat_label": ("Segoe UI", 9),
}

# Risk level to color mapping
RISK_COLORS = {
    RiskLevel.SAFE: {
        "primary": COLORS["risk_safe"],
        "bg": COLORS["risk_safe_bg"],
        "icon": "✅",
    },
    RiskLevel.LOW_RISK: {
        "primary": COLORS["risk_low"],
        "bg": COLORS["risk_low_bg"],
        "icon": "⚠️",
    },
    RiskLevel.SUSPICIOUS: {
        "primary": COLORS["risk_suspicious"],
        "bg": COLORS["risk_suspicious_bg"],
        "icon": "🔶",
    },
    RiskLevel.DANGEROUS: {
        "primary": COLORS["risk_dangerous"],
        "bg": COLORS["risk_dangerous_bg"],
        "icon": "🛑",
    },
    RiskLevel.UNKNOWN: {
        "primary": COLORS["risk_unknown"],
        "bg": COLORS["risk_unknown_bg"],
        "icon": "❓",
    },
}

# Window dimensions
WINDOW_WIDTH = 900
WINDOW_HEIGHT = 750
SETTINGS_WIDTH = 550
SETTINGS_HEIGHT = 500
