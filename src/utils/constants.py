"""Application-wide constants for LootCheck."""

import os
import sys

# Application metadata
APP_NAME = "LootCheck"
APP_VERSION = "1.0.0"
APP_TAGLINE = "Check your loot before you run it."
APP_SUBTITLE = "Your last checkpoint before malware."

# VirusTotal API
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_FILE_REPORT_URL = f"{VT_API_BASE}/files"
VT_FILE_UPLOAD_URL = f"{VT_API_BASE}/files"
VT_ANALYSIS_URL = f"{VT_API_BASE}/analyses"
VT_LARGE_FILE_URL = f"{VT_API_BASE}/files/upload_url"
VT_WEB_REPORT_URL = "https://www.virustotal.com/gui/file"

# API limits
VT_STANDARD_UPLOAD_LIMIT = 32 * 1024 * 1024  # 32 MB
VT_LARGE_UPLOAD_LIMIT = 650 * 1024 * 1024    # 650 MB
VT_REQUEST_TIMEOUT = 60  # seconds
VT_UPLOAD_TIMEOUT = 300  # seconds for uploads
VT_POLL_INTERVAL = 15    # seconds between analysis polls
VT_MAX_POLL_ATTEMPTS = 40  # ~10 minutes max polling

# Credential storage
CREDENTIAL_SERVICE_NAME = "LootCheck"
CREDENTIAL_USERNAME = "virustotal_api_key"

# File hashing
HASH_BUFFER_SIZE = 65536  # 64 KB chunks for hashing

# Risk classification thresholds
RISK_LOW_MAX_DETECTIONS = 2       # 1-2 detections = low risk
RISK_SUSPICIOUS_MIN_DETECTIONS = 3  # 3-4 detections = suspicious
RISK_DANGEROUS_MIN_DETECTIONS = 5   # 5+ = dangerous
RISK_DANGEROUS_MIN_RATIO = 0.08     # 8% of engines = dangerous


def get_resource_path(relative_path: str) -> str:
    """Get path to a resource, works for dev and PyInstaller."""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base_path, relative_path)


def get_config_dir() -> str:
    """Get the user configuration directory with graceful permission fallbacks."""
    candidates = [
        os.path.join(os.environ.get('APPDATA', ''), 'LootCheck'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'LootCheck'),
        os.path.join(os.path.expanduser('~'), '.lootcheck'),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config'),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            os.makedirs(candidate, exist_ok=True)
            # Test writability
            test_file = os.path.join(candidate, '.write_test')
            with open(test_file, 'w') as f:
                f.write('ok')
            os.remove(test_file)
            return candidate
        except (PermissionError, OSError):
            continue

    # Absolute fallback: current working directory / config
    fallback = os.path.abspath("config")
    try:
        os.makedirs(fallback, exist_ok=True)
        return fallback
    except Exception:
        import tempfile
        return tempfile.gettempdir()
