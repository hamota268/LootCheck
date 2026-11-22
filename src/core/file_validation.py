"""File validation module for LootCheck."""

import logging
import os

logger = logging.getLogger('LootCheck')

# Maximum file size for display (not a scan limit)
MAX_DISPLAY_SIZE = 1024 * 1024 * 1024 * 10  # 10 GB


def validate_file(file_path: str) -> dict:
    """
    Validate a file for scanning.

    Returns:
        dict with keys: valid (bool), error (str|None), file_info (dict|None)
    """
    result = {"valid": False, "error": None, "file_info": None}

    # Check path exists
    if not file_path:
        result["error"] = "No file path provided."
        return result

    # Clean up path (handle drag-and-drop quirks)
    file_path = file_path.strip().strip('"').strip("'")
    # Handle tkinterdnd2 curly brace wrapping for paths with spaces
    if file_path.startswith('{') and file_path.endswith('}'):
        file_path = file_path[1:-1]

    if not os.path.exists(file_path):
        result["error"] = f"File not found: {os.path.basename(file_path)}"
        return result

    if not os.path.isfile(file_path):
        result["error"] = "The dropped item is not a file (might be a folder)."
        return result

    # Check readability
    if not os.access(file_path, os.R_OK):
        result["error"] = "Permission denied: Cannot read this file."
        return result

    try:
        file_size = os.path.getsize(file_path)
    except OSError as e:
        result["error"] = f"Cannot access file: {e}"
        return result

    # Get file info
    file_name = os.path.basename(file_path)
    _, file_ext = os.path.splitext(file_name)
    file_ext = file_ext.lower() if file_ext else "(none)"

    file_info = {
        "path": file_path,
        "name": file_name,
        "size": file_size,
        "size_display": format_file_size(file_size),
        "extension": file_ext,
        "is_empty": file_size == 0,
    }

    if file_size == 0:
        # Allow scanning but warn
        logger.warning("File is empty: %s", file_name)

    result["valid"] = True
    result["file_info"] = file_info
    return result


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable form."""
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} B"
    return f"{size:.2f} {units[unit_index]}"


def is_uploadable(file_path: str) -> dict:
    """
    Check if a file can be uploaded to VirusTotal.

    Returns:
        dict: can_upload (bool), needs_large_upload (bool), error (str|None)
    """
    from src.utils.constants import VT_STANDARD_UPLOAD_LIMIT, VT_LARGE_UPLOAD_LIMIT

    try:
        file_size = os.path.getsize(file_path)
    except OSError as e:
        return {"can_upload": False, "needs_large_upload": False, "error": str(e)}

    if file_size == 0:
        return {"can_upload": True, "needs_large_upload": False, "error": None}

    if file_size > VT_LARGE_UPLOAD_LIMIT:
        return {
            "can_upload": False,
            "needs_large_upload": False,
            "error": f"File too large for VirusTotal ({format_file_size(file_size)}). "
                     f"Maximum: {format_file_size(VT_LARGE_UPLOAD_LIMIT)}."
        }

    needs_large = file_size > VT_STANDARD_UPLOAD_LIMIT
    return {"can_upload": True, "needs_large_upload": needs_large, "error": None}
