"""File hashing module for LootCheck."""

import hashlib
import logging
import os

from src.utils.constants import HASH_BUFFER_SIZE

logger = logging.getLogger('LootCheck')


def calculate_sha256(file_path: str, progress_callback=None) -> str:
    """
    Calculate the SHA-256 hash of a file.

    Args:
        file_path: Absolute path to the file.
        progress_callback: Optional callable(bytes_read, total_bytes) for progress.

    Returns:
        Hex string of the SHA-256 hash.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        PermissionError: If the file can't be read.
        OSError: If a read error occurs.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")

    file_size = os.path.getsize(file_path)
    sha256_hash = hashlib.sha256()
    bytes_read = 0

    logger.info("Calculating SHA-256 for file of size %d bytes", file_size)

    with open(file_path, 'rb') as f:
        while True:
            data = f.read(HASH_BUFFER_SIZE)
            if not data:
                break
            sha256_hash.update(data)
            bytes_read += len(data)
            if progress_callback:
                progress_callback(bytes_read, file_size)

    result = sha256_hash.hexdigest()
    logger.info("SHA-256 calculated: %s...%s", result[:8], result[-8:])
    return result
