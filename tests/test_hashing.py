"""Tests for file hashing module."""

import hashlib
import os
import tempfile
import pytest

# Add project root to path
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.hashing import calculate_sha256


class TestCalculateSHA256:
    """Tests for SHA-256 hash calculation."""

    def test_known_content(self, tmp_path):
        """Test SHA-256 of known content matches expected hash."""
        test_file = tmp_path / "test.txt"
        content = b"Hello, LootCheck!"
        test_file.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        result = calculate_sha256(str(test_file))

        assert result == expected

    def test_empty_file(self, tmp_path):
        """Test SHA-256 of an empty file."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        expected = hashlib.sha256(b"").hexdigest()
        result = calculate_sha256(str(test_file))

        assert result == expected

    def test_binary_content(self, tmp_path):
        """Test SHA-256 of binary data."""
        test_file = tmp_path / "binary.bin"
        content = bytes(range(256))
        test_file.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        result = calculate_sha256(str(test_file))

        assert result == expected

    def test_large_file(self, tmp_path):
        """Test SHA-256 of a file larger than the buffer size."""
        test_file = tmp_path / "large.bin"
        # Create a 1 MB file
        content = os.urandom(1024 * 1024)
        test_file.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        result = calculate_sha256(str(test_file))

        assert result == expected

    def test_hash_is_hex_string(self, tmp_path):
        """Test that the result is a valid hex string of correct length."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test")

        result = calculate_sha256(str(test_file))

        assert len(result) == 64
        assert all(c in '0123456789abcdef' for c in result)

    def test_file_not_found(self):
        """Test that FileNotFoundError is raised for missing files."""
        with pytest.raises(FileNotFoundError):
            calculate_sha256("/nonexistent/file/path.exe")

    def test_directory_raises_error(self, tmp_path):
        """Test that ValueError is raised for directories."""
        with pytest.raises(ValueError):
            calculate_sha256(str(tmp_path))

    def test_progress_callback(self, tmp_path):
        """Test that the progress callback is called."""
        test_file = tmp_path / "test.bin"
        content = os.urandom(200000)  # ~200 KB
        test_file.write_bytes(content)

        progress_calls = []

        def callback(bytes_read, total):
            progress_calls.append((bytes_read, total))

        calculate_sha256(str(test_file), progress_callback=callback)

        assert len(progress_calls) > 0
        # Last call should have bytes_read == total
        assert progress_calls[-1][0] == progress_calls[-1][1]

    def test_consistent_results(self, tmp_path):
        """Test that hashing the same file twice gives the same result."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"consistent data")

        result1 = calculate_sha256(str(test_file))
        result2 = calculate_sha256(str(test_file))

        assert result1 == result2

    def test_unicode_filename(self, tmp_path):
        """Test hashing a file with Unicode characters in the name."""
        test_file = tmp_path / "тест_файл_🎮.txt"
        test_file.write_bytes(b"unicode test")

        expected = hashlib.sha256(b"unicode test").hexdigest()
        result = calculate_sha256(str(test_file))

        assert result == expected
