"""Tests for file validation module."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.file_validation import validate_file, format_file_size, is_uploadable


class TestValidateFile:
    """Tests for file validation."""

    def test_valid_file(self, tmp_path):
        """Valid file should pass validation."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        result = validate_file(str(test_file))

        assert result["valid"] is True
        assert result["error"] is None
        assert result["file_info"]["name"] == "test.exe"
        assert result["file_info"]["extension"] == ".exe"
        assert result["file_info"]["size"] > 0

    def test_empty_path(self):
        """Empty path should fail."""
        result = validate_file("")
        assert result["valid"] is False
        assert result["error"] is not None

    def test_none_path(self):
        """None path should fail."""
        result = validate_file(None)
        assert result["valid"] is False

    def test_nonexistent_file(self):
        """Nonexistent file should fail."""
        result = validate_file("/nonexistent/path/file.exe")
        assert result["valid"] is False
        assert "not found" in result["error"].lower()

    def test_directory_path(self, tmp_path):
        """Directory should fail."""
        result = validate_file(str(tmp_path))
        assert result["valid"] is False
        assert "not a file" in result["error"].lower()

    def test_empty_file(self, tmp_path):
        """Empty file should pass validation but be flagged."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        result = validate_file(str(test_file))

        assert result["valid"] is True
        assert result["file_info"]["is_empty"] is True
        assert result["file_info"]["size"] == 0

    def test_file_with_spaces(self, tmp_path):
        """File with spaces in name should work."""
        test_file = tmp_path / "my game mod v2.1.exe"
        test_file.write_bytes(b"test data")

        result = validate_file(str(test_file))

        assert result["valid"] is True
        assert result["file_info"]["name"] == "my game mod v2.1.exe"

    def test_unicode_filename(self, tmp_path):
        """Unicode filename should work."""
        test_file = tmp_path / "мод_игры.dll"
        test_file.write_bytes(b"test")

        result = validate_file(str(test_file))

        assert result["valid"] is True

    def test_no_extension(self, tmp_path):
        """File without extension should work."""
        test_file = tmp_path / "noext"
        test_file.write_bytes(b"data")

        result = validate_file(str(test_file))

        assert result["valid"] is True
        assert result["file_info"]["extension"] == "(none)"

    def test_path_with_curly_braces(self, tmp_path):
        """Curly brace wrapped paths (from tkinterdnd2) should be handled."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"data")

        result = validate_file("{" + str(test_file) + "}")

        assert result["valid"] is True

    def test_quoted_path(self, tmp_path):
        """Quoted paths should be handled."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"data")

        result = validate_file(f'"{str(test_file)}"')

        assert result["valid"] is True


class TestFormatFileSize:
    """Tests for file size formatting."""

    def test_zero_bytes(self):
        assert format_file_size(0) == "0 B"

    def test_bytes(self):
        assert format_file_size(500) == "500 B"

    def test_kilobytes(self):
        result = format_file_size(1024)
        assert "KB" in result

    def test_megabytes(self):
        result = format_file_size(1024 * 1024)
        assert "MB" in result

    def test_gigabytes(self):
        result = format_file_size(1024 * 1024 * 1024)
        assert "GB" in result

    def test_exact_values(self):
        assert format_file_size(1024) == "1.00 KB"
        assert format_file_size(1048576) == "1.00 MB"


class TestIsUploadable:
    """Tests for upload validation."""

    def test_small_file_uploadable(self, tmp_path):
        """Small files should be directly uploadable."""
        test_file = tmp_path / "small.exe"
        test_file.write_bytes(b"x" * 1000)

        result = is_uploadable(str(test_file))

        assert result["can_upload"] is True
        assert result["needs_large_upload"] is False

    def test_empty_file_uploadable(self, tmp_path):
        """Empty files should be uploadable."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        result = is_uploadable(str(test_file))

        assert result["can_upload"] is True

    def test_nonexistent_file(self):
        """Nonexistent file should fail."""
        result = is_uploadable("/nonexistent/file.exe")
        assert result["can_upload"] is False
