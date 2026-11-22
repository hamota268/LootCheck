"""Tests for VirusTotal API client using mock responses."""

import os
import sys
import pytest
from unittest.mock import Mock, patch
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.virustotal import (
    VirusTotalClient,
    VirusTotalError,
    APIKeyError,
    RateLimitError,
    FileNotFoundOnVTError,
    UploadError,
    AnalysisError,
)
from src.api.models import RiskLevel


@pytest.fixture
def mock_client():
    return VirusTotalClient("test_api_key_12345678901234567890123456789012")


class TestVirusTotalClientInit:
    def test_empty_api_key_raises_error(self):
        with pytest.raises(APIKeyError):
            VirusTotalClient("")

        with pytest.raises(APIKeyError):
            VirusTotalClient("   ")


class TestValidateAPIKey:
    def test_validate_api_key_success(self, mock_client):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"id": "test_user"}}

        with patch.object(mock_client._session, "get", return_value=mock_resp):
            assert mock_client.validate_api_key() is True

    def test_validate_api_key_unauthorized(self, mock_client):
        mock_resp = Mock()
        mock_resp.status_code = 401

        with patch.object(mock_client._session, "get", return_value=mock_resp):
            with pytest.raises(APIKeyError):
                mock_client.validate_api_key()

    def test_validate_api_key_rate_limit(self, mock_client):
        mock_resp = Mock()
        mock_resp.status_code = 429

        with patch.object(mock_client._session, "get", return_value=mock_resp):
            with pytest.raises(RateLimitError):
                mock_client.validate_api_key()

    def test_validate_api_key_network_error(self, mock_client):
        with patch.object(mock_client._session, "get", side_effect=requests.exceptions.ConnectionError):
            with pytest.raises(VirusTotalError):
                mock_client.validate_api_key()


class TestGetFileReport:
    def test_get_file_report_success(self, mock_client):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "type_description": "Win32 EXE",
                    "last_analysis_date": 1700000000,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 70,
                        "harmless": 2,
                    },
                    "last_analysis_results": {
                        "Microsoft": {"category": "undetected", "result": None},
                        "Kaspersky": {"category": "undetected", "result": None},
                    },
                }
            }
        }

        with patch.object(mock_client._session, "get", return_value=mock_resp):
            result = mock_client.get_file_report("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            assert result.is_complete is True
            assert result.file_type == "Win32 EXE"
            assert result.statistics.malicious == 0
            assert result.statistics.total == 72
            assert len(result.engine_results) == 2

    def test_get_file_report_not_found(self, mock_client):
        mock_resp = Mock()
        mock_resp.status_code = 404

        with patch.object(mock_client._session, "get", return_value=mock_resp):
            with pytest.raises(FileNotFoundOnVTError):
                mock_client.get_file_report("0000000000000000000000000000000000000000000000000000000000000000")

    def test_get_file_report_rate_limit(self, mock_client):
        mock_resp = Mock()
        mock_resp.status_code = 429

        with patch.object(mock_client._session, "get", return_value=mock_resp):
            with pytest.raises(RateLimitError):
                mock_client.get_file_report("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


class TestUploadFile:
    def test_upload_file_success(self, mock_client, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"dummy exe data")

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"id": "analysis_id_12345"}}

        with patch.object(mock_client._session, "post", return_value=mock_resp):
            analysis_id = mock_client.upload_file(str(test_file), len(b"dummy exe data"))
            assert analysis_id == "analysis_id_12345"

    def test_upload_file_failure_status(self, mock_client, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"dummy exe data")

        mock_resp = Mock()
        mock_resp.status_code = 500

        with patch.object(mock_client._session, "post", return_value=mock_resp):
            with pytest.raises(UploadError):
                mock_client.upload_file(str(test_file), len(b"dummy exe data"))


class TestPollAnalysis:
    def test_poll_analysis_completed_with_hash(self, mock_client):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                }
            },
            "meta": {
                "file_info": {
                    "sha256": "aabbccddeeff11223344"
                }
            }
        }

        # Mock get_file_report call for the retrieved sha256
        mock_report = Mock()
        mock_report.is_complete = True

        with patch.object(mock_client._session, "get", return_value=mock_resp):
            with patch.object(mock_client, "get_file_report", return_value=mock_report):
                res = mock_client.poll_analysis("analysis_123")
                assert res.is_complete is True
