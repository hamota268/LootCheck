"""Scanner orchestrator — coordinates hashing, VT API, and classification."""

import logging
import os
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from src.core.hashing import calculate_sha256
from src.core.file_validation import validate_file, is_uploadable
from src.core.classifier import classify_risk, get_risk_messages, build_scan_result_classification
from src.api.virustotal import (
    VirusTotalClient,
    VirusTotalError,
    APIKeyError,
    RateLimitError,
    FileNotFoundOnVTError,
    UploadError,
    AnalysisError,
)
from src.api.models import ScanResult, ScanStatistics, RiskLevel

logger = logging.getLogger('LootCheck')


class ScanOrchestrator:
    """Orchestrates the full scan workflow."""

    def __init__(self, api_key: str):
        self._api_key = api_key
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._cancel_flag = False

    def scan_file(
        self,
        file_path: str,
        status_callback: Callable[[str], None] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> ScanResult:
        """
        Execute the full scan workflow:
        1. Validate file
        2. Calculate SHA-256
        3. Query VirusTotal by hash
        4. Classify and return result

        Does NOT upload — that requires explicit user consent.
        """
        self._cancel_flag = False
        result = ScanResult()

        # Step 1: Validate
        if status_callback:
            status_callback("Validating file...")

        validation = validate_file(file_path)
        if not validation["valid"]:
            result.error = validation["error"]
            result.risk_level = RiskLevel.UNKNOWN
            msgs = get_risk_messages(RiskLevel.UNKNOWN)
            result.risk_title = msgs["title"]
            result.risk_message = msgs["message"]
            result.risk_detail = validation["error"]
            return result

        file_info = validation["file_info"]
        result.file_name = file_info["name"]
        result.file_path = file_info["path"]
        result.file_size = file_info["size"]
        result.file_size_display = file_info["size_display"]

        if self._cancel_flag:
            return self._cancelled_result(result)

        # Step 2: Hash
        if status_callback:
            status_callback("Calculating SHA-256...")

        try:
            sha256 = calculate_sha256(file_info["path"], progress_callback)
            result.sha256 = sha256
        except (FileNotFoundError, PermissionError, OSError) as e:
            result.error = f"Cannot read file: {e}"
            result.risk_level = RiskLevel.UNKNOWN
            msgs = get_risk_messages(RiskLevel.UNKNOWN)
            result.risk_title = msgs["title"]
            result.risk_message = msgs["message"]
            result.risk_detail = str(e)
            return result

        if self._cancel_flag:
            return self._cancelled_result(result)

        # Step 3: Query VirusTotal
        try:
            client = VirusTotalClient(self._api_key)

            vt_result = client.get_file_report(sha256, status_callback)

            # Merge local file info into VT result
            vt_result.file_name = result.file_name
            vt_result.file_path = result.file_path
            vt_result.file_size = result.file_size
            vt_result.file_size_display = result.file_size_display
            vt_result.sha256 = sha256

            if not vt_result.scan_timestamp:
                vt_result.scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            # Classify
            build_scan_result_classification(vt_result)

            client.close()
            return vt_result

        except FileNotFoundOnVTError:
            # File not in VT database — return UNKNOWN, let UI offer upload
            result.risk_level = RiskLevel.UNKNOWN
            result.risk_title = "NO INTEL AVAILABLE"
            result.risk_message = "WE HAVE NO INTEL ON THIS ONE"
            result.risk_detail = (
                "This file is not in the VirusTotal database. "
                "It has never been scanned before. "
                "Unknown does NOT mean safe."
            )
            result.analysis_status = "not_found"
            result.error = "not_found"
            result.scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            return result

        except APIKeyError as e:
            result.error = str(e)
            result.risk_level = RiskLevel.UNKNOWN
            result.risk_title = "API KEY ERROR"
            result.risk_message = "INVALID API KEY"
            result.risk_detail = str(e)
            return result

        except RateLimitError as e:
            result.error = str(e)
            result.risk_level = RiskLevel.UNKNOWN
            result.risk_title = "RATE LIMIT HIT"
            result.risk_message = "TOO MANY REQUESTS"
            result.risk_detail = (
                "VirusTotal rate limit exceeded. Free API keys allow 4 requests per minute. "
                "Wait a moment and try again."
            )
            return result

        except VirusTotalError as e:
            result.error = str(e)
            result.risk_level = RiskLevel.UNKNOWN
            result.risk_title = "SERVER CONNECTION LOST"
            result.risk_message = "COULDN'T REACH VIRUSTOTAL"
            result.risk_detail = str(e)
            return result

        except Exception as e:
            logger.exception("Unexpected error during scan")
            result.error = str(e)
            result.risk_level = RiskLevel.UNKNOWN
            result.risk_title = "SCAN ERROR"
            result.risk_message = "SOMETHING WENT WRONG"
            result.risk_detail = f"An unexpected error occurred: {type(e).__name__}: {e}"
            return result

    def upload_and_scan(
        self,
        file_path: str,
        status_callback: Callable[[str], None] | None = None,
    ) -> ScanResult:
        """
        Upload a file to VirusTotal and poll for results.
        Only call this after the user has explicitly consented.
        """
        result = ScanResult()
        validation = validate_file(file_path)
        if not validation["valid"]:
            result.error = validation["error"]
            return result

        file_info = validation["file_info"]
        result.file_name = file_info["name"]
        result.file_path = file_info["path"]
        result.file_size = file_info["size"]
        result.file_size_display = file_info["size_display"]

        # Check uploadability
        upload_check = is_uploadable(file_path)
        if not upload_check["can_upload"]:
            result.error = upload_check["error"]
            result.risk_level = RiskLevel.UNKNOWN
            msgs = get_risk_messages(RiskLevel.UNKNOWN)
            result.risk_title = msgs["title"]
            result.risk_message = msgs["message"]
            result.risk_detail = upload_check["error"]
            return result

        try:
            client = VirusTotalClient(self._api_key)

            # Upload
            analysis_id = client.upload_file(
                file_path, file_info["size"], status_callback
            )

            # Poll
            vt_result = client.poll_analysis(analysis_id, status_callback)

            # Merge local info
            vt_result.file_name = result.file_name
            vt_result.file_path = result.file_path
            vt_result.file_size = result.file_size
            vt_result.file_size_display = result.file_size_display

            if not vt_result.sha256:
                try:
                    vt_result.sha256 = calculate_sha256(file_path)
                except Exception:
                    pass

            vt_result.vt_report_url = f"https://www.virustotal.com/gui/file/{vt_result.sha256}"

            if not vt_result.scan_timestamp:
                vt_result.scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            build_scan_result_classification(vt_result)

            client.close()
            return vt_result

        except (APIKeyError, RateLimitError, UploadError, AnalysisError, VirusTotalError) as e:
            result.error = str(e)
            result.risk_level = RiskLevel.UNKNOWN
            msgs = get_risk_messages(RiskLevel.UNKNOWN)
            result.risk_title = msgs["title"]
            result.risk_message = msgs["message"]
            result.risk_detail = str(e)
            return result

        except Exception as e:
            logger.exception("Unexpected error during upload/scan")
            result.error = str(e)
            result.risk_level = RiskLevel.UNKNOWN
            result.risk_title = "UPLOAD ERROR"
            result.risk_message = "SOMETHING WENT WRONG"
            result.risk_detail = f"Unexpected error: {type(e).__name__}: {e}"
            return result

    def cancel(self):
        """Signal cancellation."""
        self._cancel_flag = True

    def _cancelled_result(self, result: ScanResult) -> ScanResult:
        result.risk_level = RiskLevel.UNKNOWN
        result.risk_title = "SCAN CANCELLED"
        result.risk_message = "Scan was cancelled by user."
        result.risk_detail = "No verdict was generated."
        return result
