"""VirusTotal API v3 client for LootCheck."""

import logging
import time
from typing import Any

import requests

from src.utils.constants import (
    VT_API_BASE,
    VT_FILE_REPORT_URL,
    VT_FILE_UPLOAD_URL,
    VT_ANALYSIS_URL,
    VT_LARGE_FILE_URL,
    VT_WEB_REPORT_URL,
    VT_REQUEST_TIMEOUT,
    VT_UPLOAD_TIMEOUT,
    VT_POLL_INTERVAL,
    VT_MAX_POLL_ATTEMPTS,
    VT_STANDARD_UPLOAD_LIMIT,
)
from src.api.models import (
    EngineResult,
    ScanStatistics,
    ScanResult,
    RiskLevel,
)

logger = logging.getLogger('LootCheck')


class VirusTotalError(Exception):
    """Base exception for VirusTotal API errors."""
    def __init__(self, message: str, status_code: int | None = None, error_code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class APIKeyError(VirusTotalError):
    """Invalid or missing API key."""
    pass


class RateLimitError(VirusTotalError):
    """API rate limit exceeded."""
    pass


class FileNotFoundOnVTError(VirusTotalError):
    """File hash not found on VirusTotal."""
    pass


class UploadError(VirusTotalError):
    """File upload failed."""
    pass


class AnalysisError(VirusTotalError):
    """Analysis retrieval or polling failed."""
    pass


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    def __init__(self, api_key: str):
        if not api_key or not api_key.strip():
            raise APIKeyError("API key is empty or not provided.")
        self._api_key = api_key.strip()
        self._session = requests.Session()
        self._session.headers.update({
            "x-apikey": self._api_key,
            "Accept": "application/json",
        })

    def validate_api_key(self) -> bool:
        """
        Validate the API key by making a lightweight API call.

        Returns:
            True if the key is valid.

        Raises:
            APIKeyError: If the key is invalid.
            VirusTotalError: If the API is unreachable.
        """
        try:
            # Use the user endpoint to validate the key
            url = f"{VT_API_BASE}/users/current"
            response = self._session.get(url, timeout=VT_REQUEST_TIMEOUT)

            if response.status_code == 200:
                logger.info("API key validated successfully")
                return True
            elif response.status_code == 401:
                raise APIKeyError("Invalid API key.", status_code=401)
            elif response.status_code == 403:
                raise APIKeyError(
                    "API key is forbidden. Check your VirusTotal account.",
                    status_code=403
                )
            elif response.status_code == 429:
                raise RateLimitError(
                    "Rate limit exceeded. Try again later.",
                    status_code=429
                )
            else:
                raise VirusTotalError(
                    f"Unexpected response: HTTP {response.status_code}",
                    status_code=response.status_code
                )

        except requests.exceptions.ConnectionError:
            raise VirusTotalError("Cannot connect to VirusTotal. Check your internet connection.")
        except requests.exceptions.Timeout:
            raise VirusTotalError("Connection to VirusTotal timed out.")
        except requests.exceptions.RequestException as e:
            raise VirusTotalError(f"Network error: {e}")

    def get_file_report(self, sha256: str, status_callback=None) -> ScanResult:
        """
        Look up a file report by SHA-256 hash.

        Args:
            sha256: The SHA-256 hash of the file.
            status_callback: Optional callable(message) for status updates.

        Returns:
            ScanResult with the analysis data.

        Raises:
            FileNotFoundOnVTError: If the hash is not in VT's database.
            APIKeyError: If the API key is invalid.
            RateLimitError: If rate limited.
            VirusTotalError: For other API errors.
        """
        if status_callback:
            status_callback("Checking VirusTotal database...")

        url = f"{VT_FILE_REPORT_URL}/{sha256}"

        try:
            response = self._session.get(url, timeout=VT_REQUEST_TIMEOUT)
        except requests.exceptions.ConnectionError:
            raise VirusTotalError("Cannot connect to VirusTotal. Check your internet connection.")
        except requests.exceptions.Timeout:
            raise VirusTotalError("Connection to VirusTotal timed out.")
        except requests.exceptions.RequestException as e:
            raise VirusTotalError(f"Network error: {e}")

        if response.status_code == 404:
            raise FileNotFoundOnVTError(
                "File not found in VirusTotal database.",
                status_code=404
            )
        elif response.status_code == 401:
            raise APIKeyError("Invalid API key.", status_code=401)
        elif response.status_code == 429:
            raise RateLimitError(
                "API rate limit exceeded. Wait a moment and try again.",
                status_code=429
            )
        elif response.status_code != 200:
            raise VirusTotalError(
                f"VirusTotal returned HTTP {response.status_code}",
                status_code=response.status_code
            )

        try:
            data = response.json()
        except ValueError:
            raise VirusTotalError("Invalid response from VirusTotal (not JSON).")

        if status_callback:
            status_callback("Analyzing security verdicts...")

        return self._parse_file_report(data, sha256)

    def upload_file(self, file_path: str, file_size: int, status_callback=None) -> str:
        """
        Upload a file to VirusTotal for analysis.

        Args:
            file_path: Path to the file.
            file_size: Size of the file in bytes.
            status_callback: Optional callable(message) for status updates.

        Returns:
            Analysis ID string.

        Raises:
            UploadError: If upload fails.
        """
        try:
            # Determine upload URL
            if file_size > VT_STANDARD_UPLOAD_LIMIT:
                if status_callback:
                    status_callback("Getting large file upload URL...")
                upload_url = self._get_large_file_upload_url()
            else:
                upload_url = VT_FILE_UPLOAD_URL

            if status_callback:
                status_callback("Uploading file to VirusTotal...")

            with open(file_path, 'rb') as f:
                files = {"file": (self._safe_filename(file_path), f)}
                response = self._session.post(
                    upload_url,
                    files=files,
                    timeout=VT_UPLOAD_TIMEOUT,
                )

        except requests.exceptions.ConnectionError:
            raise UploadError("Lost connection during upload.")
        except requests.exceptions.Timeout:
            raise UploadError("Upload timed out.")
        except FileNotFoundError:
            raise UploadError("File was deleted or moved during upload.")
        except PermissionError:
            raise UploadError("Permission denied reading the file.")
        except requests.exceptions.RequestException as e:
            raise UploadError(f"Upload failed: {e}")

        if response.status_code == 401:
            raise APIKeyError("Invalid API key.", status_code=401)
        elif response.status_code == 429:
            raise RateLimitError("Rate limit exceeded during upload.", status_code=429)
        elif response.status_code not in (200, 201):
            raise UploadError(
                f"Upload returned HTTP {response.status_code}",
                status_code=response.status_code
            )

        try:
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            if not analysis_id:
                raise UploadError("Upload response missing analysis ID.")
            logger.info("File uploaded, analysis ID: %s", analysis_id)
            return analysis_id
        except ValueError:
            raise UploadError("Invalid response from VirusTotal after upload.")

    def poll_analysis(self, analysis_id: str, status_callback=None) -> ScanResult:
        """
        Poll for analysis completion.

        Args:
            analysis_id: The analysis ID from upload.
            status_callback: Optional callable(message) for status updates.

        Returns:
            ScanResult when analysis completes.

        Raises:
            AnalysisError: If polling fails or times out.
        """
        url = f"{VT_ANALYSIS_URL}/{analysis_id}"

        for attempt in range(VT_MAX_POLL_ATTEMPTS):
            if status_callback:
                status_callback(f"Waiting for analysis... (attempt {attempt + 1}/{VT_MAX_POLL_ATTEMPTS})")

            try:
                response = self._session.get(url, timeout=VT_REQUEST_TIMEOUT)
            except requests.exceptions.RequestException as e:
                if attempt < VT_MAX_POLL_ATTEMPTS - 1:
                    time.sleep(VT_POLL_INTERVAL)
                    continue
                raise AnalysisError(f"Network error while polling: {e}")

            if response.status_code == 429:
                # Rate limited, wait longer
                time.sleep(VT_POLL_INTERVAL * 2)
                continue

            if response.status_code != 200:
                if attempt < VT_MAX_POLL_ATTEMPTS - 1:
                    time.sleep(VT_POLL_INTERVAL)
                    continue
                raise AnalysisError(
                    f"Analysis polling returned HTTP {response.status_code}",
                    status_code=response.status_code
                )

            try:
                data = response.json()
            except ValueError:
                if attempt < VT_MAX_POLL_ATTEMPTS - 1:
                    time.sleep(VT_POLL_INTERVAL)
                    continue
                raise AnalysisError("Invalid JSON response during polling.")

            status = data.get("data", {}).get("attributes", {}).get("status")

            if status == "completed":
                logger.info("Analysis completed")
                # Get the full file report using the hash from the analysis
                meta = data.get("meta", {}).get("file_info", {})
                sha256 = meta.get("sha256", "")
                if sha256:
                    return self.get_file_report(sha256, status_callback)
                else:
                    # Parse what we have from the analysis
                    return self._parse_analysis_response(data)

            elif status == "queued" or status == "in-progress":
                time.sleep(VT_POLL_INTERVAL)
                continue
            else:
                # Unknown status, keep trying
                time.sleep(VT_POLL_INTERVAL)

        raise AnalysisError(
            "Analysis timed out. VirusTotal may still be processing the file. "
            "Try scanning again later."
        )

    def _get_large_file_upload_url(self) -> str:
        """Get a special upload URL for large files."""
        try:
            response = self._session.get(VT_LARGE_FILE_URL, timeout=VT_REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as e:
            raise UploadError(f"Failed to get large file upload URL: {e}")

        if response.status_code != 200:
            raise UploadError(
                f"Failed to get large file upload URL: HTTP {response.status_code}",
                status_code=response.status_code
            )

        try:
            data = response.json()
            url = data.get("data")
            if not url:
                raise UploadError("No upload URL in response.")
            return url
        except ValueError:
            raise UploadError("Invalid response getting upload URL.")

    def _parse_file_report(self, data: dict, sha256: str) -> ScanResult:
        """Parse a full file report response into a ScanResult."""
        result = ScanResult()
        result.sha256 = sha256
        result.vt_report_url = f"{VT_WEB_REPORT_URL}/{sha256}"

        try:
            attributes = data.get("data", {}).get("attributes", {})

            # File metadata from VT
            result.file_type = attributes.get("type_description", "Unknown")
            if not result.file_type or result.file_type == "Unknown":
                result.file_type = attributes.get("type_tag", "Unknown")

            # Last analysis stats
            stats = attributes.get("last_analysis_stats", {})
            result.statistics = ScanStatistics(
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                undetected=stats.get("undetected", 0),
                harmless=stats.get("harmless", 0),
                timeout=stats.get("timeout", 0),
                confirmed_timeout=stats.get("confirmed-timeout", 0),
                failure=stats.get("failure", 0),
                type_unsupported=stats.get("type-unsupported", 0),
            )
            result.statistics.total = sum([
                result.statistics.malicious,
                result.statistics.suspicious,
                result.statistics.undetected,
                result.statistics.harmless,
                result.statistics.timeout,
                result.statistics.confirmed_timeout,
                result.statistics.failure,
                result.statistics.type_unsupported,
            ])

            # Individual engine results
            last_analysis = attributes.get("last_analysis_results", {})
            for engine_name, engine_data in last_analysis.items():
                result.engine_results.append(EngineResult(
                    engine_name=engine_name,
                    category=engine_data.get("category", "unknown"),
                    result=engine_data.get("result"),
                    engine_version=engine_data.get("engine_version"),
                    engine_update=engine_data.get("engine_update"),
                ))

            # Sort: malicious first, then suspicious, then others
            category_order = {"malicious": 0, "suspicious": 1, "undetected": 2, "harmless": 3}
            result.engine_results.sort(
                key=lambda e: (category_order.get(e.category, 99), e.engine_name)
            )

            # Analysis date
            last_analysis_date = attributes.get("last_analysis_date")
            if last_analysis_date:
                from datetime import datetime, timezone
                try:
                    dt = datetime.fromtimestamp(last_analysis_date, tz=timezone.utc)
                    result.scan_timestamp = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                except (ValueError, OSError):
                    result.scan_timestamp = str(last_analysis_date)

            result.analysis_status = "completed"
            result.is_complete = True

        except Exception as e:
            logger.error("Error parsing VT response: %s", e)
            result.error = f"Error parsing scan results: {e}"
            result.is_complete = False

        return result

    def _parse_analysis_response(self, data: dict) -> ScanResult:
        """Parse an analysis-status response (less detail than a full file report)."""
        result = ScanResult()

        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("stats", {})

            result.statistics = ScanStatistics(
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                undetected=stats.get("undetected", 0),
                harmless=stats.get("harmless", 0),
                timeout=stats.get("timeout", 0),
                failure=stats.get("failure", 0),
                type_unsupported=stats.get("type-unsupported", 0),
            )
            result.statistics.total = sum([
                result.statistics.malicious,
                result.statistics.suspicious,
                result.statistics.undetected,
                result.statistics.harmless,
                result.statistics.timeout,
                result.statistics.failure,
                result.statistics.type_unsupported,
            ])

            # Parse individual results
            analysis_results = attributes.get("results", {})
            for engine_name, engine_data in analysis_results.items():
                result.engine_results.append(EngineResult(
                    engine_name=engine_name,
                    category=engine_data.get("category", "unknown"),
                    result=engine_data.get("result"),
                    engine_version=engine_data.get("engine_version"),
                    engine_update=engine_data.get("engine_update"),
                ))

            status = attributes.get("status", "unknown")
            result.analysis_status = status
            result.is_complete = (status == "completed")

        except Exception as e:
            logger.error("Error parsing analysis response: %s", e)
            result.error = f"Error parsing analysis: {e}"
            result.is_complete = False

        return result

    @staticmethod
    def _safe_filename(file_path: str) -> str:
        """Extract a safe filename for upload."""
        import os
        name = os.path.basename(file_path)
        # Limit length and remove control characters
        name = ''.join(c for c in name if c.isprintable())
        return name[:255] if name else "file"

    def close(self):
        """Close the HTTP session."""
        self._session.close()
