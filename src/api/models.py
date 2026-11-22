"""Data models for VirusTotal API responses."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(Enum):
    """Risk classification levels."""
    SAFE = "safe"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"


@dataclass
class EngineResult:
    """Individual antivirus engine result."""
    engine_name: str
    category: str         # "malicious", "suspicious", "undetected", "harmless", "timeout", etc.
    result: str | None    # Detection name or None
    engine_version: str | None = None
    engine_update: str | None = None


@dataclass
class ScanStatistics:
    """Aggregated scan statistics."""
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0
    confirmed_timeout: int = 0
    failure: int = 0
    type_unsupported: int = 0
    total: int = 0

    @property
    def detection_count(self) -> int:
        return self.malicious + self.suspicious

    @property
    def detection_ratio(self) -> str:
        if self.total == 0:
            return "0/0"
        return f"{self.malicious}/{self.total}"

    @property
    def detection_percentage(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.malicious / self.total) * 100


@dataclass
class ScanResult:
    """Complete scan result."""
    file_name: str = ""
    file_path: str = ""
    file_size: int = 0
    file_size_display: str = ""
    file_type: str = ""
    sha256: str = ""
    scan_timestamp: str = ""
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_title: str = ""
    risk_message: str = ""
    risk_detail: str = ""
    statistics: ScanStatistics = field(default_factory=ScanStatistics)
    engine_results: list[EngineResult] = field(default_factory=list)
    analysis_status: str = ""
    vt_report_url: str = ""
    error: str | None = None
    is_complete: bool = False
    raw_response: dict[str, Any] | None = None

    @property
    def malicious_engines(self) -> list[EngineResult]:
        return [e for e in self.engine_results if e.category == "malicious"]

    @property
    def suspicious_engines(self) -> list[EngineResult]:
        return [e for e in self.engine_results if e.category == "suspicious"]
