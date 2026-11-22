"""Tests for report generation module."""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.models import ScanResult, ScanStatistics, EngineResult, RiskLevel
from src.core.report import generate_json_report, generate_text_report, DISCLAIMER


@pytest.fixture
def sample_scan_result():
    result = ScanResult(
        file_name="suspicious_mod.dll",
        file_path="C:\\Downloads\\suspicious_mod.dll",
        file_size=2048576,
        file_size_display="1.95 MB",
        file_type="Win32 DLL",
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        scan_timestamp="2026-11-21 21:00:00 UTC",
        risk_level=RiskLevel.DANGEROUS,
        risk_title="THIS IS NOT LOOT. THIS IS A TRAP.",
        risk_message="FINAL BOSS: MALWARE",
        risk_detail="Multiple security engines detected malicious activity.",
        statistics=ScanStatistics(
            malicious=12,
            suspicious=3,
            harmless=5,
            undetected=50,
            timeout=0,
            total=70
        ),
        engine_results=[
            EngineResult(engine_name="CrowdStrike", category="malicious", result="Win32.Trojan.Generic"),
            EngineResult(engine_name="Microsoft", category="malicious", result="Trojan:Win32/Wacatac.B!ml"),
            EngineResult(engine_name="Avast", category="suspicious", result="Win32:Evo-gen"),
            EngineResult(engine_name="Kaspersky", category="undetected", result=None),
        ],
        analysis_status="completed",
        vt_report_url="https://www.virustotal.com/gui/file/1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        is_complete=True
    )
    return result


class TestReportGeneration:
    def test_generate_json_report(self, sample_scan_result):
        json_str = generate_json_report(sample_scan_result)
        data = json.loads(json_str)

        assert data["application"] == "LootCheck"
        assert data["file"]["name"] == "suspicious_mod.dll"
        assert data["file"]["sha256"] == sample_scan_result.sha256
        assert data["classification"]["risk_level"] == "dangerous"
        assert data["statistics"]["malicious"] == 12
        assert data["statistics"]["total_engines"] == 70
        assert len(data["engine_results"]) == 3  # malicious & suspicious
        assert len(data["all_engine_results"]) == 4
        assert "disclaimer" in data
        assert "api_key" not in json_str.lower()

    def test_generate_text_report(self, sample_scan_result):
        text = generate_text_report(sample_scan_result)

        assert "LOOTCHECK SCAN REPORT" in text
        assert "suspicious_mod.dll" in text
        assert sample_scan_result.sha256 in text
        assert "DANGEROUS" in text
        assert "FLAGGING ENGINES" in text
        assert "CrowdStrike" in text
        assert "Win32.Trojan.Generic" in text
        assert DISCLAIMER in text
        assert "api_key" not in text.lower()
