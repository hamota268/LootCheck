"""Tests for the risk classification engine."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.classifier import classify_risk, get_risk_messages, build_scan_result_classification
from src.api.models import RiskLevel, ScanStatistics, ScanResult


class TestClassifyRisk:
    """Tests for risk classification."""

    def test_zero_detections_safe(self):
        """Zero detections should be classified as SAFE."""
        stats = ScanStatistics(malicious=0, suspicious=0, undetected=60, harmless=5, total=65)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.SAFE

    def test_one_detection_low_risk(self):
        """One malicious detection should be LOW_RISK."""
        stats = ScanStatistics(malicious=1, suspicious=0, undetected=60, harmless=5, total=66)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.LOW_RISK

    def test_two_detections_low_risk(self):
        """Two malicious detections should be LOW_RISK."""
        stats = ScanStatistics(malicious=2, suspicious=0, undetected=60, harmless=5, total=67)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.LOW_RISK

    def test_three_detections_suspicious(self):
        """Three malicious detections should be SUSPICIOUS."""
        stats = ScanStatistics(malicious=3, suspicious=0, undetected=60, harmless=5, total=68)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.SUSPICIOUS

    def test_four_detections_suspicious(self):
        """Four malicious detections should be SUSPICIOUS."""
        stats = ScanStatistics(malicious=4, suspicious=0, undetected=60, harmless=5, total=69)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.SUSPICIOUS

    def test_five_detections_dangerous(self):
        """Five malicious detections should be DANGEROUS."""
        stats = ScanStatistics(malicious=5, suspicious=0, undetected=60, harmless=5, total=70)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.DANGEROUS

    def test_high_detections_dangerous(self):
        """Many malicious detections should be DANGEROUS."""
        stats = ScanStatistics(malicious=30, suspicious=5, undetected=20, harmless=5, total=60)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.DANGEROUS

    def test_high_ratio_dangerous(self):
        """High detection ratio (>8%) should be DANGEROUS."""
        stats = ScanStatistics(malicious=4, suspicious=0, undetected=40, harmless=5, total=49)
        result = classify_risk(stats, analysis_complete=True)
        # 4/49 = 8.16% — above threshold
        assert result == RiskLevel.DANGEROUS

    def test_suspicious_only(self):
        """Three suspicious-only detections should be SUSPICIOUS."""
        stats = ScanStatistics(malicious=0, suspicious=3, undetected=60, harmless=5, total=68)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.SUSPICIOUS

    def test_one_suspicious_low_risk(self):
        """One suspicious detection should be LOW_RISK."""
        stats = ScanStatistics(malicious=0, suspicious=1, undetected=60, harmless=5, total=66)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.LOW_RISK

    def test_incomplete_analysis_unknown(self):
        """Incomplete analysis should be UNKNOWN."""
        stats = ScanStatistics(malicious=0, suspicious=0, undetected=10, total=10)
        result = classify_risk(stats, analysis_complete=False)
        assert result == RiskLevel.UNKNOWN

    def test_no_engines_unknown(self):
        """Zero total engines should be UNKNOWN."""
        stats = ScanStatistics(malicious=0, suspicious=0, total=0)
        result = classify_risk(stats, analysis_complete=True)
        assert result == RiskLevel.UNKNOWN

    def test_custom_thresholds(self):
        """Custom thresholds should work."""
        stats = ScanStatistics(malicious=3, suspicious=0, undetected=60, total=63)

        # With default thresholds: SUSPICIOUS (3 >= suspicious_min)
        result_default = classify_risk(stats, analysis_complete=True)
        assert result_default == RiskLevel.SUSPICIOUS

        # With higher thresholds: LOW_RISK
        result_custom = classify_risk(
            stats, analysis_complete=True,
            thresholds={"low_risk_max": 3, "suspicious_min": 5, "dangerous_min": 10}
        )
        assert result_custom == RiskLevel.LOW_RISK


class TestGetRiskMessages:
    """Tests for risk message retrieval."""

    def test_all_risk_levels_have_messages(self):
        """Every risk level should have messages."""
        for level in RiskLevel:
            messages = get_risk_messages(level)
            assert "title" in messages
            assert "message" in messages
            assert "detail" in messages

    def test_safe_has_disclaimer(self):
        """SAFE level should have a disclaimer."""
        messages = get_risk_messages(RiskLevel.SAFE)
        assert "disclaimer" in messages


class TestBuildScanResultClassification:
    """Tests for scan result classification."""

    def test_classifies_safe_result(self):
        """Should correctly classify a safe scan result."""
        result = ScanResult()
        result.statistics = ScanStatistics(malicious=0, suspicious=0, undetected=60, total=60)
        result.is_complete = True

        classified = build_scan_result_classification(result)

        assert classified.risk_level == RiskLevel.SAFE
        assert classified.risk_title != ""
        assert classified.risk_message != ""

    def test_classifies_dangerous_result(self):
        """Should correctly classify a dangerous scan result."""
        result = ScanResult()
        result.statistics = ScanStatistics(malicious=20, suspicious=5, undetected=40, total=65)
        result.is_complete = True

        classified = build_scan_result_classification(result)

        assert classified.risk_level == RiskLevel.DANGEROUS

    def test_classifies_incomplete_as_unknown(self):
        """Should classify incomplete analysis as UNKNOWN."""
        result = ScanResult()
        result.statistics = ScanStatistics(malicious=0, suspicious=0, total=0)
        result.is_complete = False

        classified = build_scan_result_classification(result)

        assert classified.risk_level == RiskLevel.UNKNOWN
