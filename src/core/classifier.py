"""Risk classification engine for LootCheck."""

import logging
from src.api.models import RiskLevel, ScanResult, ScanStatistics

logger = logging.getLogger('LootCheck')

# Default thresholds (can be overridden)
DEFAULT_THRESHOLDS = {
    "low_risk_max": 2,
    "suspicious_min": 3,
    "dangerous_min": 5,
    "dangerous_ratio": 0.08,
}

# Risk messages — gamer-friendly
RISK_MESSAGES = {
    RiskLevel.SAFE: {
        "title": "YOUR LOOT LOOKS CLEAN",
        "message": "NO THREATS DETECTED",
        "detail": "Looks clean so far. No security engines flagged this file.",
        "disclaimer": (
            "Zero detections does NOT guarantee this file is safe. "
            "New, modified, or undetected malware can still exist."
        ),
    },
    RiskLevel.LOW_RISK: {
        "title": "SMALL RED FLAG",
        "message": "POSSIBLE FALSE POSITIVE",
        "detail": (
            "A few engines flagged this file. It may be a false positive, "
            "but proceed carefully."
        ),
    },
    RiskLevel.SUSPICIOUS: {
        "title": "THIS FILE IS SUS",
        "message": "SUSPICIOUS FILE DETECTED",
        "detail": (
            "Several security engines flagged this file. "
            "We recommend NOT running it until you investigate further. "
            "Your PC isn't worth the gamble."
        ),
    },
    RiskLevel.DANGEROUS: {
        "title": "THIS IS NOT LOOT. THIS IS A TRAP.",
        "message": "FINAL BOSS: MALWARE",
        "detail": (
            "Multiple security engines detected malicious activity. "
            "Running this file could compromise your PC, accounts, or personal data. "
            "Do not run it."
        ),
    },
    RiskLevel.UNKNOWN: {
        "title": "NO INTEL AVAILABLE",
        "message": "WE HAVE NO INTEL ON THIS ONE",
        "detail": (
            "We couldn't verify this file. "
            "Unknown does NOT mean safe."
        ),
    },
}


def classify_risk(
    statistics: ScanStatistics,
    analysis_complete: bool = True,
    thresholds: dict | None = None,
) -> RiskLevel:
    """
    Classify the risk level of a scan based on detection statistics.

    Args:
        statistics: Aggregated scan statistics.
        analysis_complete: Whether the analysis has completed.
        thresholds: Optional custom thresholds.

    Returns:
        RiskLevel enum value.
    """
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}

    # If analysis is not complete, we can't make a determination
    if not analysis_complete:
        logger.info("Analysis incomplete — classifying as UNKNOWN")
        return RiskLevel.UNKNOWN

    # If no engines responded, we have no data
    if statistics.total == 0:
        logger.info("No engines responded — classifying as UNKNOWN")
        return RiskLevel.UNKNOWN

    malicious = statistics.malicious
    suspicious = statistics.suspicious
    total = statistics.total

    # Calculate detection ratio
    detection_ratio = malicious / total if total > 0 else 0

    logger.info(
        "Classification input: malicious=%d, suspicious=%d, total=%d, ratio=%.3f",
        malicious, suspicious, total, detection_ratio
    )

    # DANGEROUS: High detections or high ratio
    if malicious >= t["dangerous_min"] or detection_ratio >= t["dangerous_ratio"]:
        logger.info("Classified as DANGEROUS")
        return RiskLevel.DANGEROUS

    # SUSPICIOUS: Moderate detections or significant suspicious flags
    if malicious >= t["suspicious_min"] or suspicious >= t["suspicious_min"]:
        logger.info("Classified as SUSPICIOUS")
        return RiskLevel.SUSPICIOUS

    # LOW RISK: One or two detections
    if malicious > 0 or suspicious > 0:
        if malicious <= t["low_risk_max"]:
            logger.info("Classified as LOW_RISK")
            return RiskLevel.LOW_RISK
        logger.info("Classified as SUSPICIOUS (edge case)")
        return RiskLevel.SUSPICIOUS

    # SAFE: No detections at all
    logger.info("Classified as SAFE")
    return RiskLevel.SAFE


def get_risk_messages(risk_level: RiskLevel) -> dict:
    """Get the display messages for a risk level."""
    return RISK_MESSAGES.get(risk_level, RISK_MESSAGES[RiskLevel.UNKNOWN])


def build_scan_result_classification(scan_result: ScanResult) -> ScanResult:
    """
    Apply risk classification to a scan result and populate messages.

    Modifies and returns the scan result with classification data.
    """
    risk_level = classify_risk(
        scan_result.statistics,
        analysis_complete=scan_result.is_complete,
    )

    messages = get_risk_messages(risk_level)

    scan_result.risk_level = risk_level
    scan_result.risk_title = messages["title"]
    scan_result.risk_message = messages["message"]
    scan_result.risk_detail = messages["detail"]

    return scan_result
