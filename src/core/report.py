"""Report generation module for LootCheck."""

import json
import logging
from datetime import datetime, timezone

from src.api.models import ScanResult, RiskLevel

logger = logging.getLogger('LootCheck')

DISCLAIMER = (
    "DISCLAIMER: VirusTotal is a multi-engine scanning service, not a guarantee "
    "that a file is safe. Detection results can change over time, malware can be "
    "undetected, and false positives can occur. Uploading a file to VirusTotal "
    "may expose the sample to security researchers and third parties. "
    "LootCheck does not execute, modify, or install any scanned file. "
    "Use this tool as one input in your security decisions, not as the sole authority."
)


def generate_json_report(scan_result: ScanResult) -> str:
    """Generate a JSON report from scan results."""
    report = {
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": "LootCheck",
        "file": {
            "name": scan_result.file_name,
            "size_bytes": scan_result.file_size,
            "size_display": scan_result.file_size_display,
            "type": scan_result.file_type,
            "sha256": scan_result.sha256,
        },
        "scan": {
            "timestamp": scan_result.scan_timestamp,
            "status": scan_result.analysis_status,
            "complete": scan_result.is_complete,
        },
        "classification": {
            "risk_level": scan_result.risk_level.value,
            "title": scan_result.risk_title,
            "message": scan_result.risk_message,
            "detail": scan_result.risk_detail,
        },
        "statistics": {
            "malicious": scan_result.statistics.malicious,
            "suspicious": scan_result.statistics.suspicious,
            "harmless": scan_result.statistics.harmless,
            "undetected": scan_result.statistics.undetected,
            "timeout": scan_result.statistics.timeout,
            "total_engines": scan_result.statistics.total,
            "detection_ratio": scan_result.statistics.detection_ratio,
            "detection_percentage": round(scan_result.statistics.detection_percentage, 2),
        },
        "engine_results": [
            {
                "engine": er.engine_name,
                "category": er.category,
                "result": er.result,
            }
            for er in scan_result.engine_results
            if er.category in ("malicious", "suspicious")
        ],
        "all_engine_results": [
            {
                "engine": er.engine_name,
                "category": er.category,
                "result": er.result,
            }
            for er in scan_result.engine_results
        ],
        "virustotal_report_url": scan_result.vt_report_url,
        "disclaimer": DISCLAIMER,
    }

    return json.dumps(report, indent=2, ensure_ascii=False)


def generate_text_report(scan_result: ScanResult) -> str:
    """Generate a plain text report from scan results."""
    lines = [
        "=" * 70,
        "LOOTCHECK SCAN REPORT",
        "=" * 70,
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "FILE INFORMATION",
        "-" * 40,
        f"  Filename:  {scan_result.file_name}",
        f"  Size:      {scan_result.file_size_display} ({scan_result.file_size:,} bytes)",
        f"  Type:      {scan_result.file_type}",
        f"  SHA-256:   {scan_result.sha256}",
        "",
        "SCAN RESULTS",
        "-" * 40,
        f"  Scan Date:      {scan_result.scan_timestamp}",
        f"  Status:         {scan_result.analysis_status}",
        f"  Classification: {scan_result.risk_level.value.upper()}",
        f"  Verdict:        {scan_result.risk_title}",
        f"  Message:        {scan_result.risk_message}",
        "",
        "DETECTION STATISTICS",
        "-" * 40,
        f"  Detection Ratio:  {scan_result.statistics.detection_ratio}",
        f"  Malicious:        {scan_result.statistics.malicious}",
        f"  Suspicious:       {scan_result.statistics.suspicious}",
        f"  Harmless:         {scan_result.statistics.harmless}",
        f"  Undetected:       {scan_result.statistics.undetected}",
        f"  Total Engines:    {scan_result.statistics.total}",
        "",
    ]

    # Flagging engines
    flagged = [e for e in scan_result.engine_results if e.category in ("malicious", "suspicious")]
    if flagged:
        lines.append("FLAGGING ENGINES")
        lines.append("-" * 40)
        for engine in flagged:
            verdict = engine.result or engine.category
            lines.append(f"  [{engine.category.upper()}] {engine.engine_name}: {verdict}")
        lines.append("")

    lines.extend([
        "VIRUSTOTAL REPORT",
        "-" * 40,
        f"  {scan_result.vt_report_url}",
        "",
        "DISCLAIMER",
        "-" * 40,
        f"  {DISCLAIMER}",
        "",
        "=" * 70,
    ])

    return "\n".join(lines)
