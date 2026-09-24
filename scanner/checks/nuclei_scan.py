"""
Nuclei Vulnerability Scan
Wraps the Nuclei CLI tool to run template-based vulnerability detection
against a target URL, normalizing results into the platform's finding format.
"""

import json
import subprocess
from datetime import datetime, timezone

# Map Nuclei's severity levels directly (they already match our scale)
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def run(target_url: str, timeout: int = 300, severity_filter: str = None) -> dict:
    """
    Run a Nuclei scan against a target URL.
    severity_filter: optional comma-separated string e.g. "critical,high,medium"
                      to limit scan scope and runtime.
    Returns a normalized result dict with findings list.
    """
    findings = []

    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",           # newline-delimited JSON output, easy to parse
        "-silent",          # suppress banner/progress noise
        "-no-color",
    ]

    if severity_filter:
        cmd.extend(["-severity", severity_filter])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "check": "nuclei_scan",
            "target": target_url,
            "status": "error",
            "error": f"Scan timed out after {timeout}s",
            "findings": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except FileNotFoundError:
        return {
            "check": "nuclei_scan",
            "target": target_url,
            "status": "error",
            "error": "nuclei binary not found — is it installed and in PATH?",
            "findings": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # Nuclei outputs one JSON object per line (JSONL), one per finding
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = entry.get("info", {})
        severity = info.get("severity", "info").lower()
        if severity not in VALID_SEVERITIES:
            severity = "info"

        findings.append({
            "finding": info.get("name", entry.get("template-id", "Unknown finding")),
            "severity": severity,
            "tool": "nuclei",
            "template_id": entry.get("template-id"),
            "matched_at": entry.get("matched-at"),
            "recommendation": info.get("remediation") or "Review the matched template details and apply the relevant fix.",
            "reference": info.get("reference", []),
        })

    return {
        "check": "nuclei_scan",
        "target": target_url,
        "status": "completed",
        "findings": findings,
        "findings_count": len(findings),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    # Start with common/quick templates only, to keep first test runs fast
    result = run(url, severity_filter="critical,high,medium")
    print(json.dumps(result, indent=2))