"""
Scan Orchestrator
Runs all security checks against a target URL in parallel, merges their
findings into one normalized report, and calculates an overall risk score.
"""

import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from scanner.checks import headers, ssl_check, nuclei_scan
from scanner.utils.scoring import calculate_risk_score

# Register checks here — add new ones as you build them (e.g. wpscan_check later)
CHECKS = {
    "http_security_headers": headers.run,
    "ssl_tls": ssl_check.run,
    "nuclei_scan": nuclei_scan.run,
}


def run_full_scan(target_url: str, checks_to_run: list = None) -> dict:
    """
    Run selected (or all) checks against a target URL concurrently.
    Returns one unified report dict.
    """
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    checks_to_run = checks_to_run or list(CHECKS.keys())
    check_results = {}
    all_findings = []

    with ThreadPoolExecutor(max_workers=len(checks_to_run)) as executor:
        future_to_check = {
            executor.submit(CHECKS[check_name], target_url): check_name
            for check_name in checks_to_run
            if check_name in CHECKS
        }

        for future in as_completed(future_to_check):
            check_name = future_to_check[future]
            try:
                result = future.result()
            except Exception as e:
                result = {
                    "check": check_name,
                    "target": target_url,
                    "status": "error",
                    "error": str(e),
                    "findings": [],
                }
            check_results[check_name] = result
            all_findings.extend(result.get("findings", []))

    risk_summary = calculate_risk_score(all_findings)

    report = {
        "scan_id": scan_id,
        "target": target_url,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checks_run": checks_to_run,
        "risk_summary": risk_summary,
        "findings": all_findings,
        "check_details": check_results,
    }

    return report


def save_report(report: dict, output_dir: str = "reports/output") -> str:
    """Save a scan report as JSON and return the file path."""
    import os
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"scan_{report['scan_id']}.json")
    with open(file_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return file_path


if __name__ == "__main__":
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    print(f"Running full scan against {url}...")

    report = run_full_scan(url)
    path = save_report(report)

    print(f"\nScan complete. Risk Grade: {report['risk_summary']['grade']} "
          f"(Score: {report['risk_summary']['risk_score']}/100)")
    print(f"Total findings: {report['risk_summary']['total_findings']}")
    print(f"Full report saved to: {path}")