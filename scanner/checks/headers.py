"""
HTTP Security Headers Check
Analyzes a target URL's response headers for missing/misconfigured
security headers, following OWASP Secure Headers Project guidance.
"""

import requests
from datetime import datetime, timezone


# Each entry: header name -> (severity if missing, recommendation)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "high",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to force HTTPS."
    ),
    "Content-Security-Policy": (
        "high",
        "Add a Content-Security-Policy header to mitigate XSS and data injection attacks."
    ),
    "X-Frame-Options": (
        "medium",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking."
    ),
    "X-Content-Type-Options": (
        "medium",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks."
    ),
    "Referrer-Policy": (
        "low",
        "Add a Referrer-Policy header to control referrer information leakage."
    ),
    "Permissions-Policy": (
        "low",
        "Add a Permissions-Policy header to restrict browser feature access."
    ),
}

# Headers that leak server/tech info and should ideally be removed or masked
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def run(target_url: str, timeout: int = 10) -> dict:
    """
    Run the security headers check against a target URL.
    Returns a normalized result dict with findings list.
    """
    findings = []

    try:
        response = requests.get(target_url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return {
            "check": "http_security_headers",
            "target": target_url,
            "status": "error",
            "error": str(e),
            "findings": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    headers = response.headers

    # Check for missing security headers
    for header_name, (severity, recommendation) in SECURITY_HEADERS.items():
        if header_name not in headers:
            findings.append({
                "finding": f"Missing '{header_name}' header",
                "severity": severity,
                "tool": "custom-header-check",
                "recommendation": recommendation,
            })

    # Check for info-leaking headers
    for header_name in INFO_LEAK_HEADERS:
        if header_name in headers:
            findings.append({
                "finding": f"'{header_name}' header exposes technology info: {headers[header_name]}",
                "severity": "low",
                "tool": "custom-header-check",
                "recommendation": f"Remove or mask the '{header_name}' header to reduce information disclosure.",
            })

    return {
        "check": "http_security_headers",
        "target": target_url,
        "status": "completed",
        "status_code": response.status_code,
        "findings": findings,
        "findings_count": len(findings),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import json
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    result = run(url)
    print(json.dumps(result, indent=2))