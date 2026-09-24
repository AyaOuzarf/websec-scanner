"""
SSL/TLS Security Check
Analyzes a target's TLS configuration: certificate validity/expiry,
supported protocol versions, and weak cipher usage.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse

from sslyze import (
    ServerNetworkLocation,
    ServerScanRequest,
    Scanner,
    ScanCommand,
)


def _get_hostname(target_url: str) -> str:
    parsed = urlparse(target_url)
    return parsed.hostname or target_url


def run(target_url: str, timeout: int = 15) -> dict:
    """
    Run an SSL/TLS check against a target URL's host.
    Returns a normalized result dict with findings list.
    """
    hostname = _get_hostname(target_url)
    findings = []

    try:
        server_location = ServerNetworkLocation(hostname=hostname, port=443)
        scanner = Scanner()
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
            },
        )
        scanner.queue_scans([scan_request])
        result = next(scanner.get_results())

    except Exception as e:
        return {
            "check": "ssl_tls",
            "target": target_url,
            "status": "error",
            "error": str(e),
            "findings": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # --- Certificate checks ---
    cert_result = result.scan_result.certificate_info
    if cert_result.status.value == "COMPLETED":
        for deployment in cert_result.result.certificate_deployments:
            leaf_cert = deployment.received_certificate_chain[0]
            not_after = leaf_cert.not_valid_after
            days_left = (not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days

            if days_left < 0:
                findings.append({
                    "finding": "SSL certificate has expired",
                    "severity": "critical",
                    "tool": "sslyze",
                    "recommendation": "Renew the SSL certificate immediately.",
                })
            elif days_left < 30:
                findings.append({
                    "finding": f"SSL certificate expires in {days_left} days",
                    "severity": "medium",
                    "tool": "sslyze",
                    "recommendation": "Renew the SSL certificate before it expires.",
                })

            if not deployment.path_validation_results[0].was_validation_successful:
                findings.append({
                    "finding": "SSL certificate failed trust validation",
                    "severity": "high",
                    "tool": "sslyze",
                    "recommendation": "Ensure the certificate is issued by a trusted CA and the chain is complete.",
                })

    # --- Weak protocol checks ---
    weak_protocols = {
        "SSL 2.0": result.scan_result.ssl_2_0_cipher_suites,
        "SSL 3.0": result.scan_result.ssl_3_0_cipher_suites,
        "TLS 1.0": result.scan_result.tls_1_0_cipher_suites,
        "TLS 1.1": result.scan_result.tls_1_1_cipher_suites,
    }

    for protocol_name, scan_cmd_result in weak_protocols.items():
        if scan_cmd_result.status.value == "COMPLETED":
            accepted = scan_cmd_result.result.accepted_cipher_suites
            if accepted:
                findings.append({
                    "finding": f"Server accepts deprecated protocol: {protocol_name}",
                    "severity": "high",
                    "tool": "sslyze",
                    "recommendation": f"Disable {protocol_name} support; use TLS 1.2 or 1.3 only.",
                })

    return {
        "check": "ssl_tls",
        "target": target_url,
        "status": "completed",
        "findings": findings,
        "findings_count": len(findings),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import json
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = run(url)
    print(json.dumps(result, indent=2, default=str))