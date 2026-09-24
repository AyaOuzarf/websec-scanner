"""
Risk Scoring Utility
Calculates an overall risk score and letter grade from a list of findings,
based on severity-weighted counts.
"""

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 0.5,
}


def calculate_risk_score(findings: list) -> dict:
    """
    Takes a flat list of findings (each with a 'severity' key) and returns
    a risk score (0-100, capped) plus a letter grade and severity breakdown.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    raw_score = sum(
        SEVERITY_WEIGHTS[sev] * count for sev, count in severity_counts.items()
    )
    # Cap at 100 so the score stays readable
    score = min(round(raw_score), 100)

    if score == 0:
        grade = "A+"
    elif score <= 10:
        grade = "A"
    elif score <= 25:
        grade = "B"
    elif score <= 45:
        grade = "C"
    elif score <= 70:
        grade = "D"
    else:
        grade = "F"

    return {
        "risk_score": score,
        "grade": grade,
        "severity_breakdown": severity_counts,
        "total_findings": len(findings),
    }