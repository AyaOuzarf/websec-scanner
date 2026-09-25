"""
PDF Report Generator
Renders a scan report (from the orchestrator's JSON structure) into a
client-ready PDF using a Jinja2 HTML template + WeasyPrint.
"""

import os
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def generate_pdf_report(scan_record: dict) -> str:
    """
    Takes a scan record dict (as returned by GET /scan/{id}) and generates
    a PDF file. Returns the path to the generated PDF.
    """
    report = scan_record.get("report") or {}
    risk_summary = report.get("risk_summary", {})

    context = {
        "target": scan_record.get("target"),
        "scan_id": scan_record.get("id"),
        "completed_at": scan_record.get("completed_at"),
        "grade": scan_record.get("grade", "N/A"),
        "risk_score": scan_record.get("risk_score", 0),
        "total_findings": scan_record.get("total_findings", 0),
        "severity_breakdown": risk_summary.get(
            "severity_breakdown",
            {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        ),
        "findings": report.get("findings", []),
    }

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")
    html_content = template.render(**context)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, f"report_{scan_record['id']}.pdf")

    HTML(string=html_content).write_pdf(output_path)
    return output_path


if __name__ == "__main__":
    import sys
    import requests

    scan_id = sys.argv[1]
    token = sys.argv[2]

    response = requests.get(
        f"http://localhost:8001/scan/{scan_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    response.raise_for_status()
    scan_record = response.json()

    path = generate_pdf_report(scan_record)
    print(f"PDF generated: {path}")