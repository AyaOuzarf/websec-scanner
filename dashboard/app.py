"""
WebSec Scanner Dashboard
Streamlit frontend for triggering scans and viewing security reports.
"""

import time
import requests
import pandas as pd
import plotly.express as px
import streamlit as st

API_BASE_URL = "http://localhost:8001"

st.set_page_config(page_title="WebSec Scanner", page_icon="🛡️", layout="wide")

SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#dc2626",
    "medium": "#f59e0b",
    "low": "#3b82f6",
    "info": "#9ca3af",
}


# ---------- Sidebar navigation ----------
st.sidebar.title("🛡️ WebSec Scanner")
page = st.sidebar.radio("Navigate", ["New Scan", "Scan History"])


# ---------- Helpers ----------
def trigger_scan(target_url: str):
    response = requests.post(f"{API_BASE_URL}/scan", json={"target_url": target_url})
    response.raise_for_status()
    return response.json()


def get_scan(scan_id: str):
    response = requests.get(f"{API_BASE_URL}/scan/{scan_id}")
    response.raise_for_status()
    return response.json()


def list_scans():
    response = requests.get(f"{API_BASE_URL}/scan")
    response.raise_for_status()
    return response.json()


def render_report(scan: dict):
    """Render a completed scan's report: score, severity chart, findings table."""
    risk_score = scan.get("risk_score")
    grade = scan.get("grade")
    total_findings = scan.get("total_findings")

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Score", f"{risk_score}/100" if risk_score is not None else "—")
    col2.metric("Grade", grade or "—")
    col3.metric("Total Findings", total_findings if total_findings is not None else "—")

    report = scan.get("report")
    if not report:
        st.info("No detailed report available yet.")
        return

    findings = report.get("findings", [])
    if not findings:
        st.success("No findings — clean scan!")
        return

    # Severity breakdown chart
    df = pd.DataFrame(findings)
    severity_counts = df["severity"].value_counts().reset_index()
    severity_counts.columns = ["severity", "count"]

    fig = px.pie(
        severity_counts,
        names="severity",
        values="count",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Findings by Severity",
    )
    st.plotly_chart(fig, use_container_width=True)

    # Findings table, sorted by severity priority
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    df["_sort"] = df["severity"].map(severity_order)
    df = df.sort_values("_sort").drop(columns="_sort")

    st.subheader("Findings Detail")
    for _, row in df.iterrows():
        severity = row.get("severity", "info")
        with st.expander(f"[{severity.upper()}] {row.get('finding', 'Unknown finding')}"):
            st.write(f"**Tool:** {row.get('tool', 'N/A')}")
            st.write(f"**Recommendation:** {row.get('recommendation', 'N/A')}")
            if row.get("matched_at"):
                st.write(f"**Matched at:** {row.get('matched_at')}")
            if row.get("reference"):
                st.write(f"**References:** {row.get('reference')}")


# ---------- Page: New Scan ----------
if page == "New Scan":
    st.title("Run a New Security Scan")
    st.caption("Only scan domains you own or have explicit written authorization to test.")

    target_url = st.text_input("Target URL", placeholder="http://localhost:8080")
    confirm = st.checkbox("I confirm I am authorized to scan this target")

    if st.button("Start Scan", type="primary", disabled=not (target_url and confirm)):
        with st.spinner("Launching scan..."):
            scan = trigger_scan(target_url)
            scan_id = scan["id"]

        st.success(f"Scan started — ID: `{scan_id}`")

        progress_placeholder = st.empty()
        result_placeholder = st.empty()

        status = "pending"
        while status in ("pending", "running"):
            scan = get_scan(scan_id)
            status = scan["status"]
            progress_placeholder.info(f"Status: **{status}**...")
            time.sleep(3)

        progress_placeholder.empty()

        if status == "completed":
            st.balloons()
            with result_placeholder.container():
                render_report(scan)
        else:
            st.error(f"Scan ended with status: {status}")
            if scan.get("report"):
                st.json(scan["report"])


# ---------- Page: Scan History ----------
elif page == "Scan History":
    st.title("Scan History")

    scans = list_scans()
    if not scans:
        st.info("No scans yet — run one from the 'New Scan' page.")
    else:
        df = pd.DataFrame(scans)
        st.dataframe(
            df[["target", "status", "risk_score", "grade", "total_findings", "created_at"]],
            use_container_width=True,
        )

        st.subheader("View Full Report")
        selected_id = st.selectbox("Select a scan by ID", df["id"].tolist())
        if selected_id:
            scan = get_scan(selected_id)
            st.divider()
            render_report(scan)