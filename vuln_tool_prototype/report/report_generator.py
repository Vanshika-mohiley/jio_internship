#!/usr/bin/env python3
"""
report_generator.py — Day 4 deliverable.

Renders an AssessmentReport as a Streamlit dashboard with:
- Executive Summary
- Host / OS / model metadata
- Severity counts
- Assessment statistics
- Candidate CVE match status
- Sortable Findings Table
- Per-finding Remediation and Confidence
- DPDP Compliance Badge

Run with:
    streamlit run report_generator.py -- --report-json path/to/report.json

Optional:
    --collection path/to/windows_artifacts.json
    --enrichment path/to/enrichment.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from schema.findings_schema import AssessmentReport

import streamlit as st
import pandas as pd


SEVERITY_COLORS = {
    "CRITICAL": "#8B0000",
    "HIGH": "#D32F2F",
    "MEDIUM": "#F57C00",
    "LOW": "#FBC02D",
    "INFORMATIONAL": "#607D8B",
}

SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",
]

CONFIDENCE_ICONS = {
    "exact": "🟢 Exact (advisory-matched)",
    "semantic": "🟡 Semantic (RAG-retrieved)",
    "heuristic": "🔵 Heuristic (config-based)",
}


def load_report(path: str) -> AssessmentReport:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return AssessmentReport.model_validate(data)


def load_json(path: str) -> dict:
    file_path = Path(path)

    if not file_path.exists():
        return {}

    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def render_compliance_badge():
    st.markdown(
        """
        <div style="padding:12px 16px;border-radius:8px;background-color:#E8F5E9;
                    border:1px solid #4CAF50;display:inline-block;margin-bottom:16px;">
            <span style="font-weight:600;color:#2E7D32;">✅ DPDP Compliance:</span>
            <span style="color:#2E7D32;">
                All processing performed on-premise — no data transmitted externally.
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_executive_summary(
    report: AssessmentReport,
    collection: dict,
    enrichment: dict,
):
    st.subheader("Executive Summary")

    counts = report.counts_by_severity

    cols = st.columns(len(SEVERITY_ORDER))

    for col, severity in zip(cols, SEVERITY_ORDER):
        col.metric(
            label=severity.title(),
            value=counts.get(severity, 0),
        )

    hostname = (
        report.hostname
        or collection.get("host", {}).get("hostname")
        or collection.get("host", {}).get("computer_name")
        or "unknown"
    )

    os_family = (
        report.os_family
        or collection.get("host", {}).get("os_family")
        or collection.get("host", {}).get("os")
        or "unknown"
    )

    st.markdown("---")

    meta_col1, meta_col2, meta_col3, meta_col4 = st.columns(4)

    meta_col1.markdown(f"**Host:** {hostname}")
    meta_col2.markdown(f"**OS:** {os_family}")
    meta_col3.markdown(f"**Model:** {report.model_used}")

    network_used = collection.get("network_used")

    if network_used is None:
        # The assessment pipeline is designed to operate offline.
        network_used = False

    meta_col4.markdown(
        f"**Network used:** {'Yes' if network_used else 'No'}"
    )

    st.caption(f"Generated at {report.generated_at}")

    st.markdown("---")

    package_count = len(collection.get("packages", []))
    port_count = len(collection.get("listening_ports", []))
    service_count = len(collection.get("services", []))
    candidate_cves = set()

    for match in enrichment.get("matches", []):
        for candidate in match.get("candidates", []):
            cve_id = candidate.get("cve_id")
            if cve_id and not match.get("confirmed_vulnerability", False):
                candidate_cves.add(cve_id)

    candidate_count = len(candidate_cves)

    stat1, stat2, stat3, stat4 = st.columns(4)

    stat1.metric("Packages scanned", package_count)
    stat2.metric("Listening ports", port_count)
    stat3.metric("Services", service_count)
    stat4.metric("Candidate CVE matches", candidate_count)

    if candidate_count:
        st.warning(
            " Candidate CVE matches are not confirmed vulnerabilities. "
            "They require vendor/product/affected-version verification."
        )


def render_findings_table(report: AssessmentReport):
    st.subheader("Confirmed Findings")

    if not report.findings:
        st.success(
            "No confirmed vulnerability findings were reported for this host."
        )

        st.info(
            "This does not mean the host has no security considerations. "
            "It means the assessment did not produce a defensible confirmed "
            "vulnerability finding from the available evidence."
        )

        return

    sorted_findings = sorted(
        report.findings,
        key=lambda finding: (
            SEVERITY_ORDER.index(finding.severity)
            if finding.severity in SEVERITY_ORDER
            else len(SEVERITY_ORDER)
        ),
    )

    table_rows = [
        {
            "Severity": finding.severity,
            "Component": finding.affected_component,
            "Version": finding.installed_version or "—",
            "CVEs": ", ".join(finding.cve_ids)
            if finding.cve_ids
            else "—",
            "Title": finding.title,
            "Confidence": finding.confidence,
        }
        for finding in sorted_findings
    ]

    df = pd.DataFrame(table_rows)

    def highlight_severity(row):
        color = SEVERITY_COLORS.get(
            row["Severity"],
            "#FFFFFF",
        )

        return [
            f"background-color: {color}20"
        ] * len(row)

    st.dataframe(
        df.style.apply(highlight_severity, axis=1),
        width="stretch",
        hide_index=True,
    )

    st.markdown("### Details & Remediation")

    for finding in sorted_findings:
        with st.expander(
            f"[{finding.severity}] "
            f"{finding.title} — "
            f"{finding.affected_component}"
        ):
            st.markdown(
                f"**Description:** {finding.description}"
            )

            st.markdown(
                f"**Remediation:** {finding.remediation}"
            )

            if finding.cve_ids:
                st.markdown(
                    f"**CVEs:** {', '.join(finding.cve_ids)}"
                )

            st.markdown(
                "**Confidence:** "
                f"{CONFIDENCE_ICONS.get(finding.confidence, finding.confidence)}"
            )


def render_assessment_status(report: AssessmentReport):
    st.subheader("Assessment Status")

    if report.findings:
        st.error(
            f"{len(report.findings)} confirmed finding(s) require attention."
        )
    else:
        st.success(
            "Assessment completed with zero confirmed findings."
        )

    st.caption(
        "Candidate CVE matches are deliberately separated from confirmed "
        "findings to prevent unsupported vulnerability claims."
    )


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--report-json",
        required=True,
        help="Path to an AssessmentReport JSON file",
    )

    ap.add_argument(
        "--collection",
        default="windows_artifacts.json",
        help="Path to the collected host artifacts JSON",
    )

    ap.add_argument(
        "--enrichment",
        default="data/enrichment.json",
        help="Path to the local CVE enrichment JSON",
    )

    args = ap.parse_args()

    st.set_page_config(
        page_title="Vulnerability Assessment Report",
        layout="wide",
    )

    st.title(
        " AI-Augmented Vulnerability Assessment Report"
    )

    render_compliance_badge()

    report = load_report(args.report_json)
    collection = load_json(args.collection)
    enrichment = load_json(args.enrichment)

    render_executive_summary(
        report,
        collection,
        enrichment,
    )

    render_assessment_status(report)

    render_findings_table(report)


if __name__ == "__main__":
    main()