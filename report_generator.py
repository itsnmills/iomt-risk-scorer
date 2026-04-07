"""
IoMT Risk Assessment Report Generator
======================================
Generates a professional PDF risk assessment report using ReportLab.

Author: Noah Mills
"""

import io
from datetime import datetime
from typing import List, Dict, Optional

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import VerticalBarChart

from scorer import get_risk_level, DEFAULT_WEIGHTS
from controls import get_recommendations, get_priority_color


# ── Colors ──────────────────────────────────────────────────────────

TEAL = colors.HexColor("#20808D")
DARK_BG = colors.HexColor("#0E1117")
CARD_BG = colors.HexColor("#1A1D23")
TEXT_WHITE = colors.HexColor("#FAFAFA")
CRITICAL_RED = colors.HexColor("#FF4B4B")
HIGH_ORANGE = colors.HexColor("#FF8C00")
MEDIUM_YELLOW = colors.HexColor("#FFD700")
LOW_TEAL = colors.HexColor("#20808D")
LIGHT_GRAY = colors.HexColor("#CCCCCC")
MID_GRAY = colors.HexColor("#888888")


def _risk_color(level: str) -> colors.HexColor:
    return {
        "Critical": CRITICAL_RED,
        "High": HIGH_ORANGE,
        "Medium": MEDIUM_YELLOW,
        "Low": LOW_TEAL,
    }.get(level, MID_GRAY)


# ── Styles ──────────────────────────────────────────────────────────

def _build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#555555"),
        spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        "SectionHead",
        parent=styles["Heading1"],
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#20808D"),
        spaceBefore=20,
        spaceAfter=10,
        borderColor=colors.HexColor("#20808D"),
        borderWidth=0,
        borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        "SubHead",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1a1a2e"),
        spaceBefore=12,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "BodyText2",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#333333"),
        spaceAfter=8,
        alignment=TA_JUSTIFY,
    ))
    styles.add(ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#888888"),
    ))
    styles.add(ParagraphStyle(
        "ControlTitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#1a1a2e"),
        fontName="Helvetica-Bold",
        spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        "ControlBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#444444"),
        spaceAfter=4,
        leftIndent=10,
    ))
    styles.add(ParagraphStyle(
        "Citation",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#20808D"),
        leftIndent=10,
        spaceAfter=8,
    ))

    return styles


# ── PDF Generator ───────────────────────────────────────────────────

def generate_report(
    df: pd.DataFrame,
    organization: str = "Hospital",
    assessor: str = "IoMT Risk Scorer",
) -> bytes:
    """
    Generate a complete PDF risk assessment report.

    Parameters
    ----------
    df : pd.DataFrame
        Scored device inventory (must include risk score columns).
    organization : str
        Name of the healthcare organization.
    assessor : str
        Name of the person/tool performing the assessment.

    Returns
    -------
    bytes
        PDF file content as bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )

    styles = _build_styles()
    story = []

    # ── Title Page ──────────────────────────────────────────────
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("IoMT Risk Assessment Report", styles["ReportTitle"]))
    story.append(HRFlowable(
        width="100%", thickness=2, color=TEAL, spaceAfter=12
    ))
    story.append(Paragraph(
        f"<b>Organization:</b> {organization}", styles["BodyText2"]
    ))
    story.append(Paragraph(
        f"<b>Assessment Date:</b> {datetime.now().strftime('%B %d, %Y')}", styles["BodyText2"]
    ))
    story.append(Paragraph(
        f"<b>Assessed By:</b> {assessor}", styles["BodyText2"]
    ))
    story.append(Paragraph(
        f"<b>Total Devices Assessed:</b> {len(df)}", styles["BodyText2"]
    ))
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        "This report was generated by the IoMT Risk Assessment Tool, a healthcare cybersecurity "
        "risk scoring system informed by NIST SP 800-30, NIST Cybersecurity Framework 2.0, "
        "FDA Premarket Cybersecurity Guidance (2023), HHS 405(d) HICP, and the "
        "HIPAA Security Rule (45 CFR §164.308-312).",
        styles["BodyText2"],
    ))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "<b>CONFIDENTIAL</b> — This document contains sensitive security assessment information "
        "and should be handled in accordance with the organization's information classification policy.",
        styles["SmallText"],
    ))
    story.append(PageBreak())

    # ── Executive Summary ───────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL, spaceAfter=10))

    total = len(df)
    if "total_score" in df.columns:
        avg_score = df["total_score"].mean()
        critical_count = len(df[df["risk_level"] == "Critical"])
        high_count = len(df[df["risk_level"] == "High"])
        medium_count = len(df[df["risk_level"] == "Medium"])
        low_count = len(df[df["risk_level"] == "Low"])
        max_score = df["total_score"].max()
        max_device = df.loc[df["total_score"].idxmax(), "Device Name"] if total > 0 else "N/A"
    else:
        avg_score = 0
        critical_count = high_count = medium_count = low_count = 0
        max_score = 0
        max_device = "N/A"

    summary_data = [
        ["Metric", "Value"],
        ["Total Devices Assessed", str(total)],
        ["Average Risk Score", f"{avg_score:.1f} / 100"],
        ["Critical Risk Devices", str(critical_count)],
        ["High Risk Devices", str(high_count)],
        ["Medium Risk Devices", str(medium_count)],
        ["Low Risk Devices", str(low_count)],
        ["Highest Risk Device", f"{max_device} ({max_score:.1f})"],
    ]

    t = Table(summary_data, colWidths=[3 * inch, 3.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TEAL),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.3 * inch))

    # Executive narrative
    if critical_count > 0:
        urgency = (
            f"<b>{critical_count} device(s)</b> scored in the <font color='#FF4B4B'>Critical</font> "
            f"risk range (75-100) and require immediate remediation action. "
        )
    else:
        urgency = "No devices scored in the Critical risk range. "

    story.append(Paragraph(
        f"This assessment evaluated {total} IoMT devices across the {organization} environment. "
        f"The average composite risk score is <b>{avg_score:.1f}</b> out of 100. {urgency}"
        f"A total of {critical_count + high_count} device(s) are rated Critical or High and "
        f"should be prioritized for remediation within the next 30-90 days.",
        styles["BodyText2"],
    ))
    story.append(PageBreak())

    # ── Methodology ─────────────────────────────────────────────
    story.append(Paragraph("2. Methodology", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL, spaceAfter=10))

    story.append(Paragraph(
        "The composite risk score (0-100) is calculated as a weighted sum of five sub-scores, "
        "each evaluating a different risk dimension:",
        styles["BodyText2"],
    ))

    weights = DEFAULT_WEIGHTS
    method_data = [
        ["Sub-Score", "Weight", "Factors Evaluated"],
        ["Exposure", f"{weights['exposure']:.0%}", "Network segment placement"],
        ["Vulnerability", f"{weights['vulnerability']:.0%}", "Patchability, vendor support, OS risk, scan recency"],
        ["Data Sensitivity", f"{weights['data_sensitivity']:.0%}", "PHI handling level"],
        ["Patient Safety", f"{weights['patient_safety']:.0%}", "FDA classification, device type criticality"],
        ["Authentication", f"{weights['authentication']:.0%}", "Authentication method, encryption posture"],
    ]

    t = Table(method_data, colWidths=[1.8 * inch, 1 * inch, 3.7 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TEAL),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph(
        "Risk levels are assigned as: <font color='#FF4B4B'><b>Critical</b></font> (75-100), "
        "<font color='#FF8C00'><b>High</b></font> (50-74), "
        "<font color='#DAA520'><b>Medium</b></font> (25-49), "
        "<font color='#20808D'><b>Low</b></font> (0-24).",
        styles["BodyText2"],
    ))

    story.append(Paragraph("Frameworks Referenced", styles["SubHead"]))
    frameworks = [
        "NIST SP 800-30 Rev. 1 — Guide for Conducting Risk Assessments",
        "NIST Cybersecurity Framework (CSF) 2.0",
        "FDA Premarket Cybersecurity Guidance (September 2023)",
        "HHS 405(d) Health Industry Cybersecurity Practices (HICP)",
        "HIPAA Security Rule — 45 CFR §164.308-312",
    ]
    for fw in frameworks:
        story.append(Paragraph(f"• {fw}", styles["BodyText2"]))

    story.append(PageBreak())

    # ── Device Inventory ────────────────────────────────────────
    story.append(Paragraph("3. Device Inventory", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL, spaceAfter=10))

    # Compact inventory table
    inv_cols = ["Device Name", "Device Type", "Network Segment", "total_score", "risk_level"]
    available_cols = [c for c in inv_cols if c in df.columns]

    if available_cols:
        header = ["Device Name", "Type", "Network", "Score", "Risk"]
        rows = [header]
        for _, row in df.sort_values("total_score", ascending=False).iterrows():
            rows.append([
                str(row.get("Device Name", ""))[:30],
                str(row.get("Device Type", ""))[:18],
                str(row.get("Network Segment", ""))[:16],
                f"{row.get('total_score', 0):.1f}",
                str(row.get("risk_level", "")),
            ])

        t = Table(rows, colWidths=[2.2 * inch, 1.3 * inch, 1.2 * inch, 0.8 * inch, 0.9 * inch])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), TEAL),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]

        # Color-code risk level cells
        for i in range(1, len(rows)):
            level = rows[i][4]
            bg = {
                "Critical": colors.HexColor("#FFE0E0"),
                "High": colors.HexColor("#FFF0D0"),
                "Medium": colors.HexColor("#FFFDE0"),
                "Low": colors.HexColor("#E0F5F0"),
            }.get(level, colors.white)
            style_cmds.append(("BACKGROUND", (4, i), (4, i), bg))

        t.setStyle(TableStyle(style_cmds))
        story.append(t)

    story.append(PageBreak())

    # ── Risk Findings & Recommendations ─────────────────────────
    story.append(Paragraph("4. Risk Findings & Recommendations", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL, spaceAfter=10))

    # Sort by risk score descending
    if "total_score" in df.columns:
        sorted_df = df.sort_values("total_score", ascending=False)
    else:
        sorted_df = df

    for idx, (_, row) in enumerate(sorted_df.iterrows()):
        device = row.to_dict()
        score = device.get("total_score", 0)
        level = device.get("risk_level", "Unknown")
        level_color = _risk_color(level)

        # Device header
        device_name = device.get("Device Name", f"Device {idx + 1}")
        story.append(Paragraph(
            f"<font color='{level_color.hexval()}'>[{level}]</font> "
            f"<b>{device_name}</b> — Score: {score:.1f}/100",
            styles["SubHead"],
        ))

        # Quick facts
        facts = (
            f"Type: {device.get('Device Type', 'N/A')} | "
            f"Network: {device.get('Network Segment', 'N/A')} | "
            f"FDA Class: {device.get('FDA Class', 'N/A')} | "
            f"PHI: {device.get('PHI Handling', 'N/A')} | "
            f"Auth: {device.get('Authentication', 'N/A')}"
        )
        story.append(Paragraph(facts, styles["SmallText"]))
        story.append(Spacer(1, 4))

        # Sub-scores
        sub_scores = [
            ("Exposure", device.get("exposure_score", 0)),
            ("Vulnerability", device.get("vulnerability_score", 0)),
            ("Data Sensitivity", device.get("data_sensitivity_score", 0)),
            ("Patient Safety", device.get("patient_safety_score", 0)),
            ("Authentication", device.get("authentication_score", 0)),
        ]
        sub_data = [["Sub-Score", "Value"]]
        for name, val in sub_scores:
            sub_data.append([name, f"{val:.1f}"])

        st = Table(sub_data, colWidths=[2 * inch, 1 * inch])
        st.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8E8E8")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(st)
        story.append(Spacer(1, 6))

        # Recommendations
        recs = get_recommendations(device)
        if recs:
            # Limit to top 5 per device to keep report manageable
            for rec in recs[:5]:
                p_color = get_priority_color(rec["priority"])
                story.append(Paragraph(
                    f"<font color='{p_color}'>■</font> "
                    f"<b>{rec['title']}</b> "
                    f"<font color='{p_color}'>[{rec['priority']}]</font>",
                    styles["ControlTitle"],
                ))
                story.append(Paragraph(rec["description"], styles["ControlBody"]))
                story.append(Paragraph(
                    f"{rec['nist_csf']} | {rec['hipaa']}",
                    styles["Citation"],
                ))

        story.append(Spacer(1, 12))

        # Page break every 3 devices to avoid overflow
        if (idx + 1) % 3 == 0 and idx < len(sorted_df) - 1:
            story.append(PageBreak())

    story.append(PageBreak())

    # ── Prioritized Remediation Plan ────────────────────────────
    story.append(Paragraph("5. Prioritized Remediation Plan", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL, spaceAfter=10))

    story.append(Paragraph(
        "The following remediation priorities are based on composite risk scores and "
        "patient safety impact. Address Critical items within 7-14 days, High within 30 days, "
        "Medium within 90 days, and Low during the next scheduled maintenance cycle.",
        styles["BodyText2"],
    ))

    priorities = [
        ("Critical", "Immediate (7-14 days)", CRITICAL_RED),
        ("High", "Near-term (30 days)", HIGH_ORANGE),
        ("Medium", "Planned (90 days)", MEDIUM_YELLOW),
        ("Low", "Maintenance cycle", LOW_TEAL),
    ]

    for level, timeline, color in priorities:
        level_devices = sorted_df[sorted_df["risk_level"] == level] if "risk_level" in sorted_df.columns else pd.DataFrame()
        if len(level_devices) == 0:
            continue

        story.append(Paragraph(
            f"<font color='{color.hexval()}'><b>{level}</b></font> — {timeline} "
            f"({len(level_devices)} device{'s' if len(level_devices) > 1 else ''})",
            styles["SubHead"],
        ))

        for _, dev in level_devices.iterrows():
            story.append(Paragraph(
                f"• <b>{dev.get('Device Name', 'Unknown')}</b> "
                f"(Score: {dev.get('total_score', 0):.1f}) — "
                f"{dev.get('Device Type', '')} on {dev.get('Network Segment', '')}",
                styles["BodyText2"],
            ))

    story.append(PageBreak())

    # ── Framework References ────────────────────────────────────
    story.append(Paragraph("6. Framework References", styles["SectionHead"]))
    story.append(HRFlowable(width="100%", thickness=1, color=TEAL, spaceAfter=10))

    refs = [
        (
            "NIST SP 800-30 Rev. 1",
            "Guide for Conducting Risk Assessments. Provides the foundational risk assessment "
            "methodology used in this tool's scoring approach.",
            "https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final",
        ),
        (
            "NIST Cybersecurity Framework 2.0",
            "Provides the control function taxonomy (Identify, Protect, Detect, Respond, Recover, Govern) "
            "used to categorize recommended controls.",
            "https://www.nist.gov/cyberframework",
        ),
        (
            "FDA Premarket Cybersecurity Guidance (2023)",
            "Informs patient safety scoring and FDA class-based risk tiering for medical devices.",
            "https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions",
        ),
        (
            "HHS 405(d) HICP",
            "Health Industry Cybersecurity Practices. Provides healthcare-specific cybersecurity "
            "practices that inform the recommended controls.",
            "https://405d.hhs.gov/",
        ),
        (
            "HIPAA Security Rule (45 CFR §164.308-312)",
            "Defines the administrative, physical, and technical safeguards required for "
            "electronic protected health information (ePHI).",
            "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
        ),
    ]

    for title, desc, url in refs:
        story.append(Paragraph(f"<b>{title}</b>", styles["SubHead"]))
        story.append(Paragraph(desc, styles["BodyText2"]))
        story.append(Paragraph(
            f"<font color='#20808D'>{url}</font>", styles["SmallText"]
        ))
        story.append(Spacer(1, 8))

    # ── Footer / Disclaimer ─────────────────────────────────────
    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=10))
    story.append(Paragraph(
        "This report is generated for informational purposes and should be reviewed by "
        "qualified cybersecurity and clinical engineering professionals before action. "
        "Risk scores are estimates based on the information provided and do not constitute "
        "a complete security audit.",
        styles["SmallText"],
    ))
    story.append(Paragraph(
        f"Generated by IoMT Risk Assessment Tool — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        styles["SmallText"],
    ))

    # Build the PDF
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
