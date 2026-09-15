"""Deterministic Excel and Word report generation for PQC Recon V2."""

from __future__ import annotations

from io import BytesIO
from typing import Any

import pandas as pd
from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from openpyxl.styles import Alignment, Font, PatternFill


INK = "192C36"
TEAL = "087F73"
PALE = "E7F3F1"
MUTED = "5D6C74"
RED = "B74D46"


def _frame(rows: list[dict[str, Any]], columns: list[str] | None = None) -> pd.DataFrame:
    frame = pd.DataFrame(rows)
    if columns:
        for column in columns:
            if column not in frame:
                frame[column] = ""
        frame = frame[columns]
    return frame


def build_excel(result: dict[str, Any]) -> BytesIO:
    meta = result.get("meta", {})
    summary = result.get("summary", {})
    overview_rows = [{"Field": key.replace("_", " ").title(), "Value": value} for key, value in {**meta, **summary}.items()]
    asset_rows = [{key: value for key, value in row.items() if key != "Ports"} for row in result.get("asset_rows", [])]
    sheets = {
        "Overview": _frame(overview_rows),
        "Priority_Findings": _frame(result.get("findings", [])),
        "Assets": _frame(asset_rows),
        "Vulnerabilities": _frame(result.get("cve_rows", [])),
        "TLS_PQC": _frame(result.get("tls_rows", [])),
        "Source_Health": _frame(result.get("source_health", [])),
        "Rejected_Targets": _frame(result.get("rejected_targets", [])),
    }

    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for sheet_name, frame in sheets.items():
            frame.to_excel(writer, index=False, sheet_name=sheet_name[:31])
            sheet = writer.book[sheet_name[:31]]
            sheet.freeze_panes = "A2"
            sheet.auto_filter.ref = sheet.dimensions
            for cell in sheet[1]:
                cell.fill = PatternFill("solid", fgColor=INK)
                cell.font = Font(color="FFFFFF", bold=True)
                cell.alignment = Alignment(vertical="center")
            for column in sheet.columns:
                values = [str(cell.value or "") for cell in column[:100]]
                width = min(max(max(map(len, values), default=8) + 2, 10), 48)
                sheet.column_dimensions[column[0].column_letter].width = width
                for cell in column:
                    cell.alignment = Alignment(vertical="top", wrap_text=True)
    output.seek(0)
    return output


def _shade(cell, fill: str) -> None:
    properties = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), fill)
    properties.append(shading)


def _set_table_borders(table, color: str = "D9D9D9") -> None:
    properties = table._tbl.tblPr
    existing = properties.find(qn("w:tblBorders"))
    if existing is not None:
        properties.remove(existing)
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        border = OxmlElement(f"w:{edge}")
        border.set(qn("w:val"), "single")
        border.set(qn("w:sz"), "4")
        border.set(qn("w:space"), "0")
        border.set(qn("w:color"), color)
        borders.append(border)
    properties.append(borders)


def _set_cell_text(cell, value: Any, *, bold: bool = False, color: str = INK, size: int = 8) -> None:
    cell.text = ""
    paragraph = cell.paragraphs[0]
    run = paragraph.add_run(str(value if value not in (None, "") else "-"))
    run.bold = bold
    run.font.name = "Aptos"
    run.font.size = Pt(size)
    run.font.color.rgb = RGBColor.from_string(color)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP


def _add_table(document: Document, rows: list[dict[str, Any]], columns: list[str], limit: int = 30) -> None:
    if not rows:
        document.add_paragraph("No observations recorded.", style="Intense Quote")
        return
    table = document.add_table(rows=1, cols=len(columns))
    table.style = "Table Grid"
    _set_table_borders(table)
    for index, column in enumerate(columns):
        _set_cell_text(table.rows[0].cells[index], column, bold=True, color="FFFFFF")
        _shade(table.rows[0].cells[index], INK)
    for row in rows[:limit]:
        cells = table.add_row().cells
        for index, column in enumerate(columns):
            _set_cell_text(cells[index], row.get(column, ""))
            if len(table.rows) % 2 == 0:
                _shade(cells[index], "F4F7F8")
    if len(rows) > limit:
        note = document.add_paragraph(f"Showing {limit} of {len(rows)} records. See the Excel evidence package for all rows.")
        note.style = "Caption"


def _heading(document: Document, text: str, level: int = 1) -> None:
    heading = document.add_heading(text, level=level)
    heading.paragraph_format.space_before = Pt(10)
    heading.paragraph_format.space_after = Pt(5)


def _remove_style_border(style) -> None:
    paragraph_properties = style.element.get_or_add_pPr()
    border = paragraph_properties.find(qn("w:pBdr"))
    if border is not None:
        paragraph_properties.remove(border)


def build_docx(result: dict[str, Any]) -> BytesIO:
    meta = result.get("meta", {})
    summary = result.get("summary", {})
    findings = result.get("findings", [])
    assets = result.get("asset_rows", [])
    cves = result.get("cve_rows", [])
    tls_rows = result.get("tls_rows", [])

    document = Document()
    section = document.sections[0]
    section.top_margin = Inches(0.65)
    section.bottom_margin = Inches(0.65)
    section.left_margin = Inches(0.65)
    section.right_margin = Inches(0.65)

    styles = document.styles
    styles["Normal"].font.name = "Aptos"
    styles["Normal"].font.size = Pt(10.5)
    styles["Title"].font.name = "Aptos Display"
    styles["Title"].font.size = Pt(26)
    styles["Title"].font.color.rgb = RGBColor(0, 0, 0)
    _remove_style_border(styles["Title"])
    styles["Subtitle"].font.name = "Aptos"
    styles["Subtitle"].font.color.rgb = RGBColor(0, 0, 0)
    styles["Subtitle"].font.italic = False
    _remove_style_border(styles["Subtitle"])
    for style_name in ("Heading 1", "Heading 2"):
        styles[style_name].font.name = "Aptos Display"
        styles[style_name].font.color.rgb = RGBColor(0, 0, 0)

    title = document.add_paragraph(style="Title")
    title.add_run("External Attack Surface and PQC Readiness")
    subtitle = document.add_paragraph("Presales Reconnaissance and Customer Validation Report")
    subtitle.style = "Subtitle"

    identity = document.add_table(rows=4, cols=2)
    identity.style = "Table Grid"
    _set_table_borders(identity)
    identity_rows = (
        ("Customer / account", meta.get("customer", "Internal or sanitized assessment")),
        ("Engagement", meta.get("engagement", "External reconnaissance")),
        ("Assessment time", meta.get("completed_at", "")),
        ("Scope", meta.get("scope", "Authorized targets supplied for this run")),
    )
    for row, values in zip(identity.rows, identity_rows):
        _set_cell_text(row.cells[0], values[0], bold=True, color=TEAL, size=9)
        _set_cell_text(row.cells[1], values[1], size=9)
        _shade(row.cells[0], PALE)

    notice = document.add_paragraph()
    notice.paragraph_format.space_before = Pt(8)
    notice.paragraph_format.space_after = Pt(8)
    notice_lead = notice.add_run("Interpretation boundary: ")
    notice_lead.bold = True
    notice.add_run(
        "External telemetry is an observation at a point in time. CVE associations, ownership, service exposure, "
        "and business impact require customer validation before remediation or solution decisions."
    )

    _heading(document, "Executive snapshot")
    metrics = [
        ("Public IPs observed", summary.get("public_ips", 0)),
        ("Reported open services", summary.get("open_ports", 0)),
        ("CVE associations", summary.get("cve_associations", 0)),
        ("CISA KEV matches", summary.get("kev_matches", 0)),
        ("TLS endpoints assessed", summary.get("tls_endpoints", 0)),
        ("Classical-only key exchange", summary.get("classical_only_kex", 0)),
        ("PQC-protected key exchange", summary.get("pqc_protected_kex", 0)),
        ("Unknown key exchange", summary.get("unknown_kex", 0)),
    ]
    metric_table = document.add_table(rows=2, cols=4)
    metric_table.style = "Table Grid"
    _set_table_borders(metric_table)
    for index, (label, value) in enumerate(metrics):
        cell = metric_table.rows[index // 4].cells[index % 4]
        cell.text = ""
        paragraph = cell.paragraphs[0]
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        score_run = paragraph.add_run(f"{value}\n")
        score_run.bold = True
        score_run.font.size = Pt(18)
        score_run.font.color.rgb = RGBColor.from_string(TEAL)
        label_run = paragraph.add_run(label)
        label_run.font.size = Pt(7)
        label_run.font.color.rgb = RGBColor.from_string(MUTED)
        _shade(cell, PALE)

    _heading(document, "Prioritized findings")
    if not findings:
        document.add_paragraph("No prioritized findings were generated from the available observations.")
    for finding in findings[:20]:
        finding_title = document.add_paragraph()
        finding_title.paragraph_format.space_before = Pt(7)
        finding_title.paragraph_format.space_after = Pt(3)
        lead = finding_title.add_run(
            f"{finding.get('Finding ID', '')}  {finding.get('Priority', 'Review')}  {finding.get('Domain', '')}"
        )
        lead.bold = True
        lead.font.size = Pt(11)
        document.add_paragraph(f"Asset: {finding.get('Asset', '-')}")
        document.add_paragraph(str(finding.get("Observation", "")))
        for label, key in (
            ("Evidence", "Evidence"),
            ("Confidence", "Confidence"),
            ("Why it matters", "Why it matters"),
            ("Customer validation", "Customer validation"),
            ("Suggested next step", "Suggested next step"),
        ):
            paragraph = document.add_paragraph()
            paragraph.paragraph_format.space_after = Pt(2)
            label_run = paragraph.add_run(f"{label}: ")
            label_run.bold = True
            paragraph.add_run(str(finding.get(key, "-") or "-"))
    if len(findings) > 20:
        document.add_paragraph(f"Showing 20 of {len(findings)} findings. See the Excel evidence package for all records.")

    _heading(document, "External asset inventory")
    asset_report_rows = [{**row, "Open TCP ports": row.get("Open TCP ports", "")} for row in assets]
    _add_table(document, asset_report_rows, ["IP", "Hostnames", "Discovery sources", "Open TCP ports", "InternetDB status"], limit=40)

    _heading(document, "Vulnerability observations")
    _add_table(document, cves, ["IP", "CVE ID", "CVSS", "CISA KEV", "EPSS", "Technical Priority", "Title"], limit=35)

    _heading(document, "TLS and post-quantum readiness")
    tls_report_rows = []
    for row in tls_rows:
        tls_report_rows.append({
            "Endpoint": f"{row.get('hostname') or row.get('ip')}:{row.get('port', '')}",
            "TLS": row.get("tls_version", ""),
            "Certificate expiry": row.get("not_after", ""),
            "Public key": f"{row.get('public_key_algorithm', '')} {row.get('public_key_size') or ''}".strip(),
            "KEX verdict": row.get("key_exchange_pqc", ""),
            "Risk": row.get("risk", ""),
            "Findings": row.get("findings", ""),
        })
    _add_table(document, tls_report_rows, ["Endpoint", "TLS", "Certificate expiry", "Public key", "KEX verdict", "Risk", "Findings"], limit=35)

    _heading(document, "Interpretation and limitations")
    limitations = (
        "Shodan InternetDB and DNS sources may be incomplete or stale; absence of a reported CVE is not evidence of security.\n"
        "CVE-to-asset associations require authenticated product and version validation.\n"
        "A normal TLS handshake does not test every protocol version or cipher supported by a service.\n"
        "CA/Browser Forum validity limits apply to publicly trusted subscriber certificates; trust applicability requires validation.\n"
        "NIST IR 8547 transition dates are sourced from an Initial Public Draft and must be labeled accordingly.\n"
        "PQC urgency depends on data sensitivity, confidentiality lifetime, architecture, and migration dependencies."
    )
    for line in limitations.splitlines():
        document.add_paragraph(line, style="List Bullet")

    _heading(document, "Data-source health")
    _add_table(document, result.get("source_health", []), ["Source", "Status", "Detail"], limit=20)

    output = BytesIO()
    document.save(output)
    output.seek(0)
    return output
