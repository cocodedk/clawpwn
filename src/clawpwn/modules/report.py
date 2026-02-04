"""Reporting module for ClawPwn.

Generates professional penetration testing reports in multiple formats:
- HTML: Rich, styled report with findings details
- PDF: Executive-ready document (via HTML -> PDF)
- JSON: Machine-readable format
- Markdown: GitHub-friendly format
"""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.config import get_project_db_path
from clawpwn.modules.session import SessionManager


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    format: str = "html"  # html, pdf, json, md
    include_evidence: bool = True
    include_remediation: bool = True
    include_technical_details: bool = True
    executive_summary: bool = True
    risk_rating: str = "cvss"  # cvss, custom


class ReportGenerator:
    """Generates penetration testing reports."""

    def __init__(self, project_dir: Path, llm_client: LLMClient | None = None):
        self.project_dir = project_dir
        db_path = get_project_db_path(project_dir)
        if db_path is None:
            raise ValueError("Project storage not found. Run 'clawpwn init' first.")
        self.db_path = db_path
        self.session = SessionManager(self.db_path)
        self._llm_owned = llm_client is None
        self.llm = llm_client or LLMClient(project_dir=project_dir)
        self.report_dir = project_dir / "report"
        self.report_dir.mkdir(exist_ok=True)

    def close(self) -> None:
        """Release resources; closes the LLM client if this generator created it."""
        if self._llm_owned and getattr(self, "llm", None) is not None:
            self.llm.close()

    def generate(self, config: ReportConfig | None = None) -> Path:
        """
        Generate a report based on configuration.

        Returns:
            Path to the generated report file
        """
        config = config or ReportConfig()

        # Get all project data
        state = self.session.get_state()
        if not state:
            raise ValueError("No project data available")

        # Gather findings
        from clawpwn.db.models import Finding

        project = self.session.get_project()
        if not project:
            raise ValueError("No project found in database")

        findings = self.session.session.query(Finding).filter_by(project_id=project.id).all()

        # Generate based on format
        if config.format == "html":
            return self._generate_html(state, findings, config)
        elif config.format == "json":
            return self._generate_json(state, findings, config)
        elif config.format == "md":
            return self._generate_markdown(state, findings, config)
        elif config.format == "pdf":
            return self._generate_pdf(state, findings, config)
        else:
            raise ValueError(f"Unsupported format: {config.format}")

    def _generate_html(self, state, findings: list[Any], config: ReportConfig) -> Path:
        """Generate an HTML report."""

        # Generate executive summary using AI
        exec_summary = ""
        if config.executive_summary:
            try:
                exec_summary = self._generate_executive_summary(state, findings)
            except Exception:
                exec_summary = "Executive summary unavailable."

        # Build HTML
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {state.target or "Unknown"}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header .meta {{
            opacity: 0.9;
            margin-top: 10px;
        }}
        .summary-box {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        .stat-card.critical {{ border-left-color: #dc3545; }}
        .stat-card.high {{ border-left-color: #fd7e14; }}
        .stat-card.medium {{ border-left-color: #ffc107; }}
        .stat-card.low {{ border-left-color: #28a745; }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
        }}
        .finding {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            border-left: 4px solid #ddd;
        }}
        .finding.critical {{ border-left-color: #dc3545; background: #fdf2f2; }}
        .finding.high {{ border-left-color: #fd7e14; background: #fff8f0; }}
        .finding.medium {{ border-left-color: #ffc107; background: #fffdf5; }}
        .finding.low {{ border-left-color: #28a745; background: #f0fff4; }}
        .finding h3 {{
            margin-top: 0;
            color: #333;
        }}
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity.critical {{ background: #dc3545; color: white; }}
        .severity.high {{ background: #fd7e14; color: white; }}
        .severity.medium {{ background: #ffc107; color: black; }}
        .severity.low {{ background: #28a745; color: white; }}
        .severity.info {{ background: #17a2b8; color: white; }}
        .field {{
            margin: 15px 0;
        }}
        .field-label {{
            font-weight: bold;
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .field-value {{
            margin-top: 5px;
            color: #333;
        }}
        .evidence {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        h2 {{
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 40px;
        }}
        .toc {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .toc ul {{
            list-style: none;
            padding-left: 0;
        }}
        .toc li {{
            padding: 5px 0;
        }}
        .toc a {{
            color: #667eea;
            text-decoration: none;
        }}
        .toc a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Penetration Test Report</h1>
        <div class="meta">
            <strong>Target:</strong> {state.target or "N/A"}<br>
            <strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
            <strong>Phase:</strong> {state.current_phase}
        </div>
    </div>

    <div class="summary-box">
        <h2>Executive Summary</h2>
        <p>{exec_summary}</p>
    </div>

    <div class="stats">
        <div class="stat-card critical">
            <div class="stat-number">{state.critical_count}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card high">
            <div class="stat-number">{state.high_count}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card medium">
            <div class="stat-number">{state.findings_count - state.critical_count - state.high_count}</div>
            <div class="stat-label">Medium/Low</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(findings)}</div>
            <div class="stat-label">Total Findings</div>
        </div>
    </div>

    <h2>Table of Contents</h2>
    <div class="toc">
        <ul>
            <li><a href="#findings">Findings Summary</a></li>
            <li><a href="#detailed">Detailed Findings</a></li>
            <li><a href="#technical">Technical Details</a></li>
            <li><a href="#methodology">Methodology</a></li>
        </ul>
    </div>

    <h2 id="findings">Findings Summary</h2>
"""

        # Add findings grouped by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        by_severity = {s: [] for s in severity_order}

        for finding in findings:
            sev = finding.severity.lower()
            if sev in by_severity:
                by_severity[sev].append(finding)

        for severity in severity_order:
            if by_severity[severity]:
                html_content += f"<h3>{severity.upper()} ({len(by_severity[severity])})</h3>\n"
                for finding in by_severity[severity]:
                    html_content += self._render_finding_html(finding, config)

        if not findings:
            html_content += "<p>No findings recorded.</p>\n"

        # Close HTML
        html_content += f"""

    <h2 id="methodology">Methodology</h2>
    <div class="summary-box">
        <p>This penetration test followed industry-standard methodologies including:</p>
        <ul>
            <li>OWASP Testing Guide</li>
            <li>PTES (Penetration Testing Execution Standard)</li>
            <li>NIST SP 800-115</li>
        </ul>
        <p>Testing phases included: Reconnaissance, Enumeration, Vulnerability Assessment,
        Exploitation, Post-Exploitation, and Reporting.</p>
    </div>

    <div class="footer">
        <p>Generated by ClawPwn AI-Powered Penetration Testing Tool</p>
        <p>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
</body>
</html>
"""

        # Save file
        report_file = (
            self.report_dir / f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        report_file.write_text(html_content, encoding="utf-8")

        return report_file

    def _render_finding_html(self, finding: Any, config: ReportConfig) -> str:
        """Render a single finding as HTML."""
        severity_class = finding.severity.lower()

        html = f"""
    <div class="finding {severity_class}" id="finding-{finding.id}">
        <h3>{finding.title}</h3>
        <span class="severity {severity_class}">{finding.severity.upper()}</span>

        <div class="field">
            <div class="field-label">Type</div>
            <div class="field-value">{finding.attack_type}</div>
        </div>

        <div class="field">
            <div class="field-label">Description</div>
            <div class="field-value">{finding.description or "No description available"}</div>
        </div>
"""

        if config.include_evidence and finding.evidence:
            html += f"""
        <div class="field">
            <div class="field-label">Evidence</div>
            <div class="evidence">{finding.evidence}</div>
        </div>
"""

        if config.include_remediation and finding.remediation:
            html += f"""
        <div class="field">
            <div class="field-label">Remediation</div>
            <div class="field-value">{finding.remediation}</div>
        </div>
"""

        html += "    </div>\n"
        return html

    def _generate_json(self, state, findings: list[Any], config: ReportConfig) -> Path:
        """Generate a JSON report."""

        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "ClawPwn",
                "version": "0.1.0",
            },
            "project": {
                "path": state.project_path,
                "target": state.target,
                "current_phase": state.current_phase,
                "created_at": state.created_at.isoformat()
                if hasattr(state.created_at, "isoformat")
                else str(state.created_at),
            },
            "summary": {
                "total_findings": len(findings),
                "critical": state.critical_count,
                "high": state.high_count,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "attack_type": f.attack_type,
                    "description": f.description,
                    "evidence": f.evidence if config.include_evidence else None,
                    "remediation": f.remediation if config.include_remediation else None,
                    "created_at": f.created_at.isoformat()
                    if hasattr(f.created_at, "isoformat")
                    else str(f.created_at),
                }
                for f in findings
            ],
        }

        report_file = (
            self.report_dir / f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        report_file.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        return report_file

    def _generate_markdown(self, state, findings: list[Any], config: ReportConfig) -> Path:
        """Generate a Markdown report."""

        # Generate executive summary
        exec_summary = ""
        if config.executive_summary:
            try:
                exec_summary = self._generate_executive_summary(state, findings)
            except Exception:
                exec_summary = "Executive summary unavailable."

        md_content = f"""# 🔒 Penetration Test Report

**Target:** {state.target or "N/A"}
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Current Phase:** {state.current_phase}

---

## Executive Summary

{exec_summary}

## Findings Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {state.critical_count} |
| 🟠 High | {state.high_count} |
| 🟡 Medium/Low | {state.findings_count - state.critical_count - state.high_count} |
| **Total** | **{len(findings)}** |

## Detailed Findings

"""

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        by_severity = {s: [] for s in severity_order}

        for finding in findings:
            sev = finding.severity.lower()
            if sev in by_severity:
                by_severity[sev].append(finding)

        for severity in severity_order:
            if by_severity[severity]:
                md_content += f"\n### {severity.upper()} ({len(by_severity[severity])})\n\n"
                for finding in by_severity[severity]:
                    md_content += self._render_finding_markdown(finding, config)

        if not findings:
            md_content += "*No findings recorded.*\n"

        md_content += f"""

## Methodology

This penetration test followed industry-standard methodologies:

- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST SP 800-115

Testing phases included: Reconnaissance, Enumeration, Vulnerability Assessment,
Exploitation, Post-Exploitation, and Reporting.

---

*Generated by ClawPwn AI-Powered Penetration Testing Tool*
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

        report_file = (
            self.report_dir / f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        )
        report_file.write_text(md_content, encoding="utf-8")

        return report_file

    def _render_finding_markdown(self, finding: Any, config: ReportConfig) -> str:
        """Render a single finding as Markdown."""
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }.get(finding.severity.lower(), "⚪")

        md = f"""#### {severity_emoji} {finding.title}

**Severity:** {finding.severity.upper()}
**Type:** {finding.attack_type}

**Description:**
{finding.description or "No description available."}

"""

        if config.include_evidence and finding.evidence:
            md += f"""**Evidence:**
```
{finding.evidence}
```

"""

        if config.include_remediation and finding.remediation:
            md += f"""**Remediation:**
{finding.remediation}

"""

        md += "---\n\n"
        return md

    def _generate_pdf(self, state, findings: list[Any], config: ReportConfig) -> Path:
        """Generate a PDF report (via HTML conversion)."""
        # First generate HTML
        html_file = self._generate_html(state, findings, config)

        # For now, return HTML and note PDF generation requires additional setup
        # In production, you'd use weasyprint, pdfkit, or similar
        pdf_file = (
            self.report_dir / f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

        # Create a note about PDF generation
        note = f"""PDF Report Generation

The HTML report has been generated: {html_file.name}

To convert to PDF, you can use:
- Chrome: Open HTML and print to PDF
- wkhtmltopdf: wkhtmltopdf {html_file.name} {pdf_file.name}
- WeasyPrint: python -m weasyprint {html_file.name} {pdf_file.name}

For automatic PDF generation, install weasyprint:
  pip install weasyprint
"""

        note_file = pdf_file.with_suffix(".txt")
        note_file.write_text(note)

        return html_file  # Return HTML for now

    def _generate_executive_summary(self, state, findings: list[Any]) -> str:
        """Generate an executive summary using AI."""
        system_prompt = """You are a senior security consultant writing an executive summary for a penetration test report.
Write 2-3 paragraphs summarizing the key findings and business impact. Be professional and concise. Focus on risk and business impact, not technical details."""

        findings_summary = f"""
Target: {state.target}
Total Findings: {len(findings)}
Critical: {state.critical_count}
High: {state.high_count}
Phase: {state.current_phase}
"""

        try:
            return self.llm.chat(findings_summary, system_prompt)
        except Exception:
            # Fallback if AI fails
            return f"""A penetration test was conducted against {state.target or "the target"}.
{len(findings)} security issues were identified, including {state.critical_count} critical
and {state.high_count} high severity findings. Immediate attention is recommended for critical
and high severity issues to reduce organizational risk."""


# Convenience functions
def generate_report(project_dir: Path, format: str = "html", include_evidence: bool = True) -> Path:
    """Generate a report for a project."""
    generator = ReportGenerator(project_dir)
    try:
        config = ReportConfig(format=format, include_evidence=include_evidence)
        return generator.generate(config)
    finally:
        generator.close()
