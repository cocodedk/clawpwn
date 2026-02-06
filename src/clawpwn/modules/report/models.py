"""Report data models."""

from dataclasses import dataclass


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    format: str = "html"
    include_evidence: bool = True
    include_remediation: bool = True
    include_technical_details: bool = True
    executive_summary: bool = True
    risk_rating: str = "cvss"
