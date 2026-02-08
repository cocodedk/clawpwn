"""Data models for web scanner plugins and orchestration."""

from dataclasses import dataclass, field
from typing import Any

from clawpwn.modules.scanner.models import ScanResult


@dataclass
class WebScanConfig:
    """Shared runtime settings for web scanner plugins."""

    depth: str = "normal"
    timeout: float | None = None
    follow_redirects: bool = True
    concurrency: int = 10
    verbose: bool = False
    scan_types: list[str] = field(default_factory=lambda: ["all"])


@dataclass
class WebScanFinding:
    """Normalized finding returned by a web scanner plugin."""

    tool: str
    title: str
    severity: str
    description: str
    url: str
    attack_type: str = "web"
    evidence: str = ""
    remediation: str = ""
    confidence: str = "medium"
    raw: dict[str, Any] = field(default_factory=dict)

    def to_scan_result(self) -> ScanResult:
        """Convert plugin finding to the existing scanner model."""
        return ScanResult(
            title=self.title,
            severity=self.severity,
            description=self.description,
            url=self.url,
            attack_type=self.attack_type,
            evidence=self.evidence,
            remediation=self.remediation,
            confidence=self.confidence,
        )

    @classmethod
    def from_scan_result(cls, finding: ScanResult, tool: str) -> "WebScanFinding":
        """Convert existing scanner findings to a normalized web finding."""
        return cls(
            tool=tool,
            title=finding.title,
            severity=finding.severity,
            description=finding.description,
            url=finding.url,
            attack_type=finding.attack_type,
            evidence=finding.evidence,
            remediation=finding.remediation,
            confidence=finding.confidence,
        )


@dataclass
class WebScanError:
    """A plugin runtime error captured during orchestration."""

    tool: str
    message: str
