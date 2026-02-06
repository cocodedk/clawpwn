"""Data models for scanner findings and configuration."""

from dataclasses import dataclass, field


@dataclass
class ScanResult:
    """Represents a scan finding."""

    title: str
    severity: str
    description: str
    url: str
    attack_type: str
    evidence: str = ""
    remediation: str = ""
    confidence: str = "medium"


@dataclass
class ScanConfig:
    """Configuration for a scan."""

    target: str
    scan_types: list[str] = field(default_factory=lambda: ["all"])
    depth: str = "normal"
    threads: int = 10
    timeout: float = 30.0
    follow_redirects: bool = True
