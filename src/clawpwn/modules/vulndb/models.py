"""Data models for vulnerability intelligence."""

from dataclasses import dataclass, field


@dataclass
class ExploitInfo:
    """Represents a found exploit."""

    title: str
    source: str
    cve_id: str = ""
    edb_id: str = ""
    url: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    reliability: str = "unknown"
    verified: bool = False


@dataclass
class CVEInfo:
    """Represents CVE information."""

    cve_id: str
    description: str
    severity: str
    cvss_score: float = 0.0
    published_date: str = ""
    references: list[str] = field(default_factory=list)
    cwe_id: str = ""
