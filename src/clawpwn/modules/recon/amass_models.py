"""Data models for OWASP Amass subdomain enumeration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AmassConfig:
    """Configuration for an Amass subdomain enumeration run."""

    mode: str = "passive"
    timeout: int = 300
    verbose: bool = False
    max_dns_queries: int = 0


@dataclass
class SubdomainResult:
    """A single discovered subdomain."""

    name: str
    domain: str
    addresses: list[str] = field(default_factory=list)
    tag: str = ""
    sources: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
