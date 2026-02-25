"""Credential testing result models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CredTestResult:
    """Result of credential testing."""

    form_found: bool
    form_action: str
    credentials_tested: int
    valid_credentials: list[tuple[str, str]]
    details: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    block_signals: list[str] = field(default_factory=list)
    policy_action: str = "continue"
    stopped_early: bool = False
    error: str | None = None
