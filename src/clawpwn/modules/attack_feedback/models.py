"""Models for attack-response feedback analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AttackSignal:
    """A normalized signal extracted from an attack response."""

    category: str  # hint | block
    key: str
    message: str


@dataclass(frozen=True, slots=True)
class AttackPolicyDecision:
    """Recommended next action based on current feedback signals."""

    action: str  # continue | continue_adjust | backoff | stop_and_replan
    reason: str
