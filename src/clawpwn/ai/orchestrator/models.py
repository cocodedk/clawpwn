"""Core enums and state models for AI orchestrator."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from clawpwn.modules.exploit import ExploitResult
from clawpwn.modules.scanner import ScanResult


class Phase(Enum):
    """Kill chain phases."""

    NOT_STARTED = "Not Started"
    INITIALIZED = "Initialized"
    RECONNAISSANCE = "Reconnaissance"
    ENUMERATION = "Enumeration"
    VULNERABILITY_RESEARCH = "Vulnerability Research"
    EXPLOITATION = "Exploitation"
    POST_EXPLOITATION = "Post-Exploitation"
    LATERAL_MOVEMENT = "Lateral Movement"
    PERSISTENCE = "Persistence"
    EXFILTRATION = "Exfiltration"
    REPORTING = "Reporting"


class ActionType(Enum):
    """Types of actions AI can decide to take."""

    SCAN = "scan"
    EXPLOIT = "exploit"
    ENUMERATE = "enumerate"
    RESEARCH = "research"
    WAIT = "wait"
    STOP = "stop"
    ASK_USER = "ask_user"


@dataclass
class AIAction:
    """Represents an AI-decided action."""

    action_type: ActionType
    reason: str
    target: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    risk_level: str = "low"


@dataclass
class KillChainState:
    """Tracks the current state of the kill chain."""

    current_phase: Phase
    target: str
    findings: list[ScanResult] = field(default_factory=list)
    exploited: list[ExploitResult] = field(default_factory=list)
    hosts_discovered: list[str] = field(default_factory=list)
    services_discovered: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    auto_mode: bool = False
