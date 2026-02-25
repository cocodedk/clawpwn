"""Vulnerability database integration for ClawPwn."""

from .client import VulnDBClient
from .models import CVEInfo, ExploitInfo
from .service import VulnDB, quick_research

__all__ = [
    "CVEInfo",
    "ExploitInfo",
    "VulnDB",
    "VulnDBClient",
    "quick_research",
]
