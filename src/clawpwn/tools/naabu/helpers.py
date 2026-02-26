"""Privilege and environment helpers for naabu scanner."""

import os
import subprocess


def parse_float_env(name: str, default: float | None = 3600.0) -> float | None:
    """Parse optional float from environment; return default if unset or invalid."""
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    try:
        return float(val)
    except ValueError:
        return default


def is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def can_sudo_without_password(binary_path: str) -> bool:
    """Check if we can run a binary with sudo without password prompt."""
    if not binary_path or not os.path.isfile(binary_path):
        return False
    try:
        result = subprocess.run(
            ["sudo", "-n", binary_path, "--help"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
