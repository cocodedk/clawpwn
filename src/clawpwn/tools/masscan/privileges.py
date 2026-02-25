"""Privilege checking for masscan."""

import os
import subprocess


def _is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def _can_sudo_without_password(binary_path: str) -> bool:
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
