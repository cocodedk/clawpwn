"""Privilege checking utilities for nmap."""

import os
import shutil
import subprocess
import sys


def _is_root() -> bool:
    """Return True if running as root (Unix) or elevated admin (Windows)."""
    if sys.platform == "win32":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _can_sudo_without_password(binary: str) -> bool:
    """Check if we can run a binary with sudo without password prompt."""
    bin_path = shutil.which(binary)
    if not bin_path:
        return False
    try:
        result = subprocess.run(
            ["sudo", "-n", bin_path, "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _needs_sudo(binary: str) -> bool:
    """Check if we need sudo to run privileged scans."""
    return not _is_root() and _can_sudo_without_password(binary)
