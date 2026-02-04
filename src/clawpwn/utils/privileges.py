"""Privilege detection for network scanning tools."""

import os
import shutil
import subprocess


def has_cap_net_raw(binary: str) -> bool:
    """Check if a binary has cap_net_raw capability."""
    bin_path = shutil.which(binary)
    if not bin_path:
        return False
    try:
        result = subprocess.run(
            ["getcap", bin_path],
            capture_output=True,
            text=True,
        )
        return "cap_net_raw" in result.stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def can_raw_scan(scanner: str) -> bool:
    """Check if we can run raw network scans with the given scanner."""
    return is_root() or has_cap_net_raw(scanner)


def get_privilege_help(scanner: str) -> str:
    """Return helpful message for fixing privileges."""
    bin_path = shutil.which(scanner) or f"/usr/bin/{scanner}"
    return f"""
Scanner '{scanner}' requires elevated privileges for raw network access.

Options:
  1. Set capabilities (recommended, one-time):
     sudo setcap cap_net_raw+ep {bin_path}

  2. Run with sudo:
     sudo clawpwn scan ...

  3. Re-run install.sh and choose 'y' when asked about capabilities.

To remove capabilities later:
     sudo setcap -r {bin_path}
"""
