"""Privilege detection for network scanning tools."""

import os
import shutil
import subprocess
from pathlib import Path


def _resolve_binary(binary: str) -> str | None:
    """
    Resolve binary path, preferring ~/.cargo/bin for rustscan.

    Snap binaries cannot have setcap applied, so we prefer cargo-installed
    binaries when available.
    """
    # Prefer cargo-installed rustscan (can have setcap, snap cannot)
    if binary == "rustscan":
        cargo_path = Path.home() / ".cargo" / "bin" / "rustscan"
        if cargo_path.is_file() and os.access(cargo_path, os.X_OK):
            return str(cargo_path)
    # Check Go binary locations for naabu
    if binary == "naabu":
        for go_dir in [Path.home() / ".local" / "bin", Path.home() / "go" / "bin"]:
            go_path = go_dir / "naabu"
            if go_path.is_file() and os.access(go_path, os.X_OK):
                return str(go_path)
    return shutil.which(binary)


def has_cap_net_raw(binary: str) -> bool:
    """Check if a binary has cap_net_raw capability."""
    bin_path = _resolve_binary(binary)
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
    bin_path = _resolve_binary(scanner) or shutil.which(scanner) or f"/usr/bin/{scanner}"
    clawpwn_path = shutil.which("clawpwn") or str(Path.home() / ".local" / "bin" / "clawpwn")
    return f"""
Scanner '{scanner}' requires elevated privileges for raw network access.

Options:
  1. Set capabilities (recommended, one-time):
     sudo setcap cap_net_raw+ep {bin_path}

  2. Run with sudo (use full path since ~/.local/bin may not be in root's PATH):
     sudo {clawpwn_path} scan ...

  3. Re-run install.sh and choose 'y' when asked about capabilities.

To remove capabilities later:
     sudo setcap -r {bin_path}
"""
