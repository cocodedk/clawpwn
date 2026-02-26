"""Run OWASP Amass for subdomain enumeration."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from clawpwn.modules.webscan.runtime import resolve_binary, run_command

from .amass_models import AmassConfig, SubdomainResult


async def run_amass(
    domain: str,
    config: AmassConfig | None = None,
) -> list[SubdomainResult]:
    """Enumerate subdomains for *domain* using OWASP Amass.

    Returns a deduplicated list of :class:`SubdomainResult` entries.
    Raises :class:`RuntimeError` when the ``amass`` binary is not found.
    """
    if config is None:
        config = AmassConfig()

    binary = resolve_binary("amass")
    if binary is None:
        raise RuntimeError(
            "amass binary not found. Install via: "
            "apt install amass  OR  go install github.com/owasp-amass/amass/v4/...@master"
        )

    with tempfile.TemporaryDirectory(prefix="clawpwn-amass-") as tmpdir:
        out_file = Path(tmpdir) / "amass.jsonl"
        command = _build_command(binary, domain, config, out_file)

        timeout_secs = max(60.0, config.timeout + 30.0) if config.timeout else None
        await run_command(
            command,
            timeout=timeout_secs,
            allowed_exit_codes=(0, 1),
            verbose=config.verbose,
        )
        return _parse_output(out_file)


def _build_command(
    binary: str,
    domain: str,
    config: AmassConfig,
    out_file: Path,
) -> list[str]:
    """Assemble the amass CLI invocation."""
    cmd = [binary, "enum", "-d", domain, "-json", str(out_file)]

    if config.mode == "passive":
        cmd.append("-passive")

    if config.timeout:
        timeout_minutes = max(1, int(config.timeout // 60))
        cmd.extend(["-timeout", str(timeout_minutes)])

    if config.max_dns_queries > 0:
        cmd.extend(["-max-dns-queries", str(config.max_dns_queries)])

    return cmd


def _parse_output(out_file: Path) -> list[SubdomainResult]:
    """Read JSONL output and return deduplicated subdomain results."""
    if not out_file.exists():
        return []

    seen: set[str] = set()
    results: list[SubdomainResult] = []

    for line in out_file.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry:
            continue
        try:
            obj = json.loads(entry)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue

        name = obj.get("name", "").strip()
        if not name or name in seen:
            continue
        seen.add(name)

        addresses = [addr.get("ip", "") for addr in obj.get("addresses", []) if addr.get("ip")]

        results.append(
            SubdomainResult(
                name=name,
                domain=obj.get("domain", ""),
                addresses=addresses,
                tag=obj.get("tag", ""),
                sources=obj.get("sources", []),
                raw=obj,
            )
        )

    return results
