"""Searchsploit plugin for local Exploit-DB correlation."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from urllib.parse import urlparse

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import CommandResult, resolve_binary, run_command

_IGNORE_HOST_LABELS = {"www", "com", "net", "org", "local", "lan", "internal"}


def _severity_from_title(title: str) -> str:
    lowered = title.lower()
    if any(token in lowered for token in ("remote code execution", "rce", "unauth")):
        return "high"
    if any(token in lowered for token in ("sql injection", "auth bypass", "traversal")):
        return "high"
    if any(token in lowered for token in ("xss", "csrf", "information disclosure")):
        return "medium"
    return "low"


def _extract_keywords(target: str) -> list[str]:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    keywords: list[str] = []
    seen: set[str] = set()

    hostname = (parsed.hostname or "").lower()
    for label in hostname.split("."):
        token = label.strip()
        if (
            not token
            or token in _IGNORE_HOST_LABELS
            or token.isdigit()
            or len(token) < 3
            or token in seen
        ):
            continue
        seen.add(token)
        keywords.append(token)

    path_tokens = re.split(r"[^a-zA-Z0-9]+", parsed.path.lower())
    for token in path_tokens:
        if (
            not token
            or token in _IGNORE_HOST_LABELS
            or token.isdigit()
            or len(token) < 3
            or token in seen
        ):
            continue
        seen.add(token)
        keywords.append(token)

    return keywords


def _searchsploit_rows(payload: dict[str, object]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        value = payload.get(key)
        if isinstance(value, list):
            for row in value:
                if isinstance(row, dict):
                    rows.append(row)
    return rows


class SearchsploitWebScannerPlugin(WebScannerPlugin):
    """Run searchsploit against target-derived keywords."""

    name = "searchsploit"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("searchsploit")
        if not binary:
            raise RuntimeError("searchsploit binary not found in PATH")

        keywords = _extract_keywords(target)
        # Prepend service-derived keywords (e.g. "vsftpd 2.3.4" from nmap)
        for kw in reversed(config.service_keywords or []):
            if kw and kw not in keywords:
                keywords.insert(0, kw)
        if not keywords:
            return []

        max_keywords = {"quick": 1, "normal": 2}.get(config.depth, 3)
        max_findings = {"quick": 8, "normal": 16}.get(config.depth, 30)
        findings: list[WebScanFinding] = []
        seen: set[str] = set()

        for keyword in keywords[:max_keywords]:
            command = [binary, "-j", keyword]
            result = await self._runner(
                command,
                timeout=None if config.timeout is None else max(30.0, config.timeout + 10.0),
                allowed_exit_codes=(0, 1),
                verbose=config.verbose,
            )
            assert isinstance(result, CommandResult)
            findings.extend(self._parse_output(result.stdout, target, keyword, seen))
            if len(findings) >= max_findings:
                break

        return findings[:max_findings]

    def _parse_output(
        self,
        stdout: str,
        target: str,
        keyword: str,
        seen: set[str],
    ) -> list[WebScanFinding]:
        try:
            payload = json.loads(stdout or "{}")
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict):
            return []

        findings: list[WebScanFinding] = []
        for row in _searchsploit_rows(payload):
            title = str(row.get("Title") or row.get("title") or "").strip()
            rel_path = str(row.get("Path") or row.get("path") or "").strip()
            edb_id = str(row.get("EDB-ID") or row.get("edb-id") or "").strip()
            if not title:
                continue
            unique_key = rel_path or f"{edb_id}:{title.lower()}"
            if unique_key in seen:
                continue
            seen.add(unique_key)

            exploit_url = (
                f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id.isdigit() else target
            )
            evidence_parts: list[str] = []
            if edb_id:
                evidence_parts.append(f"EDB-ID={edb_id}")
            if rel_path:
                evidence_parts.append(f"path={rel_path}")
            findings.append(
                WebScanFinding(
                    tool=self.name,
                    title=f"Exploit-DB match: {title}",
                    severity=_severity_from_title(title),
                    description=f"searchsploit found a local Exploit-DB match for '{keyword}'.",
                    url=exploit_url,
                    attack_type="exploit_research",
                    evidence=", ".join(evidence_parts),
                    raw={"keyword": keyword, **row},
                )
            )
        return findings
