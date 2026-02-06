"""Feroxbuster directory discovery plugin."""

import json
import tempfile
from collections.abc import Callable
from pathlib import Path

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import resolve_binary, run_command


def _severity_for_status(status: int) -> str:
    if status == 200:
        return "medium"
    if status in {401, 403}:
        return "low"
    if 300 <= status < 400:
        return "info"
    return "low"


def _depth_for_mode(depth: str) -> int:
    return {"quick": 1, "normal": 3}.get(depth, 6)


class FeroxbusterWebScannerPlugin(WebScannerPlugin):
    """Run feroxbuster for recursive directory/content discovery."""

    name = "feroxbuster"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("feroxbuster")
        if not binary:
            raise RuntimeError("feroxbuster binary not found in PATH")

        with tempfile.TemporaryDirectory(prefix="clawpwn-ferox-") as tmpdir:
            out_file = Path(tmpdir) / "ferox.jsonl"
            command = [
                binary,
                "-u",
                target,
                "--json",
                "--silent",
                "--threads",
                str(max(1, config.concurrency)),
                "--depth",
                str(_depth_for_mode(config.depth)),
                "-o",
                str(out_file),
            ]
            await self._runner(
                command,
                timeout=max(60.0, config.timeout + 30.0),
                verbose=config.verbose,
            )
            return self._parse_output(out_file, target, depth=config.depth)

    def _parse_output(self, out_file: Path, target: str, depth: str) -> list[WebScanFinding]:
        if not out_file.exists():
            return []
        findings: list[WebScanFinding] = []
        max_results = {"quick": 40, "normal": 120}.get(depth, 250)
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

            status = self._extract_int(obj, "status")
            url = self._extract_str(obj, "url")
            if status is None or not url:
                continue
            method = self._extract_str(obj, "method") or "GET"
            words = self._extract_int(obj, "words")
            lines = self._extract_int(obj, "lines")
            content_length = self._extract_int(obj, "content_length")
            evidence_parts = [f"status={status}", f"method={method}"]
            if content_length is not None:
                evidence_parts.append(f"bytes={content_length}")
            if words is not None:
                evidence_parts.append(f"words={words}")
            if lines is not None:
                evidence_parts.append(f"lines={lines}")

            findings.append(
                WebScanFinding(
                    tool=self.name,
                    title=f"Discovered endpoint: {url}",
                    severity=_severity_for_status(status),
                    description=f"Feroxbuster discovered a reachable endpoint ({status}).",
                    url=url,
                    attack_type="content_discovery",
                    evidence=", ".join(evidence_parts),
                    raw=obj,
                )
            )
            if len(findings) >= max_results:
                break
        return findings

    def _extract_str(self, obj: dict[str, object], key: str) -> str:
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        nested = obj.get("response")
        if isinstance(nested, dict):
            nested_value = nested.get(key)
            if isinstance(nested_value, str) and nested_value.strip():
                return nested_value.strip()
        return ""

    def _extract_int(self, obj: dict[str, object], key: str) -> int | None:
        value = obj.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
        nested = obj.get("response")
        if isinstance(nested, dict):
            nested_value = nested.get(key)
            if isinstance(nested_value, int):
                return nested_value
            if isinstance(nested_value, float):
                return int(nested_value)
            if isinstance(nested_value, str) and nested_value.isdigit():
                return int(nested_value)
        return None
