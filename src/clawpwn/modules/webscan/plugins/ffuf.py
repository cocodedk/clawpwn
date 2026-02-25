"""FFUF content discovery plugin."""

import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urljoin

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import resolve_binary, run_command

DEFAULT_WORDLIST = [
    "admin",
    "login",
    "api",
    "graphql",
    "dashboard",
    ".env",
    "backup",
    "phpmyadmin",
]


def _severity_for_status(status: int) -> str:
    if status == 200:
        return "medium"
    if status in {401, 403}:
        return "low"
    if 300 <= status < 400:
        return "info"
    return "low"


class FFUFWebScannerPlugin(WebScannerPlugin):
    """Run ffuf and convert discovered paths to findings."""

    name = "ffuf"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("ffuf")
        if not binary:
            raise RuntimeError("ffuf binary not found in PATH")

        with tempfile.TemporaryDirectory(prefix="clawpwn-ffuf-") as tmpdir:
            out_path = Path(tmpdir) / "ffuf.json"
            wordlist = self._create_wordlist(Path(tmpdir))
            command = [
                binary,
                "-u",
                self._target_pattern(target),
                "-w",
                str(wordlist),
                "-mc",
                "200,204,301,302,307,401,403",
                "-t",
                str(max(1, config.concurrency)),
                "-of",
                "json",
                "-o",
                str(out_path),
            ]
            await self._runner(
                command,
                timeout=None if config.timeout is None else max(30.0, config.timeout + 15.0),
                verbose=config.verbose,
            )
            return self._parse_output(out_path, target, depth=config.depth)

    def _target_pattern(self, target: str) -> str:
        normalized = target.rstrip("/")
        return f"{normalized}/FUZZ"

    def _create_wordlist(self, tmpdir: Path) -> Path:
        wordlist_path = tmpdir / "wordlist.txt"
        wordlist_path.write_text("\n".join(DEFAULT_WORDLIST) + "\n", encoding="utf-8")
        return wordlist_path

    def _parse_output(self, out_path: Path, target: str, depth: str) -> list[WebScanFinding]:
        if not out_path.exists():
            return []
        try:
            payload = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        results = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(results, list):
            return []

        max_results = {"quick": 30, "normal": 80}.get(depth, 200)
        findings: list[WebScanFinding] = []
        for item in results[:max_results]:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip() or target
            status = int(item.get("status") or 0)
            input_data = item.get("input", {})
            fuzz_token = ""
            if isinstance(input_data, dict):
                fuzz_token = str(input_data.get("FUZZ") or "").strip()
            path = fuzz_token or url.removeprefix(target).lstrip("/") or "/"
            evidence = f"status={status}"
            length = item.get("length")
            if isinstance(length, int):
                evidence = f"{evidence}, bytes={length}"
            findings.append(
                WebScanFinding(
                    tool=self.name,
                    title=f"Discovered endpoint: /{path.lstrip('/')}",
                    severity=_severity_for_status(status),
                    description=f"FFUF discovered a reachable endpoint ({status}).",
                    url=urljoin(target.rstrip("/") + "/", path.lstrip("/")) if fuzz_token else url,
                    attack_type="content_discovery",
                    evidence=evidence,
                    raw=item,
                )
            )
        return findings
