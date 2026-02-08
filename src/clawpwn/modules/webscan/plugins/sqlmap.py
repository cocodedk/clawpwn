"""Sqlmap SQL injection scanner plugin."""

import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlencode, urljoin

import httpx

from clawpwn.modules.attack_feedback import (
    AttackSignal,
    decide_attack_policy,
    extract_attack_signals,
    summarize_signals,
)

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding
from ..runtime import CommandResult, resolve_binary, run_command

# Injection type -> severity mapping
_INJECTION_SEVERITY: dict[str, str] = {
    "union": "critical",
    "stacked": "critical",
    "error": "high",
    "boolean": "high",
    "time": "high",
    "inline": "medium",
}


@dataclass
class _SqlmapRequestContext:
    action_url: str | None = None
    cookie_header: str | None = None
    post_data: str | None = None
    csrf_token: str | None = None

    @property
    def has_stateful_hints(self) -> bool:
        # Cookie-only context is too weak; require form-derived state.
        return bool(self.post_data or self.csrf_token)


def _severity_for_technique(technique: str) -> str:
    lowered = technique.lower()
    for key, sev in _INJECTION_SEVERITY.items():
        if key in lowered:
            return sev
    return "high"


class SqlmapWebScannerPlugin(WebScannerPlugin):
    """Run sqlmap in batch mode and parse injection findings."""

    name = "sqlmap"

    def __init__(self, command_runner: Callable[..., object] | None = None):
        self._runner = command_runner or run_command

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        binary = resolve_binary("sqlmap")
        if not binary:
            raise RuntimeError("sqlmap binary not found in PATH")

        with tempfile.TemporaryDirectory(prefix="clawpwn-sqlmap-") as tmpdir:
            command = self._build_command(binary, target, config, tmpdir)
            try:
                result = await self._runner(
                    command,
                    timeout=None if config.timeout is None else max(300.0, config.timeout * 5),
                    allowed_exit_codes=(0, 1, 2, 3, 4, 5, 6, 7, 8),
                    verbose=config.verbose,
                )
                assert isinstance(result, CommandResult)
                signals = self._extract_signals(result.stdout, result.stderr)
                findings = self._parse_output(result.stdout, result.stderr, target)
                findings = self._annotate_findings_with_feedback(findings, signals)
            except Exception as exc:
                if config.depth != "deep" or not self._is_timeout_error(exc):
                    raise
                timeout_findings = await self._run_stateful_fallback(
                    binary=binary,
                    target=target,
                    config=config,
                    tmpdir=tmpdir,
                )
                if timeout_findings is not None:
                    return timeout_findings
                raise

            if findings:
                return findings
            if config.depth != "deep":
                feedback_findings = self._build_feedback_findings(signals, target)
                return feedback_findings if feedback_findings else findings

            if summarize_signals(signals, "block"):
                feedback_findings = self._build_feedback_findings(signals, target)
                return feedback_findings if feedback_findings else findings

            # Second pass for stateful form workflows (cookies/POST/CSRF) when deep scan finds nothing.
            request_context = await self._derive_request_context(target)
            if not request_context.has_stateful_hints:
                feedback_findings = self._build_feedback_findings(signals, target)
                return feedback_findings if feedback_findings else findings

            stateful_command = self._build_stateful_command(
                binary,
                target,
                config,
                tmpdir,
                request_context,
            )
            if stateful_command == command:
                return findings

            stateful_result = await self._runner(
                stateful_command,
                timeout=None if config.timeout is None else max(180.0, config.timeout * 4),
                allowed_exit_codes=(0, 1, 2, 3, 4, 5, 6, 7, 8),
                verbose=config.verbose,
            )
            assert isinstance(stateful_result, CommandResult)
            stateful_signals = self._extract_signals(stateful_result.stdout, stateful_result.stderr)
            stateful_findings = self._parse_output(
                stateful_result.stdout,
                stateful_result.stderr,
                request_context.action_url or target,
            )
            stateful_findings = self._annotate_findings_with_feedback(
                stateful_findings, stateful_signals
            )
            merged_findings = self._dedupe_findings([*findings, *stateful_findings])
            if merged_findings:
                return merged_findings
            feedback_findings = self._build_feedback_findings(
                [*signals, *stateful_signals], request_context.action_url or target
            )
            return feedback_findings if feedback_findings else merged_findings

    async def _run_stateful_fallback(
        self,
        *,
        binary: str,
        target: str,
        config: WebScanConfig,
        tmpdir: str,
    ) -> list[WebScanFinding] | None:
        """Attempt a narrower POST/cookie/csrf pass when broad crawl timed out."""
        request_context = await self._derive_request_context(target)
        if not request_context.has_stateful_hints:
            return None

        stateful_command = self._build_stateful_command(
            binary=binary,
            target=target,
            config=config,
            tmpdir=tmpdir,
            request_context=request_context,
        )
        try:
            stateful_result = await self._runner(
                stateful_command,
                timeout=None if config.timeout is None else max(180.0, config.timeout * 4),
                allowed_exit_codes=(0, 1, 2, 3, 4, 5, 6, 7, 8),
                verbose=config.verbose,
            )
        except Exception:
            return None
        assert isinstance(stateful_result, CommandResult)
        signals = self._extract_signals(stateful_result.stdout, stateful_result.stderr)
        findings = self._parse_output(
            stateful_result.stdout,
            stateful_result.stderr,
            request_context.action_url or target,
        )
        findings = self._annotate_findings_with_feedback(findings, signals)
        if findings:
            return findings
        feedback_findings = self._build_feedback_findings(
            signals, request_context.action_url or target
        )
        return feedback_findings if feedback_findings else findings

    def _build_command(
        self, binary: str, target: str, config: WebScanConfig, tmpdir: str
    ) -> list[str]:
        command = [
            binary,
            "-u",
            target,
            "--batch",
            "--output-dir",
            tmpdir,
            "--forms",
            "--crawl=1",
        ]
        self._apply_depth_flags(command, config.depth)
        return command

    def _build_stateful_command(
        self,
        binary: str,
        target: str,
        config: WebScanConfig,
        tmpdir: str,
        request_context: _SqlmapRequestContext,
    ) -> list[str]:
        command = [
            binary,
            "-u",
            request_context.action_url or target,
            "--batch",
            "--output-dir",
            tmpdir,
            "--method",
            "POST",
        ]

        if request_context.post_data:
            command.extend(["--data", request_context.post_data])
        else:
            command.extend(["--forms", "--crawl=1"])

        if request_context.cookie_header:
            command.extend(["--cookie", request_context.cookie_header])
        if request_context.csrf_token:
            command.extend(["--csrf-token", request_context.csrf_token])
            command.extend(["--csrf-url", request_context.action_url or target])

        self._apply_depth_flags(command, config.depth)
        return command

    def _apply_depth_flags(self, command: list[str], depth: str) -> None:
        if depth == "quick":
            command.extend(["--level=1", "--risk=1"])
        elif depth == "deep":
            command.extend(["--level=5", "--risk=3", "--technique=BEUSTQ"])
        else:
            command.extend(["--level=3", "--risk=2"])

    async def _derive_request_context(self, target: str) -> _SqlmapRequestContext:
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
                response = await client.get(target)
                html = response.text
                cookie_header = (
                    "; ".join(f"{name}={value}" for name, value in client.cookies.items()) or None
                )
        except Exception:
            return _SqlmapRequestContext()

        form_match = re.search(r"<form[^>]*>.*?</form>", html, re.DOTALL | re.IGNORECASE)
        if not form_match:
            return _SqlmapRequestContext(cookie_header=cookie_header)

        form_html = form_match.group(0)
        action = self._extract_attr(form_html, "action")
        action_url = urljoin(str(response.url), action) if action else str(response.url)
        fields, csrf_token = self._extract_form_fields(form_html)
        post_data = urlencode(fields) if fields else None
        return _SqlmapRequestContext(
            action_url=action_url,
            cookie_header=cookie_header,
            post_data=post_data,
            csrf_token=csrf_token,
        )

    def _extract_form_fields(self, form_html: str) -> tuple[dict[str, str], str | None]:
        fields: dict[str, str] = {}
        csrf_token: str | None = None
        input_tags = re.findall(r"<input\b[^>]*>", form_html, re.IGNORECASE)
        for tag in input_tags:
            name = self._extract_attr(tag, "name")
            if not name:
                continue
            field_type = (self._extract_attr(tag, "type") or "text").lower()
            if field_type in {"submit", "button", "reset", "file", "image"}:
                continue

            value = self._extract_attr(tag, "value") or ""
            name_lower = name.lower()
            if not value and field_type in {"text", "email", "password"}:
                value = "test"
            fields[name] = value
            if csrf_token is None and ("csrf" in name_lower or "token" in name_lower):
                csrf_token = name

        return fields, csrf_token

    def _extract_attr(self, html: str, attr_name: str) -> str | None:
        match = re.search(rf'{attr_name}=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def _is_timeout_error(self, exc: Exception) -> bool:
        return "timed out" in str(exc).lower()

    def _dedupe_findings(self, findings: list[WebScanFinding]) -> list[WebScanFinding]:
        seen: set[tuple[str, str, str, str, str]] = set()
        deduped: list[WebScanFinding] = []
        for finding in findings:
            key = (
                finding.tool,
                finding.url,
                finding.title,
                finding.severity,
                finding.attack_type,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def _parse_output(self, stdout: str, stderr: str, target: str) -> list[WebScanFinding]:
        """Parse sqlmap stdout/stderr for injection point summaries."""
        findings: list[WebScanFinding] = []
        combined = stdout + "\n" + stderr
        current_param: str | None = None

        for raw_line in combined.splitlines():
            line = raw_line.strip()

            # Detect parameter header: "Parameter: id (GET)"
            if line.startswith("Parameter:"):
                current_param = line.replace("Parameter:", "").strip()
                continue

            # Detect injection type line: "Type: boolean-based blind"
            if line.startswith("Type:") and current_param:
                technique = line.replace("Type:", "").strip()
                title_text = technique or "SQL Injection"
                findings.append(
                    WebScanFinding(
                        tool=self.name,
                        title=f"SQL Injection ({title_text}): {current_param}",
                        severity=_severity_for_technique(technique),
                        description=(
                            f"sqlmap detected {technique} SQL injection "
                            f"on parameter '{current_param}'."
                        ),
                        url=target,
                        attack_type="SQL Injection",
                        evidence=f"Parameter: {current_param}, Type: {technique}",
                        raw={"parameter": current_param, "type": technique},
                    )
                )

        return findings

    def _extract_signals(self, stdout: str, stderr: str) -> list[AttackSignal]:
        return extract_attack_signals(f"{stdout}\n{stderr}")

    def _annotate_findings_with_feedback(
        self, findings: list[WebScanFinding], signals: list[AttackSignal]
    ) -> list[WebScanFinding]:
        if not findings or not signals:
            return findings

        hints = summarize_signals(signals, "hint", limit=3)
        blocks = summarize_signals(signals, "block", limit=3)
        policy = decide_attack_policy(signals)
        for finding in findings:
            raw = dict(finding.raw or {})
            if hints:
                raw["feedback_hints"] = hints
            if blocks:
                raw["feedback_blocks"] = blocks
            raw["feedback_policy"] = policy.action
            raw["feedback_reason"] = policy.reason
            finding.raw = raw

            feedback_parts: list[str] = []
            if hints:
                feedback_parts.append(f"hints={'; '.join(hints[:2])}")
            if blocks:
                feedback_parts.append(f"blocks={'; '.join(blocks[:2])}")
            if feedback_parts:
                if finding.evidence:
                    finding.evidence += "\n"
                finding.evidence += f"Response feedback: {' | '.join(feedback_parts)}"
        return findings

    def _build_feedback_findings(
        self, signals: list[AttackSignal], target: str
    ) -> list[WebScanFinding]:
        if not signals:
            return []

        hints = summarize_signals(signals, "hint", limit=3)
        blocks = summarize_signals(signals, "block", limit=3)
        if not hints and not blocks:
            return []

        policy = decide_attack_policy(signals)
        evidence_parts: list[str] = []
        if hints:
            evidence_parts.append(f"hints={'; '.join(hints)}")
        if blocks:
            evidence_parts.append(f"blocks={'; '.join(blocks)}")

        title = (
            "sqlmap observed defensive response signals"
            if blocks
            else "sqlmap observed SQL response hints"
        )
        severity = "info" if blocks else "low"
        description = (
            "sqlmap output indicates target-side blocking/throttling behavior."
            if blocks
            else "sqlmap output includes SQL/backend hints that can refine attack vectors."
        )
        return [
            WebScanFinding(
                tool=self.name,
                title=title,
                severity=severity,
                description=description,
                url=target,
                attack_type="Attack Feedback",
                evidence=" | ".join(evidence_parts),
                raw={
                    "feedback_hints": hints,
                    "feedback_blocks": blocks,
                    "feedback_policy": policy.action,
                    "feedback_reason": policy.reason,
                },
            )
        ]
