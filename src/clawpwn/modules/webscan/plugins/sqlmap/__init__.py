"""Sqlmap SQL injection scanner plugin."""

from __future__ import annotations

import tempfile
from collections.abc import Callable

from clawpwn.modules.attack_feedback import summarize_signals

from ...base import WebScannerPlugin
from ...models import WebScanConfig, WebScanFinding
from ...runtime import CommandResult, resolve_binary, run_command
from .commands import build_command, build_stateful_command
from .context import SqlmapRequestContext as _SqlmapRequestContext
from .context import derive_request_context
from .feedback import annotate_findings_with_feedback, build_feedback_findings, extract_signals
from .parsing import dedupe_findings, is_timeout_error, parse_output


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
            command = build_command(binary, target, config.depth, tmpdir)
            try:
                result = await self._runner(
                    command,
                    timeout=None if config.timeout is None else max(300.0, config.timeout * 5),
                    allowed_exit_codes=(0, 1, 2, 3, 4, 5, 6, 7, 8),
                    verbose=config.verbose,
                )
                assert isinstance(result, CommandResult)
                signals = extract_signals(result.stdout, result.stderr)
                findings = parse_output(result.stdout, result.stderr, target, self.name)
                findings = annotate_findings_with_feedback(findings, signals)
            except Exception as exc:
                if config.depth != "deep" or not is_timeout_error(exc):
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
                feedback_findings = build_feedback_findings(signals, target, self.name)
                return feedback_findings if feedback_findings else findings

            if summarize_signals(signals, "block"):
                feedback_findings = build_feedback_findings(signals, target, self.name)
                return feedback_findings if feedback_findings else findings

            request_context = await self._derive_request_context(target)
            if not request_context.has_stateful_hints:
                feedback_findings = build_feedback_findings(signals, target, self.name)
                return feedback_findings if feedback_findings else findings

            stateful_command = build_stateful_command(
                binary,
                target,
                config.depth,
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
            stateful_signals = extract_signals(stateful_result.stdout, stateful_result.stderr)
            stateful_findings = parse_output(
                stateful_result.stdout,
                stateful_result.stderr,
                request_context.action_url or target,
                self.name,
            )
            stateful_findings = annotate_findings_with_feedback(stateful_findings, stateful_signals)
            merged_findings = dedupe_findings([*findings, *stateful_findings])
            if merged_findings:
                return merged_findings
            feedback_findings = build_feedback_findings(
                [*signals, *stateful_signals],
                request_context.action_url or target,
                self.name,
            )
            return feedback_findings if feedback_findings else merged_findings

    async def _derive_request_context(self, target: str) -> _SqlmapRequestContext:
        return await derive_request_context(target)

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

        stateful_command = build_stateful_command(
            binary=binary,
            target=target,
            depth=config.depth,
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
        signals = extract_signals(stateful_result.stdout, stateful_result.stderr)
        findings = parse_output(
            stateful_result.stdout,
            stateful_result.stderr,
            request_context.action_url or target,
            self.name,
        )
        findings = annotate_findings_with_feedback(findings, signals)
        if findings:
            return findings
        feedback_findings = build_feedback_findings(
            signals,
            request_context.action_url or target,
            self.name,
        )
        return feedback_findings if feedback_findings else findings


__all__ = ["SqlmapWebScannerPlugin", "_SqlmapRequestContext"]
