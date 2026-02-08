"""Attack-response signal extraction and policy decisions."""

from __future__ import annotations

import re
from collections.abc import Mapping

from .models import AttackPolicyDecision, AttackSignal

_HINT_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (
        r"#1045\s*-\s*access denied for user",
        "mysql_access_denied",
        "MySQL auth failed (#1045); adjust fields/payload strategy instead of auth-bypass claims.",
    ),
    (
        r"using password:\s*no",
        "password_missing",
        "Server reports password was not used; verify password field is submitted correctly.",
    ),
    (
        r"(sql syntax|you have an error in your sql syntax|sqlstate\[)",
        "sql_syntax_error",
        "SQL parser error observed; payload reached backend SQL parser.",
    ),
    (
        r"(unknown column|unknown table|doesn't exist|table .* doesn't exist)",
        "schema_hint",
        "Schema-related DB error observed; refine table/column assumptions.",
    ),
)

_BLOCK_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (
        r"(too many requests|rate limit|temporarily blocked)",
        "rate_limited",
        "Rate limiting detected; slow down and back off before retrying.",
    ),
    (
        r"(captcha|cf-challenge|cloudflare|sucuri|akamai)",
        "challenge_or_waf",
        "Challenge/WAF response detected; stop and re-plan vector.",
    ),
    (
        r"(request blocked|forbidden by security policy|blocked by waf)",
        "waf_block",
        "Explicit security blocking detected; stop and switch approach.",
    ),
    (
        r"(timed out|read timed out|connect timeout|connection reset by peer)",
        "network_timeout",
        "Request timeout/reset observed; repeated failures may indicate throttling or blocking.",
    ),
)


def extract_attack_signals(
    text: str,
    *,
    status_code: int | None = None,
    headers: Mapping[str, str] | None = None,
) -> list[AttackSignal]:
    """Extract hint/block signals from text plus optional HTTP metadata."""
    signals: list[AttackSignal] = []
    lowered = (text or "").lower()

    for pattern, key, message in _HINT_PATTERNS:
        if re.search(pattern, lowered):
            signals.append(AttackSignal(category="hint", key=key, message=message))

    for pattern, key, message in _BLOCK_PATTERNS:
        if re.search(pattern, lowered):
            signals.append(AttackSignal(category="block", key=key, message=message))

    if status_code in {403, 406, 429, 503}:
        signals.append(
            AttackSignal(
                category="block",
                key=f"http_{status_code}",
                message=f"HTTP {status_code} indicates defensive filtering or throttling.",
            )
        )

    if headers:
        h = {k.lower(): str(v).lower() for k, v in headers.items()}
        if "retry-after" in h:
            signals.append(
                AttackSignal(
                    category="block",
                    key="retry_after",
                    message="Retry-After header observed; service requested backoff.",
                )
            )
        if h.get("x-ratelimit-remaining", "").strip() == "0":
            signals.append(
                AttackSignal(
                    category="block",
                    key="rate_limit_zero",
                    message="Rate-limit budget reached (x-ratelimit-remaining=0).",
                )
            )

    deduped: dict[tuple[str, str], AttackSignal] = {}
    for sig in signals:
        deduped[(sig.category, sig.key)] = sig
    return list(deduped.values())


def summarize_signals(signals: list[AttackSignal], category: str, limit: int = 3) -> list[str]:
    """Return unique user-facing messages for one signal category."""
    seen: set[str] = set()
    output: list[str] = []
    for sig in signals:
        if sig.category != category:
            continue
        if sig.message in seen:
            continue
        seen.add(sig.message)
        output.append(sig.message)
        if len(output) >= limit:
            break
    return output


def decide_attack_policy(
    signals: list[AttackSignal], block_streak: int = 0
) -> AttackPolicyDecision:
    """Decide whether to continue, adjust, backoff, or stop based on signals."""
    block_count = sum(1 for sig in signals if sig.category == "block")
    hint_count = sum(1 for sig in signals if sig.category == "hint")

    if block_streak >= 2 or block_count >= 2:
        return AttackPolicyDecision(
            action="stop_and_replan",
            reason="Repeated blocking signals detected from the target.",
        )
    if block_count == 1:
        return AttackPolicyDecision(
            action="backoff",
            reason="Blocking signal detected; apply backoff and reduce request pressure.",
        )
    if hint_count > 0:
        return AttackPolicyDecision(
            action="continue_adjust",
            reason="Response hints detected; adjust payload/field strategy before retrying.",
        )
    return AttackPolicyDecision(action="continue", reason="No actionable response signals.")
