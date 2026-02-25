"""Active SQL injection and XSS checks."""

from urllib.parse import parse_qs, urlparse

from clawpwn.modules.attack_feedback import (
    decide_attack_policy,
    extract_attack_signals,
    summarize_signals,
)
from clawpwn.tools.http import HTTPClient

from .models import ScanResult


async def test_sql_injection(client: HTTPClient, target: str, depth: str) -> list[ScanResult]:
    """Test for SQL injection vulnerabilities."""
    payloads = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR 1=1--",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND 1=1--",
        "1' AND 1=2--",
    ]

    parsed = urlparse(target)
    if not parsed.query:
        return []

    observed_hints: list[str] = []
    observed_blocks: list[str] = []
    block_streak = 0

    params = parse_qs(parsed.query)
    for param_name in params:
        for payload in payloads[:4] if depth == "quick" else payloads:
            test_params = {key: values[0] if values else "" for key, values in params.items()}
            test_params[param_name] = payload
            try:
                response = await client.request("GET", target, params=test_params)
            except Exception:
                continue

            signals = extract_attack_signals(
                response.body,
                status_code=response.status_code,
                headers=response.headers,
            )
            hint_messages = summarize_signals(signals, "hint", limit=2)
            for message in hint_messages:
                if message not in observed_hints:
                    observed_hints.append(message)

            block_messages = summarize_signals(signals, "block", limit=2)
            if block_messages:
                block_streak += 1
                for message in block_messages:
                    if message not in observed_blocks:
                        observed_blocks.append(message)
            else:
                block_streak = 0

            policy = decide_attack_policy(signals, block_streak=block_streak)
            if policy.action == "stop_and_replan":
                evidence = "; ".join(observed_blocks[:3]) or policy.reason
                return [
                    ScanResult(
                        title="SQL Injection Testing Blocked by Defensive Responses",
                        severity="info",
                        description=(
                            "Target returned repeated defensive signals while testing SQLi payloads. "
                            "Stop direct spraying and re-plan approach."
                        ),
                        url=target,
                        attack_type="Attack Feedback",
                        evidence=evidence,
                        remediation=(
                            "Apply backoff, reduce request rate, and switch to a narrower/manual vector."
                        ),
                        confidence="high",
                    )
                ]

            for error in [
                "SQL syntax",
                "mysql_fetch",
                "ORA-",
                "Microsoft SQL Server",
                "PostgreSQL",
                "SQLite",
            ]:
                if error.lower() in response.body.lower():
                    evidence = f"Payload: {payload}\nError: {error}"
                    if observed_hints:
                        evidence += f"\nHints: {'; '.join(observed_hints[:2])}"
                    return [
                        ScanResult(
                            title="SQL Injection (Error-Based)",
                            severity="critical",
                            description=(
                                f"SQL injection vulnerability detected in parameter '{param_name}'."
                            ),
                            url=target,
                            attack_type="SQL Injection",
                            evidence=evidence,
                            remediation="Use parameterized queries and input validation.",
                            confidence="high",
                        )
                    ]

    if observed_hints or observed_blocks:
        feedback = observed_blocks if observed_blocks else observed_hints
        title = (
            "SQL Injection Testing Encountered Defensive Signals"
            if observed_blocks
            else "SQL Injection Response Hints Observed"
        )
        return [
            ScanResult(
                title=title,
                severity="info",
                description=(
                    "Attack-response feedback was observed during SQLi testing. "
                    "Use these signals to refine payloads and strategy."
                ),
                url=target,
                attack_type="Attack Feedback",
                evidence="; ".join(feedback[:3]),
                remediation="Adjust parameters, form fields, and request pacing before retrying.",
                confidence="medium",
            )
        ]

    return []


async def test_xss(client: HTTPClient, target: str, depth: str) -> list[ScanResult]:
    """Test for XSS vulnerabilities."""
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
    ]

    parsed = urlparse(target)
    if not parsed.query:
        return []

    params = parse_qs(parsed.query)
    for param_name in params:
        for payload in payloads[:2] if depth == "quick" else payloads:
            test_params = {key: values[0] if values else "" for key, values in params.items()}
            test_params[param_name] = payload
            try:
                response = await client.request("GET", target, params=test_params)
            except Exception:
                continue

            if payload in response.body and "<script>" in payload.lower():
                if "<script>" in response.body.lower():
                    return [
                        ScanResult(
                            title="Cross-Site Scripting (XSS) - Reflected",
                            severity="high",
                            description=(
                                f"Reflected XSS vulnerability detected in parameter '{param_name}'."
                            ),
                            url=target,
                            attack_type="XSS",
                            evidence=f"Payload: {payload}",
                            remediation="Implement input validation and output encoding.",
                            confidence="high",
                        )
                    ]

    return []
