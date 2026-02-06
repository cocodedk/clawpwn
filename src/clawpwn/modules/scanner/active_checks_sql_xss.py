"""Active SQL injection and XSS checks."""

from urllib.parse import parse_qs, urlparse

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

    params = parse_qs(parsed.query)
    for param_name in params:
        for payload in payloads[:4] if depth == "quick" else payloads:
            test_params = {key: values[0] if values else "" for key, values in params.items()}
            test_params[param_name] = payload
            try:
                response = await client.request("GET", target, params=test_params)
            except Exception:
                continue

            for error in [
                "SQL syntax",
                "mysql_fetch",
                "ORA-",
                "Microsoft SQL Server",
                "PostgreSQL",
                "SQLite",
            ]:
                if error.lower() in response.body.lower():
                    return [
                        ScanResult(
                            title="SQL Injection (Error-Based)",
                            severity="critical",
                            description=(
                                f"SQL injection vulnerability detected in parameter '{param_name}'."
                            ),
                            url=target,
                            attack_type="SQL Injection",
                            evidence=f"Payload: {payload}\nError: {error}",
                            remediation="Use parameterized queries and input validation.",
                            confidence="high",
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
