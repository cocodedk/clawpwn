"""Passive response analysis checks."""

import re

from clawpwn.tools.http import HTTPResponse

from .models import ScanResult


def check_security_headers(response: HTTPResponse) -> list[ScanResult]:
    """Check for missing security headers."""
    important_headers = {
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME-sniffing protection",
        "Content-Security-Policy": "XSS and data injection protection",
        "Strict-Transport-Security": "HTTPS enforcement",
        "X-XSS-Protection": "XSS filter (legacy)",
    }

    missing = [
        (header, description)
        for header, description in important_headers.items()
        if header not in response.headers
    ]
    if not missing:
        return []

    headers_list = ", ".join(header for header, _ in missing)
    descriptions = "\n".join(f"  - {header}: {description}" for header, description in missing)
    return [
        ScanResult(
            title="Missing Security Headers",
            severity="medium",
            description=f"The following security headers are missing:\n{descriptions}",
            url=response.url,
            attack_type="Information Disclosure",
            evidence=f"Missing headers: {headers_list}",
            remediation="Add the missing security headers to server configuration.",
        )
    ]


def check_information_disclosure(response: HTTPResponse) -> list[ScanResult]:
    """Check for information disclosure in headers/body."""
    findings: list[ScanResult] = []

    server_header = response.headers.get("Server", "")
    if server_header and any(char.isdigit() for char in server_header):
        findings.append(
            ScanResult(
                title="Server Version Disclosure",
                severity="low",
                description="The server header reveals version information.",
                url=response.url,
                attack_type="Information Disclosure",
                evidence=f"Server: {server_header}",
                remediation="Configure server to hide version information.",
            )
        )

    stack_patterns = [
        r"Traceback \(most recent call last\)",
        r"Exception in thread",
        r"Fatal error:",
        r"Error: ",
    ]
    for pattern in stack_patterns:
        if re.search(pattern, response.body, re.IGNORECASE):
            findings.append(
                ScanResult(
                    title="Detailed Error Messages (Stack Trace)",
                    severity="medium",
                    description=(
                        "Application displays detailed error messages that may reveal "
                        "internal implementation details."
                    ),
                    url=response.url,
                    attack_type="Information Disclosure",
                    evidence=f"Pattern found: {pattern}",
                    remediation="Configure application to show generic error messages in production.",
                )
            )
            break

    sensitive_patterns = {
        "API Key": r"[\"']?api[_-]?key[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_]{16,}[\"']?",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Private Key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    }
    for name, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, response.body, re.IGNORECASE)
        if matches:
            findings.append(
                ScanResult(
                    title=f"Potential {name} Exposure",
                    severity=(
                        "high" if name in ["API Key", "AWS Access Key", "Private Key"] else "low"
                    ),
                    description=f"Potential {name} found in response body.",
                    url=response.url,
                    attack_type="Information Disclosure",
                    evidence=f"Found {len(matches)} occurrences",
                    remediation="Remove sensitive data from client-side responses.",
                )
            )

    return findings


def check_error_patterns(response: HTTPResponse) -> list[ScanResult]:
    """Check for error patterns indicating possible vulnerabilities."""
    sql_patterns = [
        r"SQL syntax",
        r"mysql_fetch",
        r"ORA-[0-9]{5}",
        r"PostgreSQL",
        r"SQL Server",
        r"SQLite",
    ]
    for pattern in sql_patterns:
        if re.search(pattern, response.body, re.IGNORECASE):
            return [
                ScanResult(
                    title="SQL Error Detected",
                    severity="medium",
                    description=(
                        "SQL error message detected in response, indicating potential SQL "
                        "injection vulnerability or information disclosure."
                    ),
                    url=response.url,
                    attack_type="SQL Injection",
                    evidence=f"Pattern matched: {pattern}",
                    remediation=(
                        "Review application for SQL injection vulnerabilities and proper "
                        "error handling."
                    ),
                    confidence="medium",
                )
            ]
    return []
