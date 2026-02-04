"""Scanner module for ClawPwn - passive and active vulnerability scanning."""

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, parse_qs, urlparse

from clawpwn.tools.http import HTTPClient, HTTPResponse, check_headers
from clawpwn.modules.session import SessionManager
from clawpwn.db.models import Finding
from clawpwn.config import get_project_db_path


@dataclass
class ScanResult:
    """Represents a scan finding."""

    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    url: str
    attack_type: str
    evidence: str = ""
    remediation: str = ""
    confidence: str = "medium"  # low, medium, high


@dataclass
class ScanConfig:
    """Configuration for a scan."""

    target: str
    scan_types: List[str] = field(default_factory=lambda: ["all"])
    depth: str = "normal"  # quick, normal, deep
    threads: int = 10
    timeout: float = 30.0
    follow_redirects: bool = True


class PassiveScanner:
    """Passive scanner that analyzes responses without sending test payloads."""

    def __init__(self, project_dir: Optional[Path] = None):
        self.project_dir = project_dir
        self.session: Optional[SessionManager] = None

        if project_dir:
            db_path = get_project_db_path(project_dir)
            if db_path and db_path.exists():
                self.session = SessionManager(db_path)

    async def scan_response(self, response: HTTPResponse) -> List[ScanResult]:
        """
        Passively scan an HTTP response for issues.

        Checks for:
        - Information disclosure in headers
        - Missing security headers
        - Server version disclosure
        - Stack traces in error pages
        """
        findings = []

        # Check security headers
        header_findings = self._check_security_headers(response)
        findings.extend(header_findings)

        # Check for information disclosure
        info_findings = self._check_information_disclosure(response)
        findings.extend(info_findings)

        # Check for error patterns
        error_findings = self._check_error_patterns(response)
        findings.extend(error_findings)

        return findings

    def _check_security_headers(self, response: HTTPResponse) -> List[ScanResult]:
        """Check for missing security headers."""
        findings = []

        important_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME-sniffing protection",
            "Content-Security-Policy": "XSS and data injection protection",
            "Strict-Transport-Security": "HTTPS enforcement",
            "X-XSS-Protection": "XSS filter (legacy)",
        }

        missing = []
        for header, description in important_headers.items():
            if header not in response.headers:
                missing.append((header, description))

        if missing:
            headers_list = ", ".join([h[0] for h in missing])
            descriptions = "\n".join([f"  - {h[0]}: {h[1]}" for h in missing])

            findings.append(
                ScanResult(
                    title="Missing Security Headers",
                    severity="medium",
                    description=f"The following security headers are missing:\n{descriptions}",
                    url=response.url,
                    attack_type="Information Disclosure",
                    evidence=f"Missing headers: {headers_list}",
                    remediation="Add the missing security headers to server configuration.",
                )
            )

        return findings

    def _check_information_disclosure(self, response: HTTPResponse) -> List[ScanResult]:
        """Check for information disclosure in response."""
        findings = []

        # Check for server version disclosure
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

        # Check for stack traces
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
                        description="Application displays detailed error messages that may reveal internal implementation details.",
                        url=response.url,
                        attack_type="Information Disclosure",
                        evidence=f"Pattern found: {pattern}",
                        remediation="Configure application to show generic error messages in production.",
                    )
                )
                break

        # Check for sensitive patterns in body
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
                        severity="high"
                        if name in ["API Key", "AWS Access Key", "Private Key"]
                        else "low",
                        description=f"Potential {name} found in response body.",
                        url=response.url,
                        attack_type="Information Disclosure",
                        evidence=f"Found {len(matches)} occurrences",
                        remediation="Remove sensitive data from client-side responses.",
                    )
                )

        return findings

    def _check_error_patterns(self, response: HTTPResponse) -> List[ScanResult]:
        """Check for error patterns that indicate issues."""
        findings = []

        # SQL errors - broader patterns to catch various SQL error messages
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
                findings.append(
                    ScanResult(
                        title="SQL Error Detected",
                        severity="medium",
                        description="SQL error message detected in response, indicating potential SQL injection vulnerability or information disclosure.",
                        url=response.url,
                        attack_type="SQL Injection",
                        evidence=f"Pattern matched: {pattern}",
                        remediation="Review application for SQL injection vulnerabilities and proper error handling.",
                        confidence="medium",
                    )
                )
                break

        return findings


class ActiveScanner:
    """Active scanner that sends test payloads to detect vulnerabilities."""

    def __init__(self, project_dir: Optional[Path] = None):
        self.project_dir = project_dir
        self.session: Optional[SessionManager] = None

        if project_dir:
            db_path = get_project_db_path(project_dir)
            if db_path and db_path.exists():
                self.session = SessionManager(db_path)

    async def scan_target(self, target: str, depth: str = "normal") -> List[ScanResult]:
        """
        Actively scan a target for vulnerabilities.

        Tests for:
        - SQL Injection
        - XSS
        - Path Traversal
        - Command Injection
        - IDOR
        """
        findings = []

        async with HTTPClient() as client:
            # Get base page
            base_response = await client.get(target)

            # Test for SQL injection
            sql_findings = await self._test_sql_injection(client, target, depth)
            findings.extend(sql_findings)

            # Test for XSS
            xss_findings = await self._test_xss(client, target, depth)
            findings.extend(xss_findings)

            # Test for path traversal
            path_findings = await self._test_path_traversal(client, target)
            findings.extend(path_findings)

            # Test for command injection
            cmd_findings = await self._test_command_injection(client, target)
            findings.extend(cmd_findings)

            # Test for IDOR (if forms found)
            idor_findings = await self._test_idor(client, target, base_response)
            findings.extend(idor_findings)

        return findings

    async def _test_sql_injection(
        self, client: HTTPClient, target: str, depth: str
    ) -> List[ScanResult]:
        """Test for SQL injection vulnerabilities."""
        findings = []

        # Basic SQL injection payloads
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

        # Parse URL to find parameters
        parsed = urlparse(target)
        if parsed.query:
            params = parse_qs(parsed.query)

            for param_name, param_values in params.items():
                for payload in payloads[:4] if depth == "quick" else payloads:
                    test_params = {k: v[0] if v else "" for k, v in params.items()}
                    test_params[param_name] = payload

                    try:
                        response = await client.request(
                            "GET", target, params=test_params
                        )

                        # Check for SQL error indicators
                        sql_errors = [
                            "SQL syntax",
                            "mysql_fetch",
                            "ORA-",
                            "Microsoft SQL Server",
                            "PostgreSQL",
                            "SQLite",
                        ]

                        for error in sql_errors:
                            if error.lower() in response.body.lower():
                                findings.append(
                                    ScanResult(
                                        title="SQL Injection (Error-Based)",
                                        severity="critical",
                                        description=f"SQL injection vulnerability detected in parameter '{param_name}'.",
                                        url=target,
                                        attack_type="SQL Injection",
                                        evidence=f"Payload: {payload}\nError: {error}",
                                        remediation="Use parameterized queries and input validation.",
                                        confidence="high",
                                    )
                                )
                                return findings

                    except Exception:
                        continue

        return findings

    async def _test_xss(
        self, client: HTTPClient, target: str, depth: str
    ) -> List[ScanResult]:
        """Test for XSS vulnerabilities."""
        findings = []

        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
        ]

        parsed = urlparse(target)
        if parsed.query:
            params = parse_qs(parsed.query)

            for param_name, param_values in params.items():
                for payload in payloads[:2] if depth == "quick" else payloads:
                    test_params = {k: v[0] if v else "" for k, v in params.items()}
                    test_params[param_name] = payload

                    try:
                        response = await client.request(
                            "GET", target, params=test_params
                        )

                        # Check if payload is reflected
                        if payload in response.body:
                            # Check if it's actually executed or just reflected
                            if (
                                "<script>" in payload.lower()
                                and "<script>" in response.body.lower()
                            ):
                                findings.append(
                                    ScanResult(
                                        title="Cross-Site Scripting (XSS) - Reflected",
                                        severity="high",
                                        description=f"Reflected XSS vulnerability detected in parameter '{param_name}'.",
                                        url=target,
                                        attack_type="XSS",
                                        evidence=f"Payload: {payload}",
                                        remediation="Implement input validation and output encoding.",
                                        confidence="high",
                                    )
                                )
                                return findings

                    except Exception:
                        continue

        return findings

    async def _test_path_traversal(
        self, client: HTTPClient, target: str
    ) -> List[ScanResult]:
        """Test for path traversal vulnerabilities."""
        findings = []

        # Path traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        ]

        # Try to find file parameters
        test_paths = [
            "/?file=",
            "/?path=",
            "/?page=",
            "/?doc=",
            "/?filename=",
        ]

        for path in test_paths:
            test_url = urljoin(target, path)

            for payload in payloads:
                try:
                    full_url = f"{test_url}{payload}"
                    response = await client.get(full_url)

                    # Check for passwd file contents
                    if "root:" in response.body or "daemon:" in response.body:
                        findings.append(
                            ScanResult(
                                title="Path Traversal",
                                severity="critical",
                                description="Path traversal vulnerability allowing access to arbitrary files.",
                                url=test_url,
                                attack_type="Path Traversal",
                                evidence=f"Payload: {payload}",
                                remediation="Validate and sanitize file paths, use allowlists.",
                                confidence="high",
                            )
                        )
                        return findings

                    # Check for Windows hosts file
                    if (
                        "microsoft" in response.body.lower()
                        and "localhost" in response.body.lower()
                    ):
                        findings.append(
                            ScanResult(
                                title="Path Traversal (Windows)",
                                severity="critical",
                                description="Path traversal vulnerability allowing access to Windows system files.",
                                url=test_url,
                                attack_type="Path Traversal",
                                evidence=f"Payload: {payload}",
                                remediation="Validate and sanitize file paths, use allowlists.",
                                confidence="high",
                            )
                        )
                        return findings

                except Exception:
                    continue

        return findings

    async def _test_command_injection(
        self, client: HTTPClient, target: str
    ) -> List[ScanResult]:
        """Test for command injection vulnerabilities."""
        findings = []

        # Command injection payloads
        payloads = [
            "; id",
            "; whoami",
            "| id",
            "| whoami",
            "` id `",
            "$(id)",
        ]

        # Common injection points
        test_params = ["cmd", "exec", "command", "ping", "host", "ip"]

        for param in test_params:
            for payload in payloads:
                try:
                    test_url = f"{target}?{param}={payload}"
                    response = await client.get(test_url)

                    # Check for command output
                    if "uid=" in response.body or "gid=" in response.body:
                        findings.append(
                            ScanResult(
                                title="Command Injection",
                                severity="critical",
                                description=f"Command injection vulnerability in parameter '{param}'.",
                                url=target,
                                attack_type="Command Injection",
                                evidence=f"Payload: {payload}",
                                remediation="Never pass user input to system commands. Use parameterized APIs.",
                                confidence="high",
                            )
                        )
                        return findings

                except Exception:
                    continue

        return findings

    async def _test_idor(
        self, client: HTTPClient, target: str, base_response: HTTPResponse
    ) -> List[ScanResult]:
        """Test for IDOR (Insecure Direct Object Reference) vulnerabilities."""
        findings = []

        # Look for numeric IDs in URLs
        import re

        id_patterns = [
            r"/[\?&](id|user_id|account|document|file)=(\d+)",
            r"/api/(\w+)/(\d+)",
        ]

        for pattern in id_patterns:
            matches = re.findall(pattern, base_response.body)

            for match in matches:
                param_name = match[0]
                current_id = match[1]

                # Try to access different IDs
                try:
                    next_id = str(int(current_id) + 1)
                    modified_url = base_response.url.replace(
                        f"{param_name}={current_id}", f"{param_name}={next_id}"
                    )

                    test_response = await client.get(modified_url)

                    # If we get a successful response with different data, might be IDOR
                    if test_response.status_code == 200 and len(test_response.body) > 0:
                        # This is a potential IDOR, but needs manual verification
                        findings.append(
                            ScanResult(
                                title="Potential IDOR",
                                severity="medium",
                                description=f"Potential IDOR vulnerability in parameter '{param_name}'. Different ID returned valid response.",
                                url=target,
                                attack_type="IDOR",
                                evidence=f"Original ID: {current_id}, Tested ID: {next_id}",
                                remediation="Implement proper authorization checks for all object access.",
                                confidence="low",
                            )
                        )

                except Exception:
                    continue

        return findings


class Scanner:
    """Main scanner class that combines passive and active scanning."""

    def __init__(self, project_dir: Optional[Path] = None):
        self.project_dir = project_dir
        self.passive_scanner = PassiveScanner(project_dir)
        self.active_scanner = ActiveScanner(project_dir)
        self.session: Optional[SessionManager] = None

        if project_dir:
            db_path = get_project_db_path(project_dir)
            if db_path and db_path.exists():
                self.session = SessionManager(db_path)

    async def scan(
        self, target: str, config: Optional[ScanConfig] = None
    ) -> List[ScanResult]:
        """
        Run a complete scan (passive + active).

        Args:
            target: URL to scan
            config: Scan configuration

        Returns:
            List of findings
        """
        config = config or ScanConfig(target=target)
        all_findings = []

        print(f"[*] Starting scan of {target}")

        # Passive scan
        print("[*] Running passive scan...")
        async with HTTPClient() as client:
            response = await client.get(target)
            passive_findings = await self.passive_scanner.scan_response(response)
            all_findings.extend(passive_findings)

        # Active scan
        print("[*] Running active scan...")
        active_findings = await self.active_scanner.scan_target(target, config.depth)
        all_findings.extend(active_findings)

        # Store findings in database
        if self.session:
            for finding in all_findings:
                self.session.add_finding(
                    title=finding.title,
                    severity=finding.severity,
                    description=finding.description,
                    evidence=finding.evidence,
                    attack_type=finding.attack_type,
                )

            self.session.update_phase("Vulnerability Research")

        # Print summary
        print(f"[+] Scan complete. {len(all_findings)} findings.")
        self._print_findings_summary(all_findings)

        return all_findings

    def _print_findings_summary(self, findings: List[ScanResult]) -> None:
        """Print a summary of findings."""
        if not findings:
            print("\n[+] No vulnerabilities found.")
            return

        print("\n" + "=" * 60)
        print("SCAN RESULTS SUMMARY")
        print("=" * 60)

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        by_severity = {s: [] for s in severity_order}

        for finding in findings:
            sev = finding.severity.lower()
            if sev in by_severity:
                by_severity[sev].append(finding)

        # Print counts
        total = len(findings)
        critical = len(by_severity["critical"])
        high = len(by_severity["high"])

        print(f"\nTotal: {total} | Critical: {critical} | High: {high}")

        # Print details
        for severity in severity_order:
            if by_severity[severity]:
                print(f"\n{severity.upper()} ({len(by_severity[severity])}):")
                for finding in by_severity[severity][:5]:  # Show first 5
                    print(f"  • {finding.title} - {finding.attack_type}")

                if len(by_severity[severity]) > 5:
                    print(f"  ... and {len(by_severity[severity]) - 5} more")

        print("=" * 60)


# Convenience function
async def quick_scan(
    target: str, project_dir: Optional[Path] = None
) -> List[ScanResult]:
    """Quick scan of a target."""
    scanner = Scanner(project_dir)
    return await scanner.scan(target, ScanConfig(target=target, depth="quick"))
