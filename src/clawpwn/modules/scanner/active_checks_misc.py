"""Active path traversal, command injection, and IDOR checks."""

import re
from urllib.parse import urljoin

from clawpwn.tools.http import HTTPClient, HTTPResponse

from .models import ScanResult


async def test_path_traversal(client: HTTPClient, target: str) -> list[ScanResult]:
    """Test for path traversal vulnerabilities."""
    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    ]
    test_paths = ["/?file=", "/?path=", "/?page=", "/?doc=", "/?filename="]

    for path in test_paths:
        test_url = urljoin(target, path)
        for payload in payloads:
            try:
                response = await client.get(f"{test_url}{payload}")
            except Exception:
                continue

            if "root:" in response.body or "daemon:" in response.body:
                return [
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
                ]

            if "microsoft" in response.body.lower() and "localhost" in response.body.lower():
                return [
                    ScanResult(
                        title="Path Traversal (Windows)",
                        severity="critical",
                        description=(
                            "Path traversal vulnerability allowing access to Windows system files."
                        ),
                        url=test_url,
                        attack_type="Path Traversal",
                        evidence=f"Payload: {payload}",
                        remediation="Validate and sanitize file paths, use allowlists.",
                        confidence="high",
                    )
                ]

    return []


async def test_command_injection(client: HTTPClient, target: str) -> list[ScanResult]:
    """Test for command injection vulnerabilities."""
    payloads = ["; id", "; whoami", "| id", "| whoami", "` id `", "$(id)"]
    test_params = ["cmd", "exec", "command", "ping", "host", "ip"]

    for param in test_params:
        for payload in payloads:
            try:
                response = await client.get(f"{target}?{param}={payload}")
            except Exception:
                continue

            if "uid=" in response.body or "gid=" in response.body:
                return [
                    ScanResult(
                        title="Command Injection",
                        severity="critical",
                        description=f"Command injection vulnerability in parameter '{param}'.",
                        url=target,
                        attack_type="Command Injection",
                        evidence=f"Payload: {payload}",
                        remediation=(
                            "Never pass user input to system commands. Use parameterized APIs."
                        ),
                        confidence="high",
                    )
                ]

    return []


async def test_idor(
    client: HTTPClient,
    target: str,
    base_response: HTTPResponse,
) -> list[ScanResult]:
    """Test for IDOR vulnerabilities."""
    findings: list[ScanResult] = []
    id_patterns = [r"/[\?&](id|user_id|account|document|file)=(\d+)", r"/api/(\w+)/(\d+)"]

    for pattern in id_patterns:
        matches = re.findall(pattern, base_response.body)
        for param_name, current_id in matches:
            try:
                next_id = str(int(current_id) + 1)
                modified_url = base_response.url.replace(
                    f"{param_name}={current_id}",
                    f"{param_name}={next_id}",
                )
                test_response = await client.get(modified_url)
            except Exception:
                continue

            if test_response.status_code == 200 and len(test_response.body) > 0:
                findings.append(
                    ScanResult(
                        title="Potential IDOR",
                        severity="medium",
                        description=(
                            f"Potential IDOR vulnerability in parameter '{param_name}'. "
                            "Different ID returned valid response."
                        ),
                        url=target,
                        attack_type="IDOR",
                        evidence=f"Original ID: {current_id}, Tested ID: {next_id}",
                        remediation=(
                            "Implement proper authorization checks for all object access."
                        ),
                        confidence="low",
                    )
                )

    return findings
