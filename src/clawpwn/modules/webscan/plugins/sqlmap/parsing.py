"""sqlmap output parsing utilities."""

from __future__ import annotations

from ...models import WebScanFinding

# Injection type -> severity mapping
_INJECTION_SEVERITY: dict[str, str] = {
    "union": "critical",
    "stacked": "critical",
    "error": "high",
    "boolean": "high",
    "time": "high",
    "inline": "medium",
}


def severity_for_technique(technique: str) -> str:
    """Map sqlmap technique text to platform severity."""
    lowered = technique.lower()
    for key, sev in _INJECTION_SEVERITY.items():
        if key in lowered:
            return sev
    return "high"


def parse_output(stdout: str, stderr: str, target: str, tool_name: str) -> list[WebScanFinding]:
    """Parse sqlmap stdout/stderr for injection point summaries."""
    findings: list[WebScanFinding] = []
    current_param: str | None = None
    for raw_line in (stdout + "\n" + stderr).splitlines():
        line = raw_line.strip()
        if line.startswith("Parameter:"):
            current_param = line.replace("Parameter:", "").strip()
            continue

        if line.startswith("Type:") and current_param:
            technique = line.replace("Type:", "").strip()
            title_text = technique or "SQL Injection"
            findings.append(
                WebScanFinding(
                    tool=tool_name,
                    title=f"SQL Injection ({title_text}): {current_param}",
                    severity=severity_for_technique(technique),
                    description=(
                        f"sqlmap detected {technique} SQL injection on parameter '{current_param}'."
                    ),
                    url=target,
                    attack_type="SQL Injection",
                    evidence=f"Parameter: {current_param}, Type: {technique}",
                    raw={"parameter": current_param, "type": technique},
                )
            )

    return findings


def dedupe_findings(findings: list[WebScanFinding]) -> list[WebScanFinding]:
    """Deduplicate findings by core identity."""
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


def is_timeout_error(exc: Exception) -> bool:
    """Return True when a command exception indicates timeout."""
    return "timed out" in str(exc).lower()
