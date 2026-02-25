"""Scanner output helpers."""

from .models import ScanResult


def print_findings_summary(findings: list[ScanResult]) -> None:
    """Print a summary of findings."""
    if not findings:
        print("\n[+] No vulnerabilities found.")
        return

    print("\n" + "=" * 60)
    print("SCAN RESULTS SUMMARY")
    print("=" * 60)

    severity_order = ["critical", "high", "medium", "low", "info"]
    by_severity = {severity: [] for severity in severity_order}

    for finding in findings:
        severity = finding.severity.lower()
        if severity in by_severity:
            by_severity[severity].append(finding)

    total = len(findings)
    critical = len(by_severity["critical"])
    high = len(by_severity["high"])
    print(f"\nTotal: {total} | Critical: {critical} | High: {high}")

    for severity in severity_order:
        scoped = by_severity[severity]
        if not scoped:
            continue

        print(f"\n{severity.upper()} ({len(scoped)}):")
        for finding in scoped[:5]:
            print(f"  • {finding.title} - {finding.attack_type}")
        if len(scoped) > 5:
            print(f"  ... and {len(scoped) - 5} more")

    print("=" * 60)
