"""Main scanner orchestration."""

from pathlib import Path

from clawpwn.tools.http import HTTPClient

from .active import ActiveScanner
from .models import ScanConfig, ScanResult
from .passive import PassiveScanner
from .reporting import print_findings_summary
from .shared import load_session


class Scanner:
    """Main scanner class that combines passive and active scanning."""

    def __init__(self, project_dir: Path | None = None):
        self.project_dir = project_dir
        self.passive_scanner = PassiveScanner(project_dir)
        self.session = load_session(project_dir)

        from clawpwn.modules.experience import ExperienceManager

        self.experience = ExperienceManager()
        self.active_scanner = ActiveScanner(project_dir, self.experience)

    async def scan(self, target: str, config: ScanConfig | None = None) -> list[ScanResult]:
        """Run a complete scan (passive + active)."""
        config = config or ScanConfig(target=target)
        all_findings: list[ScanResult] = []

        print(f"[*] Starting scan of {target}")
        print("[*] Running passive scan...")
        tech_stack = None
        async with HTTPClient() as client:
            response = await client.get(target)
            all_findings.extend(await self.passive_scanner.scan_response(response))
            tech_stack = self.passive_scanner.extract_tech(response)

        print("[*] Running active scan...")
        all_findings.extend(
            await self.active_scanner.scan_target(target, config.depth, config.scan_types)
        )

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

        domain = self.experience.domain_from_url(target)
        _record_experience(self.experience, all_findings, domain, tech_stack)

        print(f"[+] Scan complete. {len(all_findings)} findings.")
        self._print_findings_summary(all_findings)
        return all_findings

    def _print_findings_summary(self, findings: list[ScanResult]) -> None:
        print_findings_summary(findings)


def _record_experience(exp, findings: list[ScanResult], domain: str, tech: str | None) -> None:
    """Record scan results into the experience DB."""
    if exp is None:
        return
    seen: set[str] = set()
    for f in findings:
        ct = f.attack_type.lower().replace(" ", "_")
        seen.add(ct)
        payload = _extract_payload(f.evidence)
        exp.record(ct, domain, "vulnerable", f.confidence, payload, tech, f.title)
    for ct in ["sql_injection", "xss", "path_traversal", "command_injection"]:
        if ct not in seen:
            exp.record(ct, domain, "not_vulnerable", "high", tech=tech)


def _extract_payload(evidence: str) -> str | None:
    """Pull the payload value from evidence text like 'Payload: ...'."""
    if not evidence:
        return None
    for line in evidence.splitlines():
        if line.strip().lower().startswith("payload:"):
            return line.split(":", 1)[1].strip()
    return None


async def quick_scan(target: str, project_dir: Path | None = None) -> list[ScanResult]:
    """Quick scan of a target."""
    scanner = Scanner(project_dir)
    return await scanner.scan(target, ScanConfig(target=target, depth="quick"))
