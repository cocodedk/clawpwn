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
        self.active_scanner = ActiveScanner(project_dir)
        self.session = load_session(project_dir)

    async def scan(self, target: str, config: ScanConfig | None = None) -> list[ScanResult]:
        """Run a complete scan (passive + active)."""
        config = config or ScanConfig(target=target)
        all_findings: list[ScanResult] = []

        print(f"[*] Starting scan of {target}")
        print("[*] Running passive scan...")
        async with HTTPClient() as client:
            response = await client.get(target)
            all_findings.extend(await self.passive_scanner.scan_response(response))

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

        print(f"[+] Scan complete. {len(all_findings)} findings.")
        self._print_findings_summary(all_findings)
        return all_findings

    def _print_findings_summary(self, findings: list[ScanResult]) -> None:
        print_findings_summary(findings)


async def quick_scan(target: str, project_dir: Path | None = None) -> list[ScanResult]:
    """Quick scan of a target."""
    scanner = Scanner(project_dir)
    return await scanner.scan(target, ScanConfig(target=target, depth="quick"))
