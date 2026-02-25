"""High-level vulnerability research orchestration."""

from pathlib import Path
from typing import Any

from .client import VulnDBClient


class VulnDB:
    """High-level vulnerability database interface."""

    def __init__(self, cache_dir: Path | None = None):
        self.client = VulnDBClient(cache_dir)

    async def research_service(
        self,
        service_name: str,
        version: str,
        project_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Research a service for vulnerabilities and exploit references."""
        _ = project_dir
        print(f"[*] Researching {service_name} {version}...")

        cache_key = f"{service_name}_{version}"
        cached = self.client.get_cached_exploits(cache_key)
        if cached:
            print(f"[+] Using cached results for {service_name}")
            return {
                "service": service_name,
                "version": version,
                "cves": [],
                "exploits": cached,
                "from_cache": True,
            }

        cves = await self.client.search_by_version(service_name, version)
        print(f"[+] Found {len(cves)} CVEs")

        exploits = await self.client.find_exploits(service_name, version)
        print(f"[+] Found {len(exploits)} exploits")

        self.client.cache_exploits(cache_key, exploits)
        return {
            "service": service_name,
            "version": version,
            "cves": cves,
            "exploits": exploits,
            "from_cache": False,
        }

    def print_research_summary(self, results: dict[str, Any]) -> None:
        """Print a summary of vulnerability research."""
        service = results.get("service", "Unknown")
        version = results.get("version", "")
        cves = results.get("cves", [])
        exploits = results.get("exploits", [])

        print("\n" + "=" * 60)
        print(f"VULNERABILITY RESEARCH: {service} {version}")
        print("=" * 60)

        if cves:
            print(f"\nCVEs Found ({len(cves)}):")
            by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
            for cve in cves:
                severity = str(cve.severity).upper()
                if severity in by_severity:
                    by_severity[severity].append(cve)

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                scoped = by_severity[severity]
                if not scoped:
                    continue
                print(f"\n  {severity} ({len(scoped)}):")
                for cve in scoped[:3]:
                    print(f"    • {cve.cve_id} (CVSS: {cve.cvss_score})")

        if exploits:
            print(f"\nExploits Available ({len(exploits)}):")
            for exploit in exploits[:5]:
                print(f"  • [{exploit.source.upper()}] {exploit.title}")
            if len(exploits) > 5:
                print(f"  ... and {len(exploits) - 5} more")

        print("=" * 60)


async def quick_research(service: str, version: str) -> dict[str, Any]:
    """Quick vulnerability research for a service."""
    vulndb = VulnDB()
    return await vulndb.research_service(service, version)
