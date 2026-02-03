"""Vulnerability Database integration for ClawPwn.

Integrates with ExploitDB, CVE databases, and GitHub to search for
exploits and vulnerabilities related to discovered services.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import quote

import httpx


@dataclass
class ExploitInfo:
    """Represents a found exploit."""

    title: str
    source: str  # exploitdb, github, cve
    cve_id: str = ""
    edb_id: str = ""  # ExploitDB ID
    url: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    reliability: str = "unknown"  # high, medium, low, unknown
    verified: bool = False


@dataclass
class CVEInfo:
    """Represents CVE information."""

    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float = 0.0
    published_date: str = ""
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""


class VulnDBClient:
    """Client for querying vulnerability databases."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path.home() / ".clawpwn" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.client = httpx.Client(timeout=30.0)

    def __del__(self):
        self.client.close()

    async def search_by_keyword(
        self, keyword: str, max_results: int = 10
    ) -> List[ExploitInfo]:
        """
        Search for exploits by keyword.

        Args:
            keyword: Search term (e.g., "apache", "nginx", "wordpress")
            max_results: Maximum number of results to return

        Returns:
            List of exploit information
        """
        exploits = []

        # Search ExploitDB
        edb_results = await self._search_exploitdb(keyword, max_results // 2)
        exploits.extend(edb_results)

        # Search GitHub for PoCs
        github_results = await self._search_github(keyword, max_results // 2)
        exploits.extend(github_results)

        return exploits[:max_results]

    async def search_by_cve(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Search for CVE information.

        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228")

        Returns:
            CVE information or None if not found
        """
        return await self._query_nvd(cve_id)

    async def search_by_version(self, product: str, version: str) -> List[CVEInfo]:
        """
        Search for CVEs affecting a specific product version.

        Args:
            product: Product name (e.g., "apache", "nginx")
            version: Version string (e.g., "1.18.0")

        Returns:
            List of CVEs affecting this version
        """
        return await self._query_nvd_by_version(product, version)

    async def find_exploits(
        self, service_name: str, version: str = ""
    ) -> List[ExploitInfo]:
        """
        Find exploits for a specific service.

        Args:
            service_name: Service name (e.g., "apache", "nginx")
            version: Optional version string

        Returns:
            List of available exploits
        """
        search_term = f"{service_name} {version}".strip()
        return await self.search_by_keyword(search_term)

    async def _search_exploitdb(
        self, keyword: str, max_results: int = 5
    ) -> List[ExploitInfo]:
        """Search ExploitDB for exploits."""
        exploits = []

        try:
            # Search via ExploitDB GitHub repository or API
            # Using GitHub search for ExploitDB
            query = quote(f"{keyword} exploit")
            url = f"https://api.github.com/search/code?q={query}+repo:offensive-security/exploitdb"

            response = self.client.get(url)

            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])[:max_results]

                for item in items:
                    exploit = ExploitInfo(
                        title=item.get("name", "Unknown"),
                        source="exploitdb",
                        url=item.get("html_url", ""),
                        description=item.get("repository", {}).get("description", ""),
                        reliability="medium",
                    )
                    exploits.append(exploit)

        except Exception:
            # If API fails, return empty list
            pass

        return exploits

    async def _search_github(
        self, keyword: str, max_results: int = 5
    ) -> List[ExploitInfo]:
        """Search GitHub for PoC exploits."""
        exploits = []

        try:
            # Search for repositories
            query = quote(f"{keyword} exploit poc")
            url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc"

            response = self.client.get(url)

            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])[:max_results]

                for item in items:
                    exploit = ExploitInfo(
                        title=item.get("full_name", "Unknown"),
                        source="github",
                        url=item.get("html_url", ""),
                        description=item.get("description", ""),
                        tags=item.get("topics", []),
                        reliability="unknown",
                    )
                    exploits.append(exploit)

        except Exception:
            pass

        return exploits

    async def _query_nvd(self, cve_id: str) -> Optional[CVEInfo]:
        """Query NVD (National Vulnerability Database) for CVE details."""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = self.client.get(url)

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if vulnerabilities:
                    vuln = vulnerabilities[0]
                    cve = vuln.get("cve", {})

                    # Get metrics
                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", [{}])[0]
                    cvss = cvss_data.get("cvssData", {}) if cvss_data else {}

                    return CVEInfo(
                        cve_id=cve_id,
                        description=cve.get("descriptions", [{}])[0].get("value", ""),
                        severity=cvss.get("baseSeverity", "UNKNOWN"),
                        cvss_score=cvss.get("baseScore", 0.0),
                        published_date=cve.get("published", ""),
                        references=[
                            ref.get("url", "") for ref in cve.get("references", [])
                        ],
                    )

        except Exception:
            pass

        return None

    async def _query_nvd_by_version(self, product: str, version: str) -> List[CVEInfo]:
        """Query NVD for CVEs affecting a product version."""
        cves = []

        try:
            # Search for CVEs
            keyword = quote(f"{product} {version}")
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"

            response = self.client.get(url)

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Get metrics
                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", [{}])[0]
                    cvss = cvss_data.get("cvssData", {}) if cvss_data else {}

                    cve_info = CVEInfo(
                        cve_id=cve_id,
                        description=cve.get("descriptions", [{}])[0].get("value", ""),
                        severity=cvss.get("baseSeverity", "UNKNOWN"),
                        cvss_score=cvss.get("baseScore", 0.0),
                        published_date=cve.get("published", ""),
                        references=[
                            ref.get("url", "") for ref in cve.get("references", [])
                        ],
                    )
                    cves.append(cve_info)

        except Exception:
            pass

        return cves

    def cache_exploits(self, service: str, exploits: List[ExploitInfo]) -> None:
        """Cache exploit results locally."""
        cache_file = self.cache_dir / f"{service.replace(' ', '_')}.json"

        data = [
            {
                "title": e.title,
                "source": e.source,
                "cve_id": e.cve_id,
                "url": e.url,
                "description": e.description,
            }
            for e in exploits
        ]

        with open(cache_file, "w") as f:
            json.dump(data, f, indent=2)

    def get_cached_exploits(self, service: str) -> List[ExploitInfo]:
        """Get cached exploits for a service."""
        cache_file = self.cache_dir / f"{service.replace(' ', '_')}.json"

        if not cache_file.exists():
            return []

        try:
            with open(cache_file) as f:
                data = json.load(f)

            return [
                ExploitInfo(
                    title=e.get("title", ""),
                    source=e.get("source", ""),
                    cve_id=e.get("cve_id", ""),
                    url=e.get("url", ""),
                    description=e.get("description", ""),
                )
                for e in data
            ]

        except Exception:
            return []


class VulnDB:
    """High-level vulnerability database interface."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.client = VulnDBClient(cache_dir)

    async def research_service(
        self, service_name: str, version: str, project_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Research a service for vulnerabilities.

        Args:
            service_name: Service name (e.g., "apache", "nginx")
            version: Service version
            project_dir: Optional project directory for caching

        Returns:
            Dictionary with CVEs and exploits found
        """
        print(f"[*] Researching {service_name} {version}...")

        # Check cache first
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

        # Query NVD for CVEs
        cves = await self.client.search_by_version(service_name, version)
        print(f"[+] Found {len(cves)} CVEs")

        # Search for exploits
        exploits = await self.client.find_exploits(service_name, version)
        print(f"[+] Found {len(exploits)} exploits")

        # Cache results
        self.client.cache_exploits(cache_key, exploits)

        return {
            "service": service_name,
            "version": version,
            "cves": cves,
            "exploits": exploits,
            "from_cache": False,
        }

    def print_research_summary(self, results: Dict[str, Any]) -> None:
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

            # Group by severity
            by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
            for cve in cves:
                sev = cve.severity.upper()
                if sev in by_severity:
                    by_severity[sev].append(cve)

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if by_severity[severity]:
                    print(f"\n  {severity} ({len(by_severity[severity])}):")
                    for cve in by_severity[severity][:3]:
                        print(f"    • {cve.cve_id} (CVSS: {cve.cvss_score})")

        if exploits:
            print(f"\nExploits Available ({len(exploits)}):")
            for exploit in exploits[:5]:
                print(f"  • [{exploit.source.upper()}] {exploit.title}")

            if len(exploits) > 5:
                print(f"  ... and {len(exploits) - 5} more")

        print("=" * 60)


# Convenience function
async def quick_research(service: str, version: str) -> Dict[str, Any]:
    """Quick vulnerability research for a service."""
    vulndb = VulnDB()
    return await vulndb.research_service(service, version)
