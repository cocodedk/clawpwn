"""Search helpers for vulnerability databases."""

from urllib.parse import quote

from .models import CVEInfo, ExploitInfo


class ClientSearchMixin:
    """Provide network search methods across exploit and CVE sources."""

    async def search_by_keyword(self, keyword: str, max_results: int = 10) -> list[ExploitInfo]:
        """Search for exploits by keyword."""
        exploits: list[ExploitInfo] = []
        exploits.extend(await self._search_exploitdb(keyword, max_results // 2))
        exploits.extend(await self._search_github(keyword, max_results // 2))
        return exploits[:max_results]

    async def search_by_cve(self, cve_id: str) -> CVEInfo | None:
        """Search for CVE information by ID."""
        return await self._query_nvd(cve_id)

    async def search_by_version(self, product: str, version: str) -> list[CVEInfo]:
        """Search for CVEs affecting a specific product version."""
        return await self._query_nvd_by_version(product, version)

    async def find_exploits(self, service_name: str, version: str = "") -> list[ExploitInfo]:
        """Find exploits for a specific service."""
        search_term = f"{service_name} {version}".strip()
        return await self.search_by_keyword(search_term)

    async def _search_exploitdb(self, keyword: str, max_results: int = 5) -> list[ExploitInfo]:
        """Search ExploitDB via GitHub API."""
        try:
            query = quote(f"{keyword} exploit")
            url = f"https://api.github.com/search/code?q={query}+repo:offensive-security/exploitdb"
            response = self.client.get(url)
            if response.status_code != 200:
                return []

            items = response.json().get("items", [])[:max_results]
            return [
                ExploitInfo(
                    title=item.get("name", "Unknown"),
                    source="exploitdb",
                    url=item.get("html_url", ""),
                    description=item.get("repository", {}).get("description", ""),
                    reliability="medium",
                )
                for item in items
            ]
        except Exception:
            return []

    async def _search_github(self, keyword: str, max_results: int = 5) -> list[ExploitInfo]:
        """Search GitHub repositories for exploit PoCs."""
        try:
            query = quote(f"{keyword} exploit poc")
            url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc"
            response = self.client.get(url)
            if response.status_code != 200:
                return []

            items = response.json().get("items", [])[:max_results]
            return [
                ExploitInfo(
                    title=item.get("full_name", "Unknown"),
                    source="github",
                    url=item.get("html_url", ""),
                    description=item.get("description", ""),
                    tags=item.get("topics", []),
                    reliability="unknown",
                )
                for item in items
            ]
        except Exception:
            return []

    async def _query_nvd(self, cve_id: str) -> CVEInfo | None:
        """Query NVD for CVE details by ID."""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = self.client.get(url)
            if response.status_code != 200:
                return None

            vulnerabilities = response.json().get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            cve = vulnerabilities[0].get("cve", {})
            cvss = _extract_cvss(cve)
            return CVEInfo(
                cve_id=cve_id,
                description=cve.get("descriptions", [{}])[0].get("value", ""),
                severity=cvss.get("baseSeverity", "UNKNOWN"),
                cvss_score=cvss.get("baseScore", 0.0),
                published_date=cve.get("published", ""),
                references=[ref.get("url", "") for ref in cve.get("references", [])],
            )
        except Exception:
            return None

    async def _query_nvd_by_version(self, product: str, version: str) -> list[CVEInfo]:
        """Query NVD for CVEs matching a product version keyword."""
        try:
            keyword = quote(f"{product} {version}")
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
            response = self.client.get(url)
            if response.status_code != 200:
                return []

            results: list[CVEInfo] = []
            for vuln in response.json().get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cvss = _extract_cvss(cve)
                results.append(
                    CVEInfo(
                        cve_id=cve.get("id", ""),
                        description=cve.get("descriptions", [{}])[0].get("value", ""),
                        severity=cvss.get("baseSeverity", "UNKNOWN"),
                        cvss_score=cvss.get("baseScore", 0.0),
                        published_date=cve.get("published", ""),
                        references=[ref.get("url", "") for ref in cve.get("references", [])],
                    )
                )
            return results
        except Exception:
            return []


def _extract_cvss(cve: dict) -> dict:
    """Extract CVSS v3.1 data from NVD CVE payload."""
    metrics = cve.get("metrics", {})
    cvss_metric = metrics.get("cvssMetricV31", [{}])[0]
    return cvss_metric.get("cvssData", {}) if cvss_metric else {}
