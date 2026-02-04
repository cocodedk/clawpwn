"""HTTP helpers for ClawPwn."""

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx


@dataclass
class HTTPResponse:
    """Represents an HTTP response."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    cookies: dict[str, str]
    response_time: float
    content_type: str = ""
    server: str = ""


class HTTPClient:
    """Async HTTP client for pentesting operations."""

    def __init__(
        self,
        timeout: float = 30.0,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            verify=self.verify_ssl,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> HTTPResponse:
        """Make an HTTP request."""
        if not self.client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        import time

        start = time.time()

        response = await self.client.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            params=params,
        )

        elapsed = time.time() - start

        return HTTPResponse(
            url=str(response.url),
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text,
            cookies=dict(response.cookies),
            response_time=elapsed,
            content_type=response.headers.get("content-type", ""),
            server=response.headers.get("server", ""),
        )

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> HTTPResponse:
        """Make a GET request."""
        return await self.request("GET", url, headers=headers)

    async def post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HTTPResponse:
        """Make a POST request."""
        return await self.request("POST", url, headers=headers, data=data)

    async def check_robots_txt(self, base_url: str) -> str | None:
        """Check if robots.txt exists and return content."""
        url = urljoin(base_url, "/robots.txt")
        try:
            response = await self.get(url)
            if response.status_code == 200:
                return response.body
        except Exception:
            pass
        return None

    async def check_sitemap(self, base_url: str) -> str | None:
        """Check if sitemap.xml exists and return content."""
        url = urljoin(base_url, "/sitemap.xml")
        try:
            response = await self.get(url)
            if response.status_code == 200:
                return response.body
        except Exception:
            pass
        return None

    async def discover_endpoints(self, base_url: str) -> list[str]:
        """
        Discover common endpoints.

        Returns list of found URLs.
        """
        common_paths = [
            "/admin",
            "/login",
            "/api",
            "/docs",
            "/swagger",
            "/api/v1",
            "/graphql",
            "/.env",
            "/config",
            "/wp-admin",
            "/phpmyadmin",
            "/admin.php",
        ]

        found = []

        for path in common_paths:
            url = urljoin(base_url, path)
            try:
                response = await self.get(url)
                if response.status_code in [200, 301, 302, 401, 403]:
                    found.append(url)
            except Exception:
                continue

        return found


class WebCrawler:
    """Simple web crawler for mapping applications."""

    def __init__(self, base_url: str, max_depth: int = 2, max_pages: int = 50):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: set = set()
        self.found_urls: list[str] = []

    async def crawl(self) -> list[str]:
        """Crawl the website and return found URLs."""
        async with HTTPClient() as client:
            await self._crawl_recursive(client, self.base_url, 0)

        return self.found_urls

    async def _crawl_recursive(self, client: HTTPClient, url: str, depth: int):
        """Recursively crawl URLs."""
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return

        if url in self.visited:
            return

        self.visited.add(url)

        try:
            response = await client.get(url)

            if response.status_code == 200:
                self.found_urls.append(url)

                # Extract links (simple regex-based)
                import re

                links = re.findall(r'href=["\']([^"\']+)["\']', response.body)

                for link in links:
                    absolute_url = urljoin(url, link)

                    # Only crawl same domain
                    if absolute_url.startswith(self.base_url):
                        await self._crawl_recursive(client, absolute_url, depth + 1)

        except Exception:
            pass


async def check_headers(url: str) -> dict[str, Any]:
    """Check security headers of a URL."""
    security_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    async with HTTPClient() as client:
        response = await client.get(url)

    results = {
        "url": url,
        "status_code": response.status_code,
        "server": response.server,
        "missing_headers": [],
        "present_headers": {},
    }

    # Headers may be lowercase in response, so check case-insensitively
    response_headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for header in security_headers:
        if header.lower() in response_headers_lower:
            results["present_headers"][header] = response_headers_lower[header.lower()]
        else:
            results["missing_headers"].append(header)

    return results
