"""Web crawler for mapping applications."""

import re
from urllib.parse import urljoin

from .client import HTTPClient


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
                links = re.findall(r'href=["\']([^"\']+)["\']', response.body)

                for link in links:
                    absolute_url = urljoin(url, link)

                    # Only crawl same domain
                    if absolute_url.startswith(self.base_url):
                        await self._crawl_recursive(client, absolute_url, depth + 1)

        except Exception:
            pass
