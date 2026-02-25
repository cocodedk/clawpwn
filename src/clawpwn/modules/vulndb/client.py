"""Primary vulnerability database client."""

from pathlib import Path

import httpx

from .client_cache_mixin import ClientCacheMixin
from .client_search_mixin import ClientSearchMixin


class VulnDBClient(ClientSearchMixin, ClientCacheMixin):
    """Client for querying vulnerability databases."""

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or Path.home() / ".clawpwn" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.client = httpx.Client(timeout=30.0)

    def __del__(self):
        self.client.close()
