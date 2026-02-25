"""Caching helpers for vulnerability lookup results."""

import json

from .models import ExploitInfo


class ClientCacheMixin:
    """Provide local filesystem caching for exploit search results."""

    def cache_exploits(self, service: str, exploits: list[ExploitInfo]) -> None:
        """Cache exploit results locally."""
        cache_file = self.cache_dir / f"{service.replace(' ', '_')}.json"
        data = [
            {
                "title": exploit.title,
                "source": exploit.source,
                "cve_id": exploit.cve_id,
                "url": exploit.url,
                "description": exploit.description,
            }
            for exploit in exploits
        ]
        with cache_file.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def get_cached_exploits(self, service: str) -> list[ExploitInfo]:
        """Get cached exploits for a service."""
        cache_file = self.cache_dir / f"{service.replace(' ', '_')}.json"
        if not cache_file.exists():
            return []

        try:
            with cache_file.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            return []

        return [
            ExploitInfo(
                title=item.get("title", ""),
                source=item.get("source", ""),
                cve_id=item.get("cve_id", ""),
                url=item.get("url", ""),
                description=item.get("description", ""),
            )
            for item in data
        ]
