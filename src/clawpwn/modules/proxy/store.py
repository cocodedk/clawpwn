"""Proxy request/response storage."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ProxyEntry:
    """Single intercepted request/response pair."""

    id: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Request
    method: str = "GET"
    url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""

    # Response
    status_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_time: float = 0.0

    # Metadata
    tags: list[str] = field(default_factory=list)
    notes: str = ""


class ProxyStore:
    """In-memory store for intercepted proxy traffic."""

    def __init__(self, max_entries: int = 5000):
        self._entries: list[ProxyEntry] = []
        self._next_id: int = 1
        self.max_entries = max_entries

    @property
    def entries(self) -> list[ProxyEntry]:
        """Return a shallow copy of all entries."""
        return list(self._entries)

    def add(self, entry: ProxyEntry) -> ProxyEntry:
        """Store an entry and assign it an auto-incremented id."""
        entry.id = self._next_id
        self._next_id += 1
        self._entries.append(entry)
        if len(self._entries) > self.max_entries:
            self._entries = self._entries[-self.max_entries :]
        return entry

    def get(self, entry_id: int) -> ProxyEntry | None:
        """Retrieve a single entry by id."""
        for entry in self._entries:
            if entry.id == entry_id:
                return entry
        return None

    def search(
        self,
        url_pattern: str = "",
        method: str = "",
        status_code: int | None = None,
        tag: str = "",
        body_contains: str = "",
    ) -> list[ProxyEntry]:
        """Filter entries by one or more criteria."""
        results = self._entries
        if url_pattern:
            results = [e for e in results if url_pattern in e.url]
        if method:
            results = [e for e in results if e.method.upper() == method.upper()]
        if status_code is not None:
            results = [e for e in results if e.status_code == status_code]
        if tag:
            results = [e for e in results if tag in e.tags]
        if body_contains:
            results = [e for e in results if body_contains in e.response_body]
        return results

    def tag(self, entry_id: int, tag: str) -> bool:
        """Add a tag to an entry.  Returns False if already tagged or not found."""
        entry = self.get(entry_id)
        if entry and tag not in entry.tags:
            entry.tags.append(tag)
            return True
        return False

    def annotate(self, entry_id: int, notes: str) -> bool:
        """Set notes on an entry.  Returns False if not found."""
        entry = self.get(entry_id)
        if entry:
            entry.notes = notes
            return True
        return False

    def clear(self) -> int:
        """Remove all entries.  Returns the count removed."""
        count = len(self._entries)
        self._entries.clear()
        self._next_id = 1
        return count

    def export(self) -> list[dict[str, Any]]:
        """Serialise entries to plain dicts (response bodies truncated to 500 chars)."""
        return [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "method": e.method,
                "url": e.url,
                "request_headers": e.request_headers,
                "request_body": e.request_body,
                "status_code": e.status_code,
                "response_headers": e.response_headers,
                "response_body": e.response_body[:500],
                "response_time": e.response_time,
                "tags": e.tags,
                "notes": e.notes,
            }
            for e in self._entries
        ]

    def __len__(self) -> int:
        return len(self._entries)
