"""Request replay and modification utilities."""

import time
from typing import Any

import httpx

from clawpwn.modules.proxy.store import ProxyEntry


async def replay_request(
    entry: ProxyEntry,
    timeout: float = 30.0,
) -> ProxyEntry:
    """Re-send an intercepted request and return a new entry with the fresh response."""
    start = time.monotonic()
    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        response = await client.request(
            method=entry.method,
            url=entry.url,
            headers=entry.request_headers or None,
            content=entry.request_body.encode() if entry.request_body else None,
        )
    elapsed = time.monotonic() - start

    return ProxyEntry(
        method=entry.method,
        url=entry.url,
        request_headers=dict(entry.request_headers),
        request_body=entry.request_body,
        status_code=response.status_code,
        response_headers=dict(response.headers),
        response_body=response.text,
        response_time=round(elapsed, 4),
        tags=["replayed"],
        notes=f"Replayed from entry #{entry.id}",
    )


async def modify_and_send(
    entry: ProxyEntry,
    *,
    method: str = "",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = 30.0,
) -> ProxyEntry:
    """Modify fields of a captured request, send it, and return a new entry."""
    req_method = method or entry.method
    req_url = url or entry.url
    req_headers = headers if headers is not None else dict(entry.request_headers)
    req_body = body if body else entry.request_body

    start = time.monotonic()
    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        response = await client.request(
            method=req_method,
            url=req_url,
            headers=req_headers or None,
            content=req_body.encode() if req_body else None,
        )
    elapsed = time.monotonic() - start

    return ProxyEntry(
        method=req_method,
        url=req_url,
        request_headers=req_headers,
        request_body=req_body,
        status_code=response.status_code,
        response_headers=dict(response.headers),
        response_body=response.text,
        response_time=round(elapsed, 4),
        tags=["modified"],
        notes=f"Modified from entry #{entry.id}",
    )


def compare_responses(original: ProxyEntry, replayed: ProxyEntry) -> dict[str, Any]:
    """Return a diff summary between two proxy entries."""
    orig_keys = set(original.response_headers)
    replay_keys = set(replayed.response_headers)
    changed = [
        k
        for k in sorted(orig_keys & replay_keys)
        if original.response_headers[k] != replayed.response_headers[k]
    ]

    return {
        "status_changed": original.status_code != replayed.status_code,
        "original_status": original.status_code,
        "replayed_status": replayed.status_code,
        "body_length_original": len(original.response_body),
        "body_length_replayed": len(replayed.response_body),
        "body_changed": original.response_body != replayed.response_body,
        "time_original": original.response_time,
        "time_replayed": replayed.response_time,
        "headers_added": sorted(replay_keys - orig_keys),
        "headers_removed": sorted(orig_keys - replay_keys),
        "headers_changed": changed,
    }
