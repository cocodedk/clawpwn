"""Executors for reconnaissance and research tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run

_MAX_BODY_BYTES = 50_000


def execute_web_search(params: dict[str, Any], _project_dir: Path) -> str:
    """Execute web search and format results."""
    query = params.get("query", "")
    max_results = params.get("max_results", 5)

    if not query:
        return "Error: query parameter is required."

    from clawpwn.modules.websearch import web_search

    results = safe_async_run(web_search(query, max_results))

    if not results:
        return f"No results found for: {query}"

    output = [f"Web search results for '{query}':\n"]
    for i, result in enumerate(results, 1):
        output.append(f"{i}. {result.title}")
        output.append(f"   URL: {result.url}")
        output.append(f"   {result.snippet}\n")

    return "\n".join(output)


def execute_fingerprint_target(params: dict[str, Any], _project_dir: Path) -> str:
    """Execute target fingerprinting and format results."""
    target = params.get("target", "")

    if not target:
        return "Error: target parameter is required."

    from clawpwn.modules.recon import fingerprint_target

    result = safe_async_run(fingerprint_target(target))

    output = [f"Fingerprint results for {target}:\n"]

    if result.server:
        output.append(f"Server: {result.server}")

    if result.technologies:
        output.append(f"Technologies: {', '.join(result.technologies)}")

    if result.version_hints:
        output.append("Version hints:")
        for hint in result.version_hints:
            output.append(f"  - {hint}")

    if result.exposed_paths:
        output.append("Exposed paths:")
        for path in result.exposed_paths:
            output.append(f"  - {path}")

    if result.security_headers_missing:
        output.append("Missing security headers:")
        for header in result.security_headers_missing:
            output.append(f"  - {header}")

    if result.title:
        output.append(f"Page title: {result.title}")

    if result.error:
        output.append(f"\nError during fingerprinting: {result.error}")

    return "\n".join(output)


async def _fetch_url(
    url: str,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
) -> str:
    """Fetch a URL and return formatted response text."""
    from clawpwn.tools.http.client import HTTPClient

    data = None
    if body:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            data = {"_raw": body}

    async with HTTPClient() as client:
        resp = await client.request(method, url, headers=headers, data=data)

    content_type = resp.content_type or "unknown"
    response_body = resp.body
    truncated = ""
    if len(response_body) > _MAX_BODY_BYTES:
        response_body = response_body[:_MAX_BODY_BYTES]
        truncated = "\n[Truncated — response exceeded 50 KB]"

    return (
        f"HTTP {resp.status_code} {url}\nContent-Type: {content_type}\n\n{response_body}{truncated}"
    )


def execute_fetch_url(params: dict[str, Any], _project_dir: Path) -> str:
    """Fetch a URL and return the raw response body."""
    url = params.get("url", "")
    if not url:
        return "Error: url parameter is required."

    method = params.get("method", "GET").upper()
    headers = params.get("headers")
    body = params.get("body")

    return safe_async_run(_fetch_url(url, method, headers, body))
