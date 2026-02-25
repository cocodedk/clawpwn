"""Executors for reconnaissance and research tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run


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
