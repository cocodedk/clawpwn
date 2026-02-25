"""Web search implementation with DuckDuckGo and Tavily backends."""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass
class SearchResult:
    """Web search result."""

    title: str
    url: str
    snippet: str


async def web_search(query: str, max_results: int = 5) -> list[SearchResult]:
    """Search the web for security research and attack techniques.

    Uses Tavily API if TAVILY_API_KEY is set, otherwise falls back to DuckDuckGo.
    """
    tavily_key = os.environ.get("TAVILY_API_KEY")
    if tavily_key:
        return await _search_tavily(query, max_results, tavily_key)
    return await _search_duckduckgo(query, max_results)


async def _search_tavily(query: str, max_results: int, api_key: str) -> list[SearchResult]:
    """Search using Tavily API (AI-optimized results)."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.tavily.com/search",
                json={
                    "api_key": api_key,
                    "query": query,
                    "search_depth": "basic",
                    "max_results": max_results,
                },
            )
            response.raise_for_status()
            data = response.json()
            results = []
            for item in data.get("results", [])[:max_results]:
                results.append(
                    SearchResult(
                        title=item.get("title", ""),
                        url=item.get("url", ""),
                        snippet=item.get("content", ""),
                    )
                )
            return results
    except Exception as e:
        # Fall back to DuckDuckGo on error
        print(f"[!] Tavily search failed ({e}), falling back to DuckDuckGo")
        return await _search_duckduckgo(query, max_results)


async def _search_duckduckgo(query: str, max_results: int) -> list[SearchResult]:
    """Search using DuckDuckGo (free, no API key required)."""
    try:
        from ddgs import DDGS
    except ImportError:
        return [
            SearchResult(
                title="DuckDuckGo Search Unavailable",
                url="",
                snippet="Install ddgs: pip install ddgs",
            )
        ]

    try:
        ddgs = DDGS()
        results = []
        for item in ddgs.text(query, max_results=max_results):
            results.append(
                SearchResult(
                    title=item.get("title", ""),
                    url=item.get("href", ""),
                    snippet=item.get("body", ""),
                )
            )
        return results[:max_results]
    except Exception as e:
        return [
            SearchResult(
                title="Search Failed",
                url="",
                snippet=f"DuckDuckGo search error: {e}",
            )
        ]
