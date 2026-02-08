"""Tests for web search module."""

import pytest
import respx
from httpx import Response

from clawpwn.modules.websearch import SearchResult, web_search


class TestWebSearch:
    """Test web search functionality."""

    @pytest.mark.asyncio
    async def test_duckduckgo_search_success(self, monkeypatch):
        """Test successful DuckDuckGo search."""
        # Ensure no Tavily key
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        # Mock duckduckgo_search - need to mock it in the search module
        async def mock_search_duckduckgo(query, max_results):
            return [
                SearchResult(
                    title="Test Result 1", url="https://example.com/1", snippet="Test snippet 1"
                ),
                SearchResult(
                    title="Test Result 2", url="https://example.com/2", snippet="Test snippet 2"
                ),
            ]

        monkeypatch.setattr(
            "clawpwn.modules.websearch.search._search_duckduckgo", mock_search_duckduckgo
        )

        results = await web_search("test query", max_results=2)

        assert len(results) == 2
        assert results[0].title == "Test Result 1"
        assert results[0].url == "https://example.com/1"
        assert results[0].snippet == "Test snippet 1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_tavily_search_success(self, monkeypatch):
        """Test successful Tavily search when API key is set."""
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")

        # Mock Tavily API
        respx.post("https://api.tavily.com/search").mock(
            return_value=Response(
                200,
                json={
                    "results": [
                        {
                            "title": "Tavily Result 1",
                            "url": "https://example.com/1",
                            "content": "Tavily snippet 1",
                        },
                        {
                            "title": "Tavily Result 2",
                            "url": "https://example.com/2",
                            "content": "Tavily snippet 2",
                        },
                    ]
                },
            )
        )

        results = await web_search("test query", max_results=2)

        assert len(results) == 2
        assert results[0].title == "Tavily Result 1"
        assert results[0].url == "https://example.com/1"
        assert results[0].snippet == "Tavily snippet 1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_tavily_fallback_to_duckduckgo(self, monkeypatch):
        """Test fallback to DuckDuckGo when Tavily fails."""
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")

        # Mock Tavily API to fail
        respx.post("https://api.tavily.com/search").mock(
            return_value=Response(500, text="Server error")
        )

        # Mock DuckDuckGo fallback
        async def mock_search_duckduckgo(query, max_results):
            return [
                SearchResult(title="DDG Fallback", url="https://example.com", snippet="Fallback")
            ]

        monkeypatch.setattr(
            "clawpwn.modules.websearch.search._search_duckduckgo", mock_search_duckduckgo
        )

        results = await web_search("test query", max_results=1)

        assert len(results) == 1
        assert results[0].title == "DDG Fallback"

    @pytest.mark.asyncio
    async def test_search_result_dataclass(self):
        """Test SearchResult dataclass."""
        result = SearchResult(
            title="Test Title",
            url="https://example.com",
            snippet="Test snippet",
        )

        assert result.title == "Test Title"
        assert result.url == "https://example.com"
        assert result.snippet == "Test snippet"
