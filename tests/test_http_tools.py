"""Tests for HTTP tools module."""

import respx
from httpx import Response

from clawpwn.tools.http import HTTPClient, HTTPResponse, WebCrawler, check_headers


class TestHTTPClient:
    """Test HTTPClient functionality."""

    @respx.mock
    async def test_get_request(self):
        """Test basic GET request."""
        respx.get("https://example.com").mock(return_value=Response(200, text="Hello World"))

        async with HTTPClient() as client:
            response = await client.get("https://example.com")

        assert response.status_code == 200
        assert response.body == "Hello World"
        assert response.url == "https://example.com"

    @respx.mock
    async def test_post_request(self):
        """Test POST request."""
        respx.post("https://example.com/api").mock(return_value=Response(201, text="Created"))

        async with HTTPClient() as client:
            response = await client.post("https://example.com/api", data={"key": "value"})

        assert response.status_code == 201

    @respx.mock
    async def test_response_headers(self):
        """Test that response headers are captured."""
        respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="OK",
                headers={
                    "Content-Type": "text/html",
                    "Server": "nginx/1.18.0",
                    "X-Frame-Options": "SAMEORIGIN",
                },
            )
        )

        async with HTTPClient() as client:
            response = await client.get("https://example.com")

        # Headers may be normalized to lowercase by httpx - check both cases
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        assert headers_lower.get("content-type") == "text/html"
        assert headers_lower.get("server") == "nginx/1.18.0"
        assert response.server == "nginx/1.18.0"

    @respx.mock
    async def test_cookies_preserved(self):
        """Test that cookies are preserved."""
        respx.get("https://example.com").mock(
            return_value=Response(200, text="OK", headers={"Set-Cookie": "session=abc123; Path=/"})
        )

        async with HTTPClient() as client:
            response = await client.get("https://example.com")

        assert "session" in response.cookies

    @respx.mock
    async def test_check_robots_txt_exists(self):
        """Test robots.txt check when file exists."""
        respx.get("https://example.com/robots.txt").mock(
            return_value=Response(200, text="User-agent: *\nDisallow: /admin")
        )

        async with HTTPClient() as client:
            content = await client.check_robots_txt("https://example.com")

        assert content is not None
        assert "User-agent" in content

    @respx.mock
    async def test_check_robots_txt_missing(self):
        """Test robots.txt check when file doesn't exist."""
        respx.get("https://example.com/robots.txt").mock(
            return_value=Response(404, text="Not Found")
        )

        async with HTTPClient() as client:
            content = await client.check_robots_txt("https://example.com")

        assert content is None

    @respx.mock
    async def test_discover_endpoints(self):
        """Test endpoint discovery."""
        # Mock various endpoints
        respx.get("https://example.com/admin").mock(return_value=Response(200))
        respx.get("https://example.com/login").mock(return_value=Response(200))
        respx.get("https://example.com/api").mock(return_value=Response(404))
        respx.get("https://example.com/.env").mock(return_value=Response(403))

        async with HTTPClient() as client:
            endpoints = await client.discover_endpoints("https://example.com")

        # Should find admin, login, and .env (403 means it exists)
        assert len(endpoints) >= 2
        assert any("admin" in url for url in endpoints)
        assert any("login" in url for url in endpoints)


class TestWebCrawler:
    """Test WebCrawler functionality."""

    @respx.mock
    async def test_crawl_basic(self):
        """Test basic crawling."""
        # Mock the base URL
        respx.get("https://example.com").mock(
            return_value=Response(200, text='<html><body><a href="/page1">Page 1</a></body></html>')
        )

        # Mock discovered pages
        respx.get("https://example.com/page1").mock(
            return_value=Response(200, text="<html><body>Page 1</body></html>")
        )

        crawler = WebCrawler("https://example.com", max_depth=1, max_pages=10)
        urls = await crawler.crawl()

        assert isinstance(urls, list)
        assert len(urls) > 0

    @respx.mock
    async def test_crawl_respects_max_depth(self):
        """Test that crawler respects max depth."""
        # Setup mock responses with nested links
        respx.get("https://example.com").mock(
            return_value=Response(
                200, text='<html><body><a href="/level1">Level 1</a></body></html>'
            )
        )
        respx.get("https://example.com/level1").mock(
            return_value=Response(
                200, text='<html><body><a href="/level2">Level 2</a></body></html>'
            )
        )
        respx.get("https://example.com/level2").mock(
            return_value=Response(200, text="<html><body>Level 2</body></html>")
        )

        # Crawl with max_depth=1
        crawler = WebCrawler("https://example.com", max_depth=1, max_pages=10)
        urls = await crawler.crawl()

        # Should only find base and level1
        assert "https://example.com" in urls
        assert "https://example.com/level1" in urls

    @respx.mock
    async def test_crawl_respects_max_pages(self):
        """Test that crawler respects max pages limit."""
        # Create many links
        links = " ".join([f'<a href="/page{i}">Page {i}</a>' for i in range(100)])
        respx.get("https://example.com").mock(
            return_value=Response(200, text=f"<html><body>{links}</body></html>")
        )

        # Crawl with max_pages=5
        crawler = WebCrawler("https://example.com", max_depth=2, max_pages=5)
        urls = await crawler.crawl()

        # Should not exceed max_pages
        assert len(urls) <= 5


class TestCheckHeaders:
    """Test security header checking."""

    @respx.mock
    async def test_check_headers_finds_missing(self):
        """Test detection of missing security headers."""
        respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="OK",
                headers={
                    "Content-Type": "text/html",
                    # Missing most security headers
                },
            )
        )

        results = await check_headers("https://example.com")

        assert results["status_code"] == 200
        assert len(results["missing_headers"]) > 0
        # Check for expected missing headers (case insensitive)
        missing_lower = [h.lower() for h in results["missing_headers"]]
        assert "x-frame-options" in missing_lower

    @respx.mock
    async def test_check_headers_finds_present(self):
        """Test that present headers are noted."""
        respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="OK",
                headers={
                    "Server": "nginx",
                    "X-Frame-Options": "SAMEORIGIN",
                    "X-Content-Type-Options": "nosniff",
                    "Strict-Transport-Security": "max-age=31536000",
                },
            )
        )

        results = await check_headers("https://example.com")

        # Check present headers using case insensitive matching
        present_lower = {k.lower(): v for k, v in results["present_headers"].items()}
        assert "x-frame-options" in present_lower
        assert "x-content-type-options" in present_lower


class TestHTTPResponse:
    """Test HTTPResponse dataclass."""

    def test_response_creation(self):
        """Test creating an HTTPResponse."""
        response = HTTPResponse(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html>Test</html>",
            cookies={"session": "abc123"},
            response_time=0.5,
            content_type="text/html",
            server="nginx",
        )

        assert response.url == "https://example.com"
        assert response.status_code == 200
        assert response.response_time == 0.5

    def test_response_defaults(self):
        """Test HTTPResponse default values."""
        response = HTTPResponse(
            url="https://example.com",
            status_code=200,
            headers={},
            body="",
            cookies={},
            response_time=0.0,
        )

        assert response.content_type == ""
        assert response.server == ""
