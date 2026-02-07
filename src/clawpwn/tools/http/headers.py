"""Security headers checking utilities."""

from typing import Any

from .client import HTTPClient


async def check_headers(url: str) -> dict[str, Any]:
    """Check security headers of a URL."""
    security_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    async with HTTPClient() as client:
        response = await client.get(url)

    results = {
        "url": url,
        "status_code": response.status_code,
        "server": response.server,
        "missing_headers": [],
        "present_headers": {},
    }

    # Headers may be lowercase in response, so check case-insensitively
    response_headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for header in security_headers:
        if header.lower() in response_headers_lower:
            results["present_headers"][header] = response_headers_lower[header.lower()]
        else:
            results["missing_headers"].append(header)

    return results
