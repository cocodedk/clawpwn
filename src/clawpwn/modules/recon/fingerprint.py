"""Target fingerprinting and reconnaissance."""

from __future__ import annotations

import re
from dataclasses import dataclass

from clawpwn.tools.http import HTTPClient


@dataclass
class FingerprintResult:
    """Result of target fingerprinting."""

    server: str
    technologies: list[str]
    version_hints: list[str]
    exposed_paths: list[str]
    security_headers_missing: list[str]
    title: str
    error: str | None = None


async def fingerprint_target(url: str) -> FingerprintResult:
    """Fingerprint a web target to identify technologies, versions, and misconfigurations."""
    technologies = []
    version_hints = []
    exposed_paths = []
    server = ""
    title = ""
    error = None
    security_headers_missing = []

    try:
        async with HTTPClient() as client:
            # Initial request to get headers and HTML
            response = await client.get(url)

            # Extract server header
            server = response.headers.get("server", "Unknown")
            if server and server != "Unknown":
                technologies.append(server)

            # Check for technology-revealing headers
            powered_by = response.headers.get("x-powered-by", "")
            if powered_by:
                technologies.append(powered_by)
                # Extract version hints from X-Powered-By
                version_match = re.search(r"[\d.]+", powered_by)
                if version_match:
                    version_hints.append(f"{powered_by}")

            # Check for generator headers
            generator = response.headers.get("x-generator", "")
            if generator:
                technologies.append(generator)

            # Parse HTML for meta tags and title
            if response.body:
                # Extract title
                title_match = re.search(
                    r"<title[^>]*>([^<]+)</title>", response.body, re.IGNORECASE
                )
                if title_match:
                    title = title_match.group(1).strip()

                # Extract meta generator
                meta_gen = re.search(
                    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                    response.body,
                    re.IGNORECASE,
                )
                if meta_gen:
                    technologies.append(meta_gen.group(1))

                # Look for version hints in HTML comments and visible text
                version_patterns = [
                    r"(?:version|ver\.?|v)\s*[:=]?\s*([\d.]+)",
                    r"(phpMyAdmin)\s+([\d.]+)",
                    r"(WordPress)\s+([\d.]+)",
                    r"(Joomla!?)\s+([\d.]+)",
                    r"(Drupal)\s+([\d.]+)",
                ]
                for pattern in version_patterns:
                    matches = re.findall(pattern, response.body, re.IGNORECASE)
                    for match in matches[:3]:  # Limit to avoid noise
                        if isinstance(match, tuple):
                            version_hints.append(" ".join(match))
                        else:
                            version_hints.append(match)

            # Check security headers
            security_headers = [
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
            ]
            response_headers_lower = {k.lower(): v for k, v in response.headers.items()}
            for header in security_headers:
                if header.lower() not in response_headers_lower:
                    security_headers_missing.append(header)

            # Check robots.txt
            robots_content = await client.check_robots_txt(url)
            if robots_content:
                exposed_paths.append("/robots.txt (found)")

            # Check sitemap
            sitemap_content = await client.check_sitemap(url)
            if sitemap_content:
                exposed_paths.append("/sitemap.xml (found)")

            # Check common admin/config paths
            common_paths = [
                "/admin",
                "/login",
                "/setup",
                "/config",
                "/install",
                "/phpmyadmin",
                "/wp-admin",
                "/administrator",
            ]

            for path in common_paths:
                try:
                    check_url = url.rstrip("/") + path
                    check_response = await client.get(check_url)
                    if check_response.status_code in (200, 301, 302, 401, 403):
                        exposed_paths.append(f"{path} ({check_response.status_code})")
                except Exception:
                    pass  # Path doesn't exist or error, skip

    except Exception as e:
        error = str(e)

    return FingerprintResult(
        server=server,
        technologies=technologies,
        version_hints=list(set(version_hints)),  # Deduplicate
        exposed_paths=exposed_paths,
        security_headers_missing=security_headers_missing,
        title=title,
        error=error,
    )
