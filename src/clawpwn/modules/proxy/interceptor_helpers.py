"""Helpers for proxy interception I/O and forwarding."""

import asyncio
import time

import httpx

from clawpwn.modules.proxy.store import ProxyEntry


async def read_headers(reader: asyncio.StreamReader, timeout: float) -> dict[str, str]:
    """Read HTTP headers from a stream."""
    headers: dict[str, str] = {}
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        text = line.decode("utf-8", errors="replace").strip()
        if not text:
            break
        key, _, value = text.partition(":")
        if value:
            headers[key.strip()] = value.strip()
    return headers


async def forward_request(entry: ProxyEntry, timeout: float) -> tuple[httpx.Response, float]:
    """Forward one HTTP request and return response with elapsed time."""
    start = time.monotonic()
    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        forward_headers = {
            key: value
            for key, value in entry.request_headers.items()
            if key.lower() not in ("host", "proxy-connection")
        }
        response = await client.request(
            method=entry.method,
            url=entry.url,
            headers=forward_headers,
            content=entry.request_body.encode() if entry.request_body else None,
        )
    elapsed = round(time.monotonic() - start, 4)
    return response, elapsed


def write_response(writer: asyncio.StreamWriter, response: httpx.Response) -> None:
    """Write an HTTP response to a client stream."""
    writer.write(f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n".encode())
    for key, value in response.headers.items():
        writer.write(f"{key}: {value}\r\n".encode())
    writer.write(b"\r\n")
    writer.write(response.content)


async def write_bad_gateway(writer: asyncio.StreamWriter) -> None:
    """Write a 502 response to the client."""
    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    await writer.drain()


async def pipe_stream(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    """Copy data between two streams until EOF."""
    try:
        while data := await src.read(8192):
            dst.write(data)
            await dst.drain()
    except (ConnectionError, OSError):
        pass
