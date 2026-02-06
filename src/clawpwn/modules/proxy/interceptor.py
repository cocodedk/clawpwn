"""HTTP intercepting proxy server."""

import asyncio
import logging
from collections.abc import Callable

import httpx

from clawpwn.modules.proxy.interceptor_helpers import (
    forward_request,
    pipe_stream,
    read_headers,
    write_bad_gateway,
    write_response,
)
from clawpwn.modules.proxy.store import ProxyEntry, ProxyStore

logger = logging.getLogger(__name__)

InterceptRule = Callable[[ProxyEntry], ProxyEntry | None]


class InterceptProxy:
    """Local HTTP proxy that intercepts, logs, and optionally modifies traffic."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        store: ProxyStore | None = None,
        timeout: float = 30.0,
    ):
        self.host = host
        self.port = port
        self.store = store if store is not None else ProxyStore()
        self.timeout = timeout
        self._server: asyncio.Server | None = None
        self._rules: list[InterceptRule] = []
        self.running = False

    def add_rule(self, rule: InterceptRule) -> None:
        """Register an intercept rule."""
        self._rules.append(rule)

    def clear_rules(self) -> None:
        """Remove all intercept rules."""
        self._rules.clear()

    async def start(self) -> None:
        """Start listening for proxy connections."""
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.running = True
        logger.info("Proxy listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Shut down the proxy server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.running = False
        logger.info("Proxy stopped")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            if not first_line:
                return
            parts = first_line.decode("utf-8", errors="replace").strip().split()
            if len(parts) < 2:
                return

            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                await self._handle_connect(reader, writer, target)
            else:
                await self._handle_http(reader, writer, method, target)
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        url: str,
    ) -> None:
        headers = await read_headers(reader, self.timeout)
        body = ""
        length = int(headers.get("Content-Length", "0"))
        if length > 0:
            raw = await asyncio.wait_for(reader.readexactly(length), timeout=self.timeout)
            body = raw.decode("utf-8", errors="replace")

        entry = ProxyEntry(method=method, url=url, request_headers=headers, request_body=body)
        for rule in self._rules:
            result = rule(entry)
            if result is None:
                return
            entry = result

        try:
            response, elapsed = await forward_request(entry, self.timeout)
        except httpx.HTTPError as exc:
            logger.debug("Forward failed for %s: %s", url, exc)
            await write_bad_gateway(writer)
            return

        entry.status_code = response.status_code
        entry.response_headers = dict(response.headers)
        entry.response_body = response.text
        entry.response_time = elapsed
        self.store.add(entry)

        write_response(writer, response)
        await writer.drain()

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
    ) -> None:
        """Tunnel HTTPS traffic without content inspection."""
        await read_headers(reader, self.timeout)
        host, _, port_str = target.partition(":")
        port = int(port_str) if port_str else 443

        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except OSError:
            await write_bad_gateway(writer)
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        self.store.add(
            ProxyEntry(
                method="CONNECT",
                url=f"https://{host}:{port}",
                status_code=200,
                notes="HTTPS tunnel (content not intercepted)",
                tags=["tunnel"],
            )
        )

        await asyncio.gather(
            pipe_stream(reader, remote_writer),
            pipe_stream(remote_reader, writer),
            return_exceptions=True,
        )
        remote_writer.close()
