"""Plugin factory helpers for web scanning."""

from collections.abc import Callable
from pathlib import Path

from .base import WebScannerPlugin
from .plugins import (
    BuiltinWebScannerPlugin,
    FeroxbusterWebScannerPlugin,
    FFUFWebScannerPlugin,
    NiktoWebScannerPlugin,
    NucleiWebScannerPlugin,
    SearchsploitWebScannerPlugin,
    SqlmapWebScannerPlugin,
    TestSSLWebScannerPlugin,
    WPScanWebScannerPlugin,
    ZAPWebScannerPlugin,
)


def create_default_webscan_plugins(
    project_dir: Path | None,
    scanner_factory: Callable[[Path | None], object],
) -> list[WebScannerPlugin]:
    """Return standard built-in plus external scanner plugins."""
    return [
        BuiltinWebScannerPlugin(project_dir=project_dir, scanner_factory=scanner_factory),
        NucleiWebScannerPlugin(),
        FeroxbusterWebScannerPlugin(),
        FFUFWebScannerPlugin(),
        NiktoWebScannerPlugin(),
        SearchsploitWebScannerPlugin(),
        ZAPWebScannerPlugin(),
        SqlmapWebScannerPlugin(),
        WPScanWebScannerPlugin(),
        TestSSLWebScannerPlugin(),
    ]
