"""Web scanner plugins."""

from .builtin import BuiltinWebScannerPlugin
from .feroxbuster import FeroxbusterWebScannerPlugin
from .ffuf import FFUFWebScannerPlugin
from .nikto import NiktoWebScannerPlugin
from .nuclei import NucleiWebScannerPlugin
from .sqlmap import SqlmapWebScannerPlugin
from .testssl import TestSSLWebScannerPlugin
from .wpscan import WPScanWebScannerPlugin
from .zap import ZAPWebScannerPlugin

__all__ = [
    "BuiltinWebScannerPlugin",
    "FFUFWebScannerPlugin",
    "FeroxbusterWebScannerPlugin",
    "NiktoWebScannerPlugin",
    "NucleiWebScannerPlugin",
    "SqlmapWebScannerPlugin",
    "TestSSLWebScannerPlugin",
    "WPScanWebScannerPlugin",
    "ZAPWebScannerPlugin",
]
