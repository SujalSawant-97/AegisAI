"""
Application-level configuration and scanner registration.

This is the single place that wires up which scanners exist. Discovery and
the AI agent (later) should not need to know how scanners are constructed.
"""

from __future__ import annotations

from core.scanner_manager import ScannerManager
from scanners.authentication.scanner import AuthenticationScanner
from scanners.authorization.scanner import AuthorizationScanner
from scanners.cors.scanner import CorsScanner
from scanners.headers.scanner import SecurityHeadersScanner
from scanners.sqli.scanner import SqliScanner
from scanners.xss.scanner import XssScanner

DEFAULT_TIMEOUT_SECONDS = 10.0


def build_scanner_manager() -> ScannerManager:
    """
    Construct a ScannerManager with all currently-implemented scanners
    registered.
    """
    manager = ScannerManager()
    manager.register(SecurityHeadersScanner())
    manager.register(CorsScanner())
    manager.register(AuthenticationScanner())
    manager.register(AuthorizationScanner())
    manager.register(SqliScanner())
    manager.register(XssScanner())
    return manager
