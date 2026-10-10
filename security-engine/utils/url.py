"""
Small URL helper utilities shared across discovery and scanners.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse


def join_url(base_url: str, path: str) -> str:
    """Join a base URL and a path, avoiding double slashes."""
    if not path.startswith("/"):
        path = "/" + path
    return base_url.rstrip("/") + path


def is_same_host(url_a: str, url_b: str) -> bool:
    a, b = urlparse(url_a), urlparse(url_b)
    return (a.hostname, a.port) == (b.hostname, b.port)


def normalize_path(path: str) -> str:
    """Collapse repeated slashes and strip trailing slash (except root)."""
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path
