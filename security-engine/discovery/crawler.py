"""
Generic crawler discovery.

Used as a fallback for applications that don't expose an OpenAPI spec.
This first version is intentionally simple: it starts from a small set of
seed paths, follows same-host links found in HTML responses, and records
any URLs it finds as GET Endpoint objects. It does not attempt to infer
request bodies, authentication, or non-GET operations — that would require
either deeper heuristics or JS execution, which is out of scope for v1.

Kept entirely separate from OpenApiDiscovery so either strategy can evolve
independently.
"""

from __future__ import annotations

import re
from typing import Optional

from core.endpoint import Endpoint
from core.http_client import HttpClient
from core.target import Target
from discovery.base import BaseDiscovery
from utils.logging import get_logger
from utils.url import is_same_host, normalize_path

logger = get_logger(__name__)

DEFAULT_SEED_PATHS = ["/"]
_HREF_PATTERN = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


class CrawlerDiscovery(BaseDiscovery):
    def __init__(
        self,
        seed_paths: Optional[list[str]] = None,
        max_pages: int = 50,
    ) -> None:
        self._seed_paths = seed_paths or DEFAULT_SEED_PATHS
        self._max_pages = max_pages

    @property
    def name(self) -> str:
        return "crawler"

    async def discover(self, target: Target, http_client: HttpClient) -> list[Endpoint]:
        visited: set[str] = set()
        to_visit: list[str] = [normalize_path(p) for p in self._seed_paths]
        discovered_paths: set[str] = set()

        while to_visit and len(visited) < self._max_pages:
            path = to_visit.pop(0)
            if path in visited:
                continue
            visited.add(path)

            try:
                response = await http_client.get(path)
            except Exception as exc:  # noqa: BLE001
                logger.debug("crawler_request_failed", extra={"path": path, "error": str(exc)})
                continue

            discovered_paths.add(path)

            content_type = response.headers.get("content-type", "")
            if "html" not in content_type.lower():
                continue

            for href in _HREF_PATTERN.findall(response.body):
                normalized = self._normalize_link(href, target)
                if normalized is not None and normalized not in visited:
                    to_visit.append(normalized)

        logger.info(
            "crawler_discovery_completed",
            extra={"target": target.base_url, "pages_visited": len(visited)},
        )

        return [Endpoint(method="GET", path=p) for p in sorted(discovered_paths)]

    def _normalize_link(self, href: str, target: Target) -> Optional[str]:
        href = href.strip()

        if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
            return None

        if href.startswith("http://") or href.startswith("https://"):
            if not is_same_host(href, target.base_url):
                return None
            # Strip scheme+host, keep the path only.
            from urllib.parse import urlparse

            path = urlparse(href).path or "/"
            return normalize_path(path)

        if href.startswith("/"):
            return normalize_path(href)

        # Relative paths (no leading slash) are not resolved in this first
        # version to avoid incorrectly guessing the current page's directory.
        return None
