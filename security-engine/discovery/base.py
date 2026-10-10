"""
Base discovery interface.

Discovery is responsible only for finding endpoints and turning them into
Endpoint objects — it must not contain vulnerability-testing logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.endpoint import Endpoint
from core.http_client import HttpClient
from core.target import Target


class BaseDiscovery(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    async def discover(self, target: Target, http_client: HttpClient) -> list[Endpoint]:
        """Return a list of discovered Endpoint objects. May return an empty list."""
