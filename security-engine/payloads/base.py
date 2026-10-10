"""
Payload provider abstraction.

Keeps test-input strings out of scanner logic so they can evolve, be
versioned, and be documented independently.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Payload:
    value: str
    strategy: str  # e.g. "error_based", "reflection", "boolean_based"
    description: str


class PayloadProvider(ABC):
    @abstractmethod
    def get_payloads(self) -> list[Payload]:
        """Return the (small, curated) list of payloads this provider offers."""
