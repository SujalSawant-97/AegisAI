"""
BaseScanner interface and ScannerMetadata.

Every vulnerability scanner implements BaseScanner. ScannerMetadata is the
descriptive envelope that will later be exposed to the AI agent as a "tool
description" — it deliberately contains no decision logic, just facts about
the scanner.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from core.finding import Finding
from core.scan_context import ScanContext


@dataclass
class ScannerMetadata:
    name: str
    description: str
    vulnerability_types: list[str]
    required_capabilities: list[str] = field(default_factory=lambda: ["http"])
    risk_level: str = "LOW"  # informational label about how "noisy"/invasive the scanner is


class BaseScanner(ABC):
    """Abstract base class every scanner must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short, stable, machine-usable identifier (e.g. 'security_headers')."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this scanner checks."""

    @property
    def metadata(self) -> ScannerMetadata:
        """
        Default metadata implementation built from name/description.
        Scanners can override this for richer AI-facing metadata.
        """
        return ScannerMetadata(
            name=self.name,
            description=self.description,
            vulnerability_types=[],
        )

    @abstractmethod
    async def scan(self, context: ScanContext) -> list[Finding]:
        """
        Run this scanner against the given context and return a list of
        Finding objects (empty list if nothing was found). Implementations
        should not raise for "no vulnerability found" — only for genuine
        execution failures (network errors, etc), which the ScannerManager
        will capture as a ScannerError.
        """
