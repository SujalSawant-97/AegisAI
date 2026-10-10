"""
Finding model.

Every scanner must return a list of Finding objects (possibly empty). This is
the single normalized output format consumed by the CLI, the REST API, and
eventually the AI agent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    scanner: str
    vulnerability_type: str
    severity: Severity
    confidence: float  # 0.0 - 1.0, independent of severity
    title: str
    description: str
    endpoint: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: f"FIND-{uuid.uuid4().hex[:12]}")

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scanner": self.scanner,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class ScannerError:
    """Represents a scanner that failed to complete, kept separate from Findings."""

    scanner: str
    error: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "error": self.error,
            "metadata": self.metadata,
        }
