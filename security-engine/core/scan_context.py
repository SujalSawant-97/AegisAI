"""
ScanContext.

A single object carrying everything scanners need: the target, the
discovered endpoints, the shared HTTP client, authentication material, and
run configuration. This avoids scanners each wiring up their own HTTP
clients or re-discovering endpoints.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from core.endpoint import Endpoint
from core.finding import Finding, ScannerError, Severity
from core.http_client import HttpClient
from core.target import Target


@dataclass
class AuthContext:
    """
    Credentials/tokens made available to scanners that need authenticated
    requests (e.g. authentication / authorization scanners).

    Never populated with hard-coded defaults — callers must supply these
    explicitly (CLI flag, API request body, environment variable, etc).
    """

    scheme: Optional[str] = None  # e.g. "Bearer", "Basic"
    valid_token: Optional[str] = None
    invalid_token: Optional[str] = None
    low_privilege_token: Optional[str] = None
    high_privilege_token: Optional[str] = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    def header_for(self, token: Optional[str]) -> Optional[str]:
        if token is None:
            return None
        if self.scheme:
            return f"{self.scheme} {token}"
        return token


@dataclass
class ScanConfig:
    max_concurrent_requests: int = 5
    request_timeout_seconds: float = 10.0
    fail_fast: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    target: Target
    endpoints: list[Endpoint] = field(default_factory=list)
    http_client: Optional[HttpClient] = None
    auth: AuthContext = field(default_factory=AuthContext)
    config: ScanConfig = field(default_factory=ScanConfig)
    scan_id: str = field(default_factory=lambda: f"SCAN-{uuid.uuid4().hex[:10]}")
    metadata: dict[str, Any] = field(default_factory=dict)

    # Agent / Workflow State Accumulation
    findings: list[Finding] = field(default_factory=list)
    completed_scanners: list[str] = field(default_factory=list)
    scanner_errors: list[ScannerError] = field(default_factory=list)
    scanned_endpoints: set[str] = field(default_factory=set)

    def add_findings(self, scanner: str, new_findings: list[Finding]) -> None:
        """Record findings from a scanner execution and track scanned endpoints."""
        self.findings.extend(new_findings)
        if scanner not in self.completed_scanners:
            self.completed_scanners.append(scanner)
        for f in new_findings:
            if f.endpoint:
                self.scanned_endpoints.add(f.endpoint)

    def add_error(self, scanner: str, error_message: str, metadata: Optional[dict[str, Any]] = None) -> None:
        """Record a scanner execution failure without aborting the scan workflow."""
        self.scanner_errors.append(
            ScannerError(scanner=scanner, error=error_message, metadata=metadata or {})
        )

    def add_endpoint(self, endpoint: Endpoint) -> None:
        """Add an endpoint to context if not already present."""
        existing = {e.identifier() for e in self.endpoints}
        if endpoint.identifier() not in existing:
            self.endpoints.append(endpoint)

    def add_endpoints(self, endpoints: list[Endpoint]) -> None:
        """Batch-add endpoints avoiding duplicates."""
        for ep in endpoints:
            self.add_endpoint(ep)

    def record_scanned_endpoint(self, endpoint_identifier: str) -> None:
        """Mark an endpoint as scanned."""
        self.scanned_endpoints.add(endpoint_identifier)

    def get_findings_by_severity(self, severity: Severity | str) -> list[Finding]:
        """Filter accumulated findings by severity level."""
        sev_value = severity.value if isinstance(severity, Severity) else str(severity).upper()
        return [f for f in self.findings if f.severity.value == sev_value]

    def get_findings_by_scanner(self, scanner: str) -> list[Finding]:
        """Filter accumulated findings by scanner name."""
        return [f for f in self.findings if f.scanner == scanner]

    def get_summary(self) -> dict[str, Any]:
        """
        Compact summary formatted for LLM prompts, status checks, and reporting.
        Provides high-level counts without flooding context windows with raw payloads.
        """
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            val = f.severity.value
            if val in sev_counts:
                sev_counts[val] += 1

        return {
            "scan_id": self.scan_id,
            "target": self.target.base_url,
            "total_endpoints": len(self.endpoints),
            "scanned_endpoints_count": len(self.scanned_endpoints),
            "completed_scanners": list(self.completed_scanners),
            "total_findings": len(self.findings),
            "findings_by_severity": sev_counts,
            "scanner_errors_count": len(self.scanner_errors),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize full context state including findings and summary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target.base_url,
            "endpoints": [e.identifier() for e in self.endpoints],
            "completed_scanners": list(self.completed_scanners),
            "scanned_endpoints": list(self.scanned_endpoints),
            "findings": [f.to_dict() for f in self.findings],
            "scanner_errors": [e.to_dict() for e in self.scanner_errors],
            "summary": self.get_summary(),
        }
