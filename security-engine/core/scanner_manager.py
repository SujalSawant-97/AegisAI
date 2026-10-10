"""
ScannerManager.

Registers scanners, looks them up by name, and executes one or more of them
against a ScanContext. Contains no vulnerability-specific logic — it only
orchestrates lifecycle and error isolation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from core.exceptions import ScannerExecutionError, ScannerNotFoundError
from core.finding import Finding, ScannerError
from core.scan_context import ScanContext
from core.scanner import BaseScanner, ScannerMetadata
from utils.logging import get_logger

logger = get_logger(__name__)


SCANNER_ALIASES: dict[str, str] = {
    "headers": "security_headers",
    "security-headers": "security_headers",
    "security_headers": "security_headers",
    "cors": "cors",
    "auth": "authentication",
    "authentication": "authentication",
    "authz": "authorization",
    "authorization": "authorization",
    "sqli": "sqli",
    "sql": "sqli",
    "xss": "xss",
}


@dataclass
class ScanRunResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScannerError] = field(default_factory=list)


class ScannerManager:
    def __init__(self) -> None:
        self._scanners: dict[str, BaseScanner] = {}

    def register(self, scanner: BaseScanner) -> None:
        if scanner.name in self._scanners:
            raise ValueError(f"A scanner named '{scanner.name}' is already registered.")
        self._scanners[scanner.name] = scanner

    def list_scanners(self) -> list[ScannerMetadata]:
        return [scanner.metadata for scanner in self._scanners.values()]

    def get(self, name: str) -> BaseScanner:
        canonical_name = SCANNER_ALIASES.get(name.lower().strip(), name.strip())
        try:
            return self._scanners[canonical_name]
        except KeyError:
            try:
                return self._scanners[name]
            except KeyError:
                raise ScannerNotFoundError(
                    f"No scanner registered with name '{name}'. "
                    f"Available: {sorted(self._scanners.keys())}"
                )

    async def _run_one(self, name: str, context: ScanContext) -> tuple[list[Finding], ScannerError | None]:
        scanner = self.get(name)
        logger.info(
            "scanner_started",
            extra={"scan_id": context.scan_id, "scanner": name, "target": context.target.base_url},
        )
        try:
            findings = await scanner.scan(context)
            context.add_findings(name, findings)
            logger.info(
                "scanner_completed",
                extra={
                    "scan_id": context.scan_id,
                    "scanner": name,
                    "finding_count": len(findings),
                },
            )
            return findings, None
        except Exception as exc:  # noqa: BLE001 - intentional: isolate scanner failures
            wrapped = ScannerExecutionError(name, exc)
            logger.error(
                "scanner_failed",
                extra={"scan_id": context.scan_id, "scanner": name, "error": str(exc)},
            )
            err_msg = str(wrapped.original_exception)
            context.add_error(name, err_msg)
            return [], ScannerError(scanner=name, error=err_msg)

    async def run(
        self,
        scanner_names: list[str],
        context: ScanContext,
    ) -> ScanRunResult:
        """
        Execute the named scanners concurrently. A failure in one scanner
        never aborts the others; failures are captured as ScannerError
        entries and returned alongside successful findings.
        """
        # Resolve all aliases and validate up front
        resolved_names: list[str] = []
        for name in scanner_names:
            canonical_scanner = self.get(name)
            if canonical_scanner.name not in resolved_names:
                resolved_names.append(canonical_scanner.name)

        results = await asyncio.gather(
            *(self._run_one(name, context) for name in resolved_names)
        )

        run_result = ScanRunResult()
        for findings, error in results:
            run_result.findings.extend(findings)
            if error is not None:
                run_result.errors.append(error)

        return run_result
