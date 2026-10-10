"""
Security Headers Scanner.

Checks HTTP responses for missing or misconfigured security-relevant
headers. Deliberately conservative: not every missing header is treated as
equally severe, and some headers only matter in certain contexts (e.g.
HSTS only matters over HTTPS).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from core.endpoint import Endpoint
from core.finding import Finding, Severity
from core.scan_context import ScanContext
from core.scanner import BaseScanner, ScannerMetadata
from utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class HeaderCheck:
    header_name: str
    severity: Severity
    confidence: float
    description: str
    recommendation: str
    # Optional predicate: only run this check when it returns True
    # (e.g. HSTS only applies over HTTPS).
    applies_if: Optional[Callable[[ScanContext], bool]] = None
    # Optional validator for headers that are present but might still be
    # misconfigured (e.g. an empty CSP). Returns (is_ok, evidence).
    validate_value: Optional[Callable[[str], tuple[bool, str]]] = None


def _is_https(context: ScanContext) -> bool:
    return context.target.protocol == "https"


def _validate_frame_options(value: str) -> tuple[bool, str]:
    ok = value.strip().upper() in {"DENY", "SAMEORIGIN"}
    return ok, f"value='{value}'"


def _validate_content_type_options(value: str) -> tuple[bool, str]:
    ok = value.strip().lower() == "nosniff"
    return ok, f"value='{value}'"


HEADER_CHECKS: list[HeaderCheck] = [
    HeaderCheck(
        header_name="Content-Security-Policy",
        severity=Severity.MEDIUM,
        confidence=0.85,
        description=(
            "No Content-Security-Policy header was present. CSP helps mitigate "
            "the impact of XSS and other content-injection attacks by restricting "
            "which sources of content the browser is allowed to load."
        ),
        recommendation=(
            "Define a Content-Security-Policy appropriate for the application, "
            "starting from a restrictive default-src and allowlisting only what is needed."
        ),
    ),
    HeaderCheck(
        header_name="X-Content-Type-Options",
        severity=Severity.LOW,
        confidence=0.9,
        description=(
            "No X-Content-Type-Options header was present, which allows some "
            "browsers to MIME-sniff responses away from the declared Content-Type."
        ),
        recommendation="Set 'X-Content-Type-Options: nosniff' on all responses.",
        validate_value=_validate_content_type_options,
    ),
    HeaderCheck(
        header_name="X-Frame-Options",
        severity=Severity.MEDIUM,
        confidence=0.8,
        description=(
            "No X-Frame-Options header was present, which may allow the page to be "
            "embedded in a frame on another site (clickjacking risk). Note: CSP "
            "frame-ancestors is a more modern replacement/complement for this header."
        ),
        recommendation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or use CSP frame-ancestors).",
        validate_value=_validate_frame_options,
    ),
    HeaderCheck(
        header_name="Strict-Transport-Security",
        severity=Severity.MEDIUM,
        confidence=0.85,
        description=(
            "No Strict-Transport-Security header was present on an HTTPS response, "
            "so browsers may still be willing to connect over plain HTTP."
        ),
        recommendation="Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains' (once HTTPS is confirmed fully deployed).",
        applies_if=_is_https,
    ),
    HeaderCheck(
        header_name="Referrer-Policy",
        severity=Severity.LOW,
        confidence=0.7,
        description=(
            "No Referrer-Policy header was present, so the browser default "
            "referrer behavior applies, which may leak full URLs (including "
            "sensitive query parameters) to third-party sites via the Referer header."
        ),
        recommendation="Set an explicit 'Referrer-Policy', e.g. 'strict-origin-when-cross-origin'.",
    ),
]


class SecurityHeadersScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "security_headers"

    @property
    def description(self) -> str:
        return "Checks HTTP responses for missing or insecure security headers."

    @property
    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=self.name,
            description=self.description,
            vulnerability_types=["MISSING_SECURITY_HEADER", "MISCONFIGURED_SECURITY_HEADER"],
            required_capabilities=["http"],
            risk_level="LOW",
        )

    async def scan(self, context: ScanContext) -> list[Finding]:
        endpoints = context.endpoints or [Endpoint(method="GET", path="/")]

        # Headers are typically applied globally (via a filter/middleware), so
        # checking every single endpoint would be redundant and noisy. We
        # sample a small, representative set: root + a handful of others.
        sample_endpoints = self._select_sample(endpoints)

        findings: list[Finding] = []
        for endpoint in sample_endpoints:
            findings.extend(await self._scan_endpoint(context, endpoint))

        return findings

    def _select_sample(self, endpoints: list[Endpoint], max_sample: int = 5) -> list[Endpoint]:
        get_endpoints = [e for e in endpoints if e.method == "GET"] or endpoints
        return get_endpoints[:max_sample]

    async def _scan_endpoint(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        try:
            response = await context.http_client.get(endpoint.resolved_path())
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "security_headers_request_failed",
                extra={"scan_id": context.scan_id, "endpoint": endpoint.identifier(), "error": str(exc)},
            )
            return []

        # Normalize header lookup to be case-insensitive.
        lower_headers = {k.lower(): v for k, v in response.headers.items()}

        findings: list[Finding] = []
        for check in HEADER_CHECKS:
            if check.applies_if is not None and not check.applies_if(context):
                continue

            header_value = lower_headers.get(check.header_name.lower())

            if header_value is None:
                findings.append(
                    Finding(
                        scanner=self.name,
                        vulnerability_type="MISSING_SECURITY_HEADER",
                        severity=check.severity,
                        confidence=check.confidence,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        title=f"Missing {check.header_name} header",
                        description=check.description,
                        evidence=f"Header '{check.header_name}' was not present in the response.",
                        recommendation=check.recommendation,
                    )
                )
                continue

            if check.validate_value is not None:
                is_ok, evidence = check.validate_value(header_value)
                if not is_ok:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            vulnerability_type="MISCONFIGURED_SECURITY_HEADER",
                            severity=check.severity,
                            # Slightly lower confidence: header is present, we're
                            # flagging its *value* as suspicious, which is more
                            # judgment-dependent than a straightforward absence.
                            confidence=max(check.confidence - 0.15, 0.5),
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            title=f"Potentially misconfigured {check.header_name} header",
                            description=check.description,
                            evidence=evidence,
                            recommendation=check.recommendation,
                        )
                    )

        return findings
