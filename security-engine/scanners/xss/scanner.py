"""
Cross-Site Scripting (XSS) Scanner.

Tests endpoints and parameters for Reflected XSS vulnerabilities:
1. Injects benign canary probes into parameters.
2. Checks for unescaped reflection in HTML rendering contexts.
3. Evaluates Content-Type and Content-Security-Policy headers to avoid false positives.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from core.endpoint import Endpoint, Parameter, ParameterLocation
from core.finding import Finding, Severity
from core.http_client import HttpResponse
from core.scan_context import ScanContext
from core.scanner import BaseScanner, ScannerMetadata
from payloads.xss import XssPayloadProvider, is_reflected_unescaped
from utils.logging import get_logger

logger = get_logger(__name__)

HTML_CONTENT_TYPES = {
    "text/html",
    "application/xhtml+xml",
}


class XssScanner(BaseScanner):
    def __init__(self, payload_provider: Optional[XssPayloadProvider] = None) -> None:
        self._payload_provider = payload_provider or XssPayloadProvider()

    @property
    def name(self) -> str:
        return "xss"

    @property
    def description(self) -> str:
        return "Tests endpoints and parameters for Reflected Cross-Site Scripting (XSS) vulnerabilities."

    @property
    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=self.name,
            description=self.description,
            vulnerability_types=["REFLECTED_XSS"],
            required_capabilities=["http"],
            risk_level="LOW",
        )

    async def scan(self, context: ScanContext) -> list[Finding]:
        endpoints = context.endpoints or [Endpoint(method="GET", path="/")]
        findings: list[Finding] = []

        for endpoint in endpoints:
            try:
                findings.extend(await self._scan_endpoint(context, endpoint))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "xss_endpoint_scan_failed",
                    extra={
                        "scan_id": context.scan_id,
                        "endpoint": endpoint.identifier(),
                        "error": str(exc),
                    },
                )

        return findings

    async def _scan_endpoint(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []

        params_to_test: list[Parameter] = list(endpoint.parameters)
        if not params_to_test and endpoint.method == "GET":
            # If no parameters defined for GET endpoint, test standard search probe 'q'
            params_to_test = [Parameter(name="q", location=ParameterLocation.QUERY, example="test")]

        for param in params_to_test:
            param_findings = await self._test_parameter(context, endpoint, param)
            findings.extend(param_findings)

        return findings

    async def _test_parameter(
        self,
        context: ScanContext,
        endpoint: Endpoint,
        param: Parameter,
    ) -> list[Finding]:
        findings: list[Finding] = []
        probes = self._payload_provider.generate_probes()

        for probe in probes:
            payload_str = probe.rendered_payload
            response = await self._send_request(context, endpoint, param, payload_str)
            if response is None:
                continue

            content_type = response.headers.get("content-type", "").lower().split(";")[0].strip()

            # Ignore strict non-HTML contexts like application/json or text/plain
            # to prevent false positives when JSON endpoints safely echo input.
            if content_type and content_type not in HTML_CONTENT_TYPES and "html" not in content_type:
                continue

            # Check if canary is reflected without proper HTML entity escaping
            if is_reflected_unescaped(probe.canary, response.body):
                # Also verify whether the injected tag / markup is unescaped
                if "<xss_" in response.body:
                    csp = response.headers.get("content-security-policy", "")
                    has_strict_csp = bool(
                        re.search(r"script-src\s+[^;]*'none'", csp, re.IGNORECASE)
                        or ("script-src" in csp and "'unsafe-inline'" not in csp)
                    )

                    severity = Severity.MEDIUM if has_strict_csp else Severity.HIGH
                    confidence = 0.9

                    evidence = (
                        f"Injected: '{payload_str}'\n"
                        f"Response Content-Type: '{content_type or 'unspecified'}'\n"
                        f"Unescaped probe reflected in response body."
                    )
                    if has_strict_csp:
                        evidence += f"\nNote: Content-Security-Policy header is present: '{csp}'"

                    findings.append(
                        Finding(
                            scanner=self.name,
                            vulnerability_type="REFLECTED_XSS",
                            severity=severity,
                            confidence=confidence,
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            parameter=param.name,
                            title=f"Reflected Cross-Site Scripting (XSS) in parameter '{param.name}' on {endpoint.identifier()}",
                            description=(
                                f"The parameter '{param.name}' reflects untrusted input directly into the "
                                f"HTML response body without sufficient sanitization or HTML entity escaping."
                            ),
                            evidence=evidence,
                            recommendation=(
                                "Contextually encode all user-supplied input before rendering it in HTML documents. "
                                "Deploy a strong Content-Security-Policy (CSP) restricting inline script execution."
                            ),
                        )
                    )
                    # Found XSS on this parameter; move to next parameter
                    break

        return findings

    async def _send_request(
        self,
        context: ScanContext,
        endpoint: Endpoint,
        param: Parameter,
        value: str,
    ) -> Optional[HttpResponse]:
        auth_header = None
        if context.auth.valid_token:
            auth_header = context.auth.header_for(context.auth.valid_token)

        try:
            if param.location == ParameterLocation.PATH:
                path = endpoint.resolved_path({param.name: value})
                return await context.http_client.get(path, auth_header=auth_header)

            if param.location == ParameterLocation.QUERY:
                path = endpoint.resolved_path()
                return await context.http_client.get(
                    path, params={param.name: value}, auth_header=auth_header
                )

            if param.location == ParameterLocation.BODY:
                path = endpoint.resolved_path()
                body = {param.name: value}
                if endpoint.content_type == "application/x-www-form-urlencoded":
                    return await context.http_client.post(path, data=body, auth_header=auth_header)
                return await context.http_client.post(path, json_body=body, auth_header=auth_header)

            return await context.http_client.get(
                endpoint.resolved_path(), params={param.name: value}, auth_header=auth_header
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("xss_request_failed", extra={"param": param.name, "error": str(exc)})
            return None
