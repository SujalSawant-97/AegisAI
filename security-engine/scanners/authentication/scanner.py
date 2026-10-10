"""
Authentication Scanner.

Tests endpoints for authentication enforcement failures:
1. Unauthenticated access permitted to protected endpoints.
2. Acceptance of invalid, expired, or malformed authentication tokens.
3. Information disclosure in authentication error responses.
"""

from __future__ import annotations

import re
from typing import Optional

from core.endpoint import Endpoint
from core.finding import Finding, Severity
from core.scan_context import ScanContext
from core.scanner import BaseScanner, ScannerMetadata
from utils.comparison import compare_body_similarity, compare_status_codes
from utils.logging import get_logger

logger = get_logger(__name__)

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\):",
    r"Exception in thread \".*\"",
    r"at [a-zA-Z0-9_.]+\([a-zA-Z0-9_.]+\.java:\d+\)",
    r"NullPointerException",
    r"Unhandled exception:",
]

# Sensitive path indicators that typically require authentication
SENSITIVE_PATH_PATTERNS = [
    r"/admin",
    r"/api/admin",
    r"/api/user",
    r"/api/profile",
    r"/api/account",
    r"/dashboard",
    r"/settings",
    r"/manage",
    r"/secure",
]


class AuthenticationScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "authentication"

    @property
    def description(self) -> str:
        return "Tests endpoints for missing authentication, invalid token acceptance, and auth disclosure."

    @property
    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=self.name,
            description=self.description,
            vulnerability_types=[
                "UNAUTHENTICATED_ACCESS",
                "INVALID_TOKEN_ACCEPTED",
                "AUTH_INFORMATION_DISCLOSURE",
            ],
            required_capabilities=["http", "auth"],
            risk_level="LOW",
        )

    async def scan(self, context: ScanContext) -> list[Finding]:
        endpoints = context.endpoints or [Endpoint(method="GET", path="/")]
        findings: list[Finding] = []

        for endpoint in endpoints:
            try:
                endpoint_findings = await self._scan_endpoint(context, endpoint)
                findings.extend(endpoint_findings)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "authentication_endpoint_scan_failed",
                    extra={
                        "scan_id": context.scan_id,
                        "endpoint": endpoint.identifier(),
                        "error": str(exc),
                    },
                )

        return findings

    async def _scan_endpoint(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        path = endpoint.resolved_path()
        method = endpoint.method.upper()

        is_declared_auth_required = endpoint.authentication_required
        looks_sensitive = any(
            re.search(pat, path, re.IGNORECASE) for pat in SENSITIVE_PATH_PATTERNS
        )

        valid_auth_header: Optional[str] = None
        if context.auth.valid_token:
            valid_auth_header = context.auth.header_for(context.auth.valid_token)

        invalid_token = context.auth.invalid_token or "invalid_token_probe_bad_signature_12345"
        invalid_auth_header = context.auth.header_for(invalid_token)
        if not invalid_auth_header.startswith(("Bearer ", "Basic ")) and context.auth.scheme:
            invalid_auth_header = f"{context.auth.scheme} {invalid_token}"
        elif not context.auth.scheme and not invalid_auth_header.startswith("Bearer "):
            invalid_auth_header = f"Bearer {invalid_token}"

        # 1. Unauthenticated baseline probe
        unauth_response = await self._send_request(
            context, method, path, auth_header=None
        )
        if unauth_response is None:
            return []

        # Check for verbose stack trace leakage in auth rejection
        if unauth_response.status_code in (401, 403, 500):
            leak_finding = self._check_information_disclosure(endpoint, unauth_response)
            if leak_finding:
                findings.append(leak_finding)

        # If endpoint is declared to require auth, but responds 200 to unauthenticated request
        if (is_declared_auth_required or looks_sensitive) and unauth_response.status_code == 200:
            # If valid token is supplied, verify that unauthenticated response matches authenticated
            is_bypass = True
            if valid_auth_header:
                valid_response = await self._send_request(
                    context, method, path, auth_header=valid_auth_header
                )
                if valid_response and valid_response.status_code == 200:
                    similarity = compare_body_similarity(unauth_response, valid_response)
                    is_bypass = similarity.equal or unauth_response.status_code == valid_response.status_code

            if is_bypass:
                findings.append(
                    Finding(
                        scanner=self.name,
                        vulnerability_type="UNAUTHENTICATED_ACCESS",
                        severity=Severity.HIGH,
                        confidence=0.9 if is_declared_auth_required else 0.75,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        title=f"Unauthenticated access permitted to {endpoint.identifier()}",
                        description=(
                            f"The endpoint '{endpoint.path}' is expected to require authentication, "
                            f"but returned HTTP 200 OK without any authentication credentials."
                        ),
                        evidence=(
                            f"Request without Authorization header yielded status "
                            f"{unauth_response.status_code} (length: {len(unauth_response.body)} bytes)."
                        ),
                        recommendation=(
                            "Ensure an authentication filter/middleware guards this route "
                            "and rejects unauthenticated requests with HTTP 401 Unauthorized."
                        ),
                    )
                )

        # 2. Invalid Token Probe
        # Test if sending an invalid token is rejected properly (401/403)
        # We test this if the endpoint responded 401/403 to unauthenticated request (proving auth is checked)
        # OR if it is declared auth required.
        should_test_invalid_token = (
            unauth_response.status_code in (401, 403) or is_declared_auth_required
        )

        if should_test_invalid_token:
            invalid_response = await self._send_request(
                context, method, path, auth_header=invalid_auth_header
            )
            if invalid_response:
                if invalid_response.status_code in (401, 403, 500):
                    leak_finding = self._check_information_disclosure(endpoint, invalid_response)
                    if leak_finding and leak_finding not in findings:
                        findings.append(leak_finding)

                if invalid_response.status_code == 200:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            vulnerability_type="INVALID_TOKEN_ACCEPTED",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            title=f"Endpoint accepts invalid authentication token on {endpoint.identifier()}",
                            description=(
                                f"The endpoint '{endpoint.path}' accepted an intentionally invalid "
                                f"or malformed authentication token and returned HTTP 200 OK."
                            ),
                            evidence=(
                                f"Sent Authorization: '{invalid_auth_header[:25]}...'; "
                                f"Received status {invalid_response.status_code}."
                            ),
                            recommendation=(
                                "Verify that token signatures, expirations, and claims are cryptographically "
                                "validated before granting access."
                            ),
                        )
                    )

        return findings

    async def _send_request(
        self,
        context: ScanContext,
        method: str,
        path: str,
        auth_header: Optional[str],
    ):
        try:
            if method == "POST":
                return await context.http_client.post(path, auth_header=auth_header)
            if method == "PUT":
                return await context.http_client.put(path, auth_header=auth_header)
            if method == "DELETE":
                return await context.http_client.delete(path, auth_header=auth_header)
            return await context.http_client.get(path, auth_header=auth_header)
        except Exception as exc:  # noqa: BLE001
            logger.debug("auth_request_failed", extra={"path": path, "error": str(exc)})
            return None

    def _check_information_disclosure(self, endpoint: Endpoint, response) -> Optional[Finding]:
        for pattern in STACK_TRACE_PATTERNS:
            match = re.search(pattern, response.body, re.IGNORECASE)
            if match:
                return Finding(
                    scanner=self.name,
                    vulnerability_type="AUTH_INFORMATION_DISCLOSURE",
                    severity=Severity.LOW,
                    confidence=0.85,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    title=f"Information disclosure in authentication response on {endpoint.identifier()}",
                    description=(
                        "The authentication response contained an unhandled exception or stack trace, "
                        "revealing internal implementation details."
                    ),
                    evidence=f"Matched trace signature: '{match.group(0)}'",
                    recommendation="Sanitize error responses and return generic error messages to clients.",
                )
        return None
