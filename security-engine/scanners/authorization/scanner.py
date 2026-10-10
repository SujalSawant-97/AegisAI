"""
Authorization Scanner.

Tests endpoints for access control vulnerabilities:
1. Broken Function Level Authorization (BFLA / Privilege Escalation):
   Verifies that administrative/privileged endpoints reject requests from
   low-privilege tokens or standard users.
2. Broken Object Level Authorization (BOLA / IDOR):
   Verifies that resource identifiers (e.g. user IDs, document IDs) cannot
   be accessed by users who do not own them.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from core.endpoint import Endpoint, ParameterLocation
from core.finding import Finding, Severity
from core.scan_context import ScanContext
from core.scanner import BaseScanner, ScannerMetadata
from utils.comparison import compare_body_similarity
from utils.logging import get_logger

logger = get_logger(__name__)

# Patterns identifying administrative or high-privilege functionality
ADMIN_PATH_PATTERNS = [
    r"(?:^|/|[-_])admin(?:[-_/]|$)",
    r"(?:^|/|[-_])manage(?:[-_/]|$)",
    r"(?:^|/|[-_])system(?:[-_/]|$)",
    r"(?:^|/|[-_])internal(?:[-_/]|$)",
    r"(?:^|/|[-_])roles?(?:[-_/]|$)",
    r"/settings/system",
]

# Parameter names that suggest object identity
OBJECT_ID_PARAM_NAMES = {
    "id",
    "userid",
    "user_id",
    "accountid",
    "account_id",
    "orderid",
    "order_id",
    "documentid",
    "document_id",
    "doc_id",
}


class AuthorizationScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "authorization"

    @property
    def description(self) -> str:
        return "Tests endpoints for Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA)."

    @property
    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=self.name,
            description=self.description,
            vulnerability_types=[
                "BROKEN_FUNCTION_LEVEL_AUTHORIZATION",
                "BROKEN_OBJECT_LEVEL_AUTHORIZATION",
            ],
            required_capabilities=["http", "auth"],
            risk_level="MEDIUM",
        )

    async def scan(self, context: ScanContext) -> list[Finding]:
        endpoints = context.endpoints or [Endpoint(method="GET", path="/")]
        findings: list[Finding] = []

        for endpoint in endpoints:
            try:
                findings.extend(await self._scan_endpoint(context, endpoint))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "authorization_endpoint_scan_failed",
                    extra={
                        "scan_id": context.scan_id,
                        "endpoint": endpoint.identifier(),
                        "error": str(exc),
                    },
                )

        return findings

    async def _scan_endpoint(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Test BFLA (Function Level Authorization)
        bfla_finding = await self._test_bfla(context, endpoint)
        if bfla_finding:
            findings.append(bfla_finding)

        # 2. Test BOLA (Object Level Authorization)
        bola_findings = await self._test_bola(context, endpoint)
        findings.extend(bola_findings)

        return findings

    async def _test_bfla(self, context: ScanContext, endpoint: Endpoint) -> Optional[Finding]:
        path = endpoint.resolved_path()
        is_admin_endpoint = any(
            re.search(pat, path, re.IGNORECASE) for pat in ADMIN_PATH_PATTERNS
        )

        if not is_admin_endpoint:
            return None

        low_priv_token = context.auth.low_privilege_token or context.auth.valid_token
        if not low_priv_token:
            # If no low priv token is given, we cannot reliably prove privilege escalation
            return None

        low_priv_header = context.auth.header_for(low_priv_token)
        if not low_priv_header.startswith(("Bearer ", "Basic ")) and context.auth.scheme:
            low_priv_header = f"{context.auth.scheme} {low_priv_token}"
        elif not context.auth.scheme and not low_priv_header.startswith("Bearer "):
            low_priv_header = f"Bearer {low_priv_token}"

        # If high priv token is available, check baseline
        high_priv_header = None
        if context.auth.high_privilege_token:
            high_priv_header = context.auth.header_for(context.auth.high_privilege_token)
            if not high_priv_header.startswith(("Bearer ", "Basic ")) and context.auth.scheme:
                high_priv_header = f"{context.auth.scheme} {context.auth.high_privilege_token}"
            elif not context.auth.scheme and not high_priv_header.startswith("Bearer "):
                high_priv_header = f"Bearer {context.auth.high_privilege_token}"

        response = await self._send_request(
            context, endpoint.method, path, auth_header=low_priv_header
        )
        if response is None:
            return None

        # If low privilege user accesses admin endpoint and receives 200 OK
        if response.status_code == 200:
            confidence = 0.85
            evidence = f"Low privilege token received HTTP {response.status_code} on administrative endpoint."

            if high_priv_header:
                high_response = await self._send_request(
                    context, endpoint.method, path, auth_header=high_priv_header
                )
                if high_response and high_response.status_code == 200:
                    similarity = compare_body_similarity(response, high_response)
                    if similarity.equal:
                        confidence = 0.95
                        evidence += " Low privilege response matches high privilege response."

            return Finding(
                scanner=self.name,
                vulnerability_type="BROKEN_FUNCTION_LEVEL_AUTHORIZATION",
                severity=Severity.HIGH,
                confidence=confidence,
                endpoint=endpoint.path,
                method=endpoint.method,
                title=f"Broken Function Level Authorization (BFLA) on {endpoint.identifier()}",
                description=(
                    f"The administrative endpoint '{endpoint.path}' granted access to a user with "
                    f"low privileges, returning HTTP 200 OK instead of HTTP 403 Forbidden."
                ),
                evidence=evidence,
                recommendation=(
                    "Implement role-based authorization checks (RBAC) to ensure only authorized "
                    "administrative roles can execute this function."
                ),
            )

        return None

    async def _test_bola(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        path = endpoint.path
        method = endpoint.method.upper()

        auth_header: Optional[str] = None
        token = context.auth.low_privilege_token or context.auth.valid_token
        if token:
            auth_header = context.auth.header_for(token)
            if not auth_header.startswith(("Bearer ", "Basic ")) and context.auth.scheme:
                auth_header = f"{context.auth.scheme} {token}"
            elif not context.auth.scheme and not auth_header.startswith("Bearer "):
                auth_header = f"Bearer {token}"

        # 1. Check Path parameters for IDs (e.g. /users/{id} or /users/1)
        path_params = endpoint.path_parameters
        for param in path_params:
            if param.name.lower() in OBJECT_ID_PARAM_NAMES or "id" in param.name.lower():
                # Attempt with original ID and foreign/alternate ID
                orig_id = param.example or "1"
                alt_id = "2" if str(orig_id) == "1" else "1"

                test_path = endpoint.resolved_path({param.name: alt_id})
                response = await self._send_request(
                    context, method, test_path, auth_header=auth_header
                )
                if response and response.status_code == 200:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            vulnerability_type="BROKEN_OBJECT_LEVEL_AUTHORIZATION",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            parameter=param.name,
                            title=f"Broken Object Level Authorization (BOLA/IDOR) on {endpoint.identifier()}",
                            description=(
                                f"Accessing resource '{test_path}' with alternate ID '{alt_id}' "
                                f"returned HTTP 200 OK without validating user ownership of the object."
                            ),
                            evidence=f"Requested path with ID '{alt_id}', received HTTP {response.status_code}.",
                            recommendation=(
                                "Verify that the authenticated user has explicit permission to read/modify "
                                "the specific object ID requested."
                            ),
                        )
                    )

        # 2. Check Query parameters for IDs
        query_params = [
            p for p in endpoint.query_parameters if p.name.lower() in OBJECT_ID_PARAM_NAMES
        ]
        for param in query_params:
            orig_id = param.example or "1"
            alt_id = "2" if str(orig_id) == "1" else "1"

            response = await self._send_request(
                context,
                method,
                endpoint.resolved_path(),
                params={param.name: alt_id},
                auth_header=auth_header,
            )
            if response and response.status_code == 200:
                findings.append(
                    Finding(
                        scanner=self.name,
                        vulnerability_type="BROKEN_OBJECT_LEVEL_AUTHORIZATION",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        parameter=param.name,
                        title=f"Broken Object Level Authorization (BOLA/IDOR) on {param.name}",
                        description=(
                            f"Query parameter '{param.name}' allows accessing alternate object '{alt_id}' "
                            f"without authorization checks."
                        ),
                        evidence=f"Sent {param.name}={alt_id}, received HTTP {response.status_code}.",
                        recommendation="Enforce object-level access control on query parameters identifying resources.",
                    )
                )

        return findings

    async def _send_request(
        self,
        context: ScanContext,
        method: str,
        path: str,
        params: Optional[dict[str, Any]] = None,
        auth_header: Optional[str] = None,
    ):
        try:
            if method == "POST":
                return await context.http_client.post(path, params=params, auth_header=auth_header)
            if method == "PUT":
                return await context.http_client.put(path, params=params, auth_header=auth_header)
            if method == "DELETE":
                return await context.http_client.delete(path, params=params, auth_header=auth_header)
            return await context.http_client.get(path, params=params, auth_header=auth_header)
        except Exception as exc:  # noqa: BLE001
            logger.debug("authz_request_failed", extra={"path": path, "error": str(exc)})
            return None
