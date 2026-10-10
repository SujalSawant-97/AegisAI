"""
SQL Injection (SQLi) Scanner.

Tests endpoints and parameters for SQL injection vulnerabilities using:
1. Error-based detection: identifies database-specific syntax errors triggered by quote escapes.
2. Boolean-based differential analysis: compares TRUE condition vs FALSE condition responses.
"""

from __future__ import annotations

from typing import Any, Optional

from core.endpoint import Endpoint, Parameter, ParameterLocation
from core.finding import Finding, Severity
from core.http_client import HttpResponse
from core.scan_context import ScanContext
from core.scanner import BaseScanner, ScannerMetadata
from payloads.sqli import SqliPayloadProvider, detect_sql_error
from utils.comparison import compare_body_similarity, compare_status_codes
from utils.logging import get_logger

logger = get_logger(__name__)


class SqliScanner(BaseScanner):
    def __init__(self, payload_provider: Optional[SqliPayloadProvider] = None) -> None:
        self._payload_provider = payload_provider or SqliPayloadProvider()

    @property
    def name(self) -> str:
        return "sqli"

    @property
    def description(self) -> str:
        return "Tests endpoints and parameters for SQL Injection using error-based and boolean techniques."

    @property
    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=self.name,
            description=self.description,
            vulnerability_types=[
                "SQL_INJECTION_ERROR_BASED",
                "SQL_INJECTION_BOOLEAN_BASED",
            ],
            required_capabilities=["http"],
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
                    "sqli_endpoint_scan_failed",
                    extra={
                        "scan_id": context.scan_id,
                        "endpoint": endpoint.identifier(),
                        "error": str(exc),
                    },
                )

        return findings

    async def _scan_endpoint(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []

        # Collect parameters to test
        params_to_test: list[Parameter] = list(endpoint.parameters)
        if not params_to_test and endpoint.method == "GET":
            # If no parameters defined for GET endpoint, test standard parameter probe 'id'
            params_to_test = [Parameter(name="id", location=ParameterLocation.QUERY, example="1")]

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
        base_val = str(param.example) if param.example is not None else "1"

        # 1. Baseline request
        baseline = await self._send_request(context, endpoint, param, base_val)
        if baseline is None:
            return []

        baseline_error = detect_sql_error(baseline.body)

        # 2. Error-based SQLi test
        for error_payload in self._payload_provider.get_payloads():
            injected_val = f"{base_val}{error_payload.value}"
            response = await self._send_request(context, endpoint, param, injected_val)
            if response is None:
                continue

            error_match = detect_sql_error(response.body)
            if error_match is not None and error_match != baseline_error:
                db_engine, pattern_str = error_match
                findings.append(
                    Finding(
                        scanner=self.name,
                        vulnerability_type="SQL_INJECTION_ERROR_BASED",
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        parameter=param.name,
                        title=f"Error-based SQL Injection in parameter '{param.name}' on {endpoint.identifier()}",
                        description=(
                            f"The parameter '{param.name}' triggered a database syntax error "
                            f"({db_engine}) when injected with '{error_payload.value}'. "
                            f"This indicates raw parameter concatenation in a database query."
                        ),
                        evidence=(
                            f"Payload: {injected_val}\n"
                            f"Matched Error: '{pattern_str}' ({db_engine})\n"
                            f"HTTP Status: {response.status_code}"
                        ),
                        recommendation=(
                            "Use parameterized queries (prepared statements) or an ORM. "
                            "Never concatenate untrusted user input directly into SQL queries."
                        ),
                    )
                )
                # Once error-based injection is confirmed for this parameter, stop testing it
                return findings

        # 3. Boolean-based SQLi test
        if baseline.status_code == 200:
            for pair in self._payload_provider.get_boolean_pairs():
                true_val = f"{base_val}{pair.true_payload}"
                false_val = f"{base_val}{pair.false_payload}"

                true_resp = await self._send_request(context, endpoint, param, true_val)
                false_resp = await self._send_request(context, endpoint, param, false_val)

                if true_resp is None or false_resp is None:
                    continue

                # TRUE condition should produce similar response to baseline
                true_matches_baseline = (
                    true_resp.status_code == baseline.status_code
                    and compare_body_similarity(baseline, true_resp).equal
                )

                # FALSE condition should differ significantly from TRUE condition
                status_differs = true_resp.status_code != false_resp.status_code
                body_differs = not compare_body_similarity(true_resp, false_resp).equal

                if true_matches_baseline and (status_differs or body_differs):
                    findings.append(
                        Finding(
                            scanner=self.name,
                            vulnerability_type="SQL_INJECTION_BOOLEAN_BASED",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            parameter=param.name,
                            title=f"Boolean-based Blind SQL Injection in parameter '{param.name}' on {endpoint.identifier()}",
                            description=(
                                f"The parameter '{param.name}' responded differentially to boolean SQL conditions. "
                                f"The TRUE condition yielded a response consistent with the baseline, whereas "
                                f"the FALSE condition caused a significant divergence."
                            ),
                            evidence=(
                                f"TRUE payload: '{true_val}' (Status {true_resp.status_code})\n"
                                f"FALSE payload: '{false_val}' (Status {false_resp.status_code})\n"
                                f"Status differs: {status_differs}, Body differs: {body_differs}"
                            ),
                            recommendation=(
                                "Use parameterized queries / prepared statements for all database access."
                            ),
                        )
                    )
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

            # Default to query parameter
            return await context.http_client.get(
                endpoint.resolved_path(), params={param.name: value}, auth_header=auth_header
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("sqli_request_failed", extra={"param": param.name, "error": str(exc)})
            return None
