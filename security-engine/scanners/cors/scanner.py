"""
CORS Scanner.

Sends requests with controlled Origin headers and inspects how the target
reflects Access-Control-* response headers, looking for overly permissive
configurations (e.g. reflecting arbitrary origins while allowing credentials).
"""

from __future__ import annotations

from core.endpoint import Endpoint
from core.finding import Finding, Severity
from core.scan_context import ScanContext
from core.scanner import BaseScanner, ScannerMetadata
from utils.logging import get_logger

logger = get_logger(__name__)

# An origin that should never legitimately be allowlisted; used to detect
# naive reflection of arbitrary Origin headers.
PROBE_ORIGIN = "https://attacker-controlled.example"
NULL_ORIGIN = "null"


class CorsScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "cors"

    @property
    def description(self) -> str:
        return "Tests Cross-Origin Resource Sharing (CORS) configuration for overly permissive policies."

    @property
    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=self.name,
            description=self.description,
            vulnerability_types=["CORS_MISCONFIGURATION"],
            required_capabilities=["http"],
            risk_level="LOW",
        )

    async def scan(self, context: ScanContext) -> list[Finding]:
        endpoints = context.endpoints or [Endpoint(method="GET", path="/")]
        sample = [e for e in endpoints if e.method == "GET"][:5] or endpoints[:5]

        findings: list[Finding] = []
        for endpoint in sample:
            findings.extend(await self._scan_endpoint(context, endpoint))
        return findings

    async def _scan_endpoint(self, context: ScanContext, endpoint: Endpoint) -> list[Finding]:
        path = endpoint.resolved_path()

        try:
            arbitrary_origin_response = await context.http_client.get(
                path, headers={"Origin": PROBE_ORIGIN}
            )
            null_origin_response = await context.http_client.get(
                path, headers={"Origin": NULL_ORIGIN}
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "cors_request_failed",
                extra={"scan_id": context.scan_id, "endpoint": endpoint.identifier(), "error": str(exc)},
            )
            return []

        findings: list[Finding] = []

        findings.extend(
            self._analyze_response(endpoint, arbitrary_origin_response, PROBE_ORIGIN)
        )
        findings.extend(
            self._analyze_response(endpoint, null_origin_response, NULL_ORIGIN)
        )

        return findings

    def _analyze_response(self, endpoint: Endpoint, response, sent_origin: str) -> list[Finding]:
        headers = {k.lower(): v for k, v in response.headers.items()}
        allow_origin = headers.get("access-control-allow-origin")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"

        if allow_origin is None:
            return []

        findings: list[Finding] = []

        reflects_arbitrary_origin = allow_origin == sent_origin and sent_origin == PROBE_ORIGIN
        wildcard_with_credentials = allow_origin == "*" and allow_credentials
        allows_null_with_credentials = (
            sent_origin == NULL_ORIGIN and allow_origin == NULL_ORIGIN and allow_credentials
        )

        if wildcard_with_credentials:
            # This combination is actually invalid per the Fetch spec (browsers
            # reject it), but seeing it configured server-side still indicates
            # a misunderstanding worth flagging at low severity/confidence.
            findings.append(
                Finding(
                    scanner=self.name,
                    vulnerability_type="CORS_MISCONFIGURATION",
                    severity=Severity.LOW,
                    confidence=0.6,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    title="CORS wildcard origin combined with credentials flag",
                    description=(
                        "The response sent 'Access-Control-Allow-Origin: *' together with "
                        "'Access-Control-Allow-Credentials: true'. Browsers reject this "
                        "combination, but it suggests the CORS policy was not carefully designed."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials: true",
                    recommendation=(
                        "Only allow credentialed requests from an explicit, validated allowlist of origins."
                    ),
                )
            )
        elif reflects_arbitrary_origin:
            severity = Severity.HIGH if allow_credentials else Severity.MEDIUM
            findings.append(
                Finding(
                    scanner=self.name,
                    vulnerability_type="CORS_MISCONFIGURATION",
                    severity=severity,
                    confidence=0.9 if allow_credentials else 0.75,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    title="CORS policy reflects arbitrary Origin"
                    + (" and allows credentials" if allow_credentials else ""),
                    description=(
                        f"The server reflected an untrusted, attacker-controlled Origin "
                        f"('{sent_origin}') back in Access-Control-Allow-Origin"
                        + (
                            " while also setting Access-Control-Allow-Credentials: true, "
                            "which would allow a malicious site to make authenticated "
                            "cross-origin requests on behalf of a victim's browser."
                            if allow_credentials
                            else ". This weakens the same-origin policy for this endpoint."
                        )
                    ),
                    evidence=f"Origin sent: {sent_origin}; Access-Control-Allow-Origin returned: {allow_origin}"
                    + (f"; Access-Control-Allow-Credentials: true" if allow_credentials else ""),
                    recommendation=(
                        "Validate the Origin header against an explicit allowlist of trusted "
                        "origins server-side, rather than reflecting whatever Origin was sent."
                    ),
                )
            )
        elif allows_null_with_credentials:
            findings.append(
                Finding(
                    scanner=self.name,
                    vulnerability_type="CORS_MISCONFIGURATION",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    title="CORS policy allows 'null' origin with credentials",
                    description=(
                        "The server allows the 'null' Origin (which can be produced by "
                        "sandboxed iframes, some redirects, and local files) with credentials "
                        "enabled, which can be abused to bypass CORS protections."
                    ),
                    evidence="Access-Control-Allow-Origin: null; Access-Control-Allow-Credentials: true",
                    recommendation="Never allowlist the 'null' origin, especially not with credentials enabled.",
                )
            )

        return findings
