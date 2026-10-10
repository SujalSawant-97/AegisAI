import pytest

from core.endpoint import Endpoint, Parameter, ParameterLocation
from core.http_client import HttpClient
from core.scan_context import ScanContext
from core.target import Target
from scanners.xss.scanner import XssScanner
from tests.test_app import TestApp


@pytest.mark.asyncio
async def test_vulnerable_html_reflection_produces_high_finding():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/xss-vulnerable",
                        parameters=[
                            Parameter(
                                name="q",
                                location=ParameterLocation.QUERY,
                                example="test",
                            )
                        ],
                    )
                ],
                http_client=client,
            )
            findings = await XssScanner().scan(context)

    assert len(findings) > 0
    assert any(f.vulnerability_type == "REFLECTED_XSS" for f in findings)
    assert any(f.severity.value == "HIGH" for f in findings)


@pytest.mark.asyncio
async def test_escaped_html_reflection_produces_no_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/xss-secure",
                        parameters=[
                            Parameter(
                                name="q",
                                location=ParameterLocation.QUERY,
                                example="test",
                            )
                        ],
                    )
                ],
                http_client=client,
            )
            findings = await XssScanner().scan(context)

    assert findings == []


@pytest.mark.asyncio
async def test_safe_json_response_produces_no_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/xss-json-safe",
                        parameters=[
                            Parameter(
                                name="q",
                                location=ParameterLocation.QUERY,
                                example="test",
                            )
                        ],
                    )
                ],
                http_client=client,
            )
            findings = await XssScanner().scan(context)

    assert findings == []


@pytest.mark.asyncio
async def test_csp_protected_endpoint_adjusts_severity_to_medium():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/xss-csp-protected",
                        parameters=[
                            Parameter(
                                name="q",
                                location=ParameterLocation.QUERY,
                                example="test",
                            )
                        ],
                    )
                ],
                http_client=client,
            )
            findings = await XssScanner().scan(context)

    assert len(findings) > 0
    assert any(f.vulnerability_type == "REFLECTED_XSS" for f in findings)
    assert any(f.severity.value == "MEDIUM" for f in findings)
