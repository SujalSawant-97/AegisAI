import pytest

from core.endpoint import Endpoint, Parameter, ParameterLocation
from core.http_client import HttpClient
from core.scan_context import ScanContext
from core.target import Target
from scanners.sqli.scanner import SqliScanner
from tests.test_app import TestApp


@pytest.mark.asyncio
async def test_error_based_sqli_produces_critical_finding():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/sqli-error-vulnerable",
                        parameters=[
                            Parameter(
                                name="id",
                                location=ParameterLocation.QUERY,
                                example="1",
                            )
                        ],
                    )
                ],
                http_client=client,
            )
            findings = await SqliScanner().scan(context)

    assert len(findings) > 0
    assert any(f.vulnerability_type == "SQL_INJECTION_ERROR_BASED" for f in findings)
    assert any(f.severity.value == "CRITICAL" for f in findings)
    assert any(f.confidence >= 0.9 for f in findings)


@pytest.mark.asyncio
async def test_boolean_based_sqli_produces_high_finding():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/sqli-boolean-vulnerable",
                        parameters=[
                            Parameter(
                                name="id",
                                location=ParameterLocation.QUERY,
                                example="1",
                            )
                        ],
                    )
                ],
                http_client=client,
            )
            findings = await SqliScanner().scan(context)

    assert len(findings) > 0
    assert any(f.vulnerability_type == "SQL_INJECTION_BOOLEAN_BASED" for f in findings)
    assert any(f.severity.value == "HIGH" for f in findings)


@pytest.mark.asyncio
async def test_secure_sqli_produces_no_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/sqli-secure",
                        parameters=[
                            Parameter(
                                name="id",
                                location=ParameterLocation.QUERY,
                                example="1",
                            )
                        ],
                    )
                ],
                http_client=client,
            )
            findings = await SqliScanner().scan(context)

    assert findings == []
