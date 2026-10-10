import pytest

from core.endpoint import Endpoint
from core.http_client import HttpClient
from core.scan_context import ScanContext
from core.target import Target
from scanners.cors.scanner import CorsScanner
from tests.test_app import TestApp


@pytest.mark.asyncio
async def test_vulnerable_cors_produces_high_severity_finding():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[Endpoint(method="GET", path="/cors-vulnerable")],
                http_client=client,
            )
            findings = await CorsScanner().scan(context)

    assert len(findings) > 0
    assert any(f.severity.value == "HIGH" for f in findings)


@pytest.mark.asyncio
async def test_secure_cors_produces_no_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[Endpoint(method="GET", path="/cors-secure")],
                http_client=client,
            )
            findings = await CorsScanner().scan(context)

    assert findings == []
