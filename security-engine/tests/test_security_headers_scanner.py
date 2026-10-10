import pytest

from core.endpoint import Endpoint
from core.http_client import HttpClient
from core.scan_context import ScanContext
from core.target import Target
from scanners.headers.scanner import SecurityHeadersScanner
from tests.test_app import TestApp


@pytest.mark.asyncio
async def test_vulnerable_endpoint_produces_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[Endpoint(method="GET", path="/vulnerable")],
                http_client=client,
            )
            findings = await SecurityHeadersScanner().scan(context)

    assert len(findings) > 0
    assert all(f.scanner == "security_headers" for f in findings)


@pytest.mark.asyncio
async def test_secure_endpoint_produces_no_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[Endpoint(method="GET", path="/secure")],
                http_client=client,
            )
            findings = await SecurityHeadersScanner().scan(context)

    assert findings == []
