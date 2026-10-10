import pytest

from core.endpoint import Endpoint
from core.http_client import HttpClient
from core.scan_context import AuthContext, ScanContext
from core.target import Target
from scanners.authentication.scanner import AuthenticationScanner
from tests.test_app import TestApp


@pytest.mark.asyncio
async def test_vulnerable_auth_produces_unauthenticated_finding():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/auth/vulnerable",
                        authentication_required=True,
                    )
                ],
                http_client=client,
            )
            findings = await AuthenticationScanner().scan(context)

    assert len(findings) > 0
    assert any(f.vulnerability_type == "UNAUTHENTICATED_ACCESS" for f in findings)
    assert any(f.severity.value == "HIGH" for f in findings)


@pytest.mark.asyncio
async def test_secure_auth_produces_no_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/auth/secure",
                        authentication_required=True,
                    )
                ],
                http_client=client,
                auth=AuthContext(scheme="Bearer", valid_token="valid-secret-token"),
            )
            findings = await AuthenticationScanner().scan(context)

    assert findings == []


@pytest.mark.asyncio
async def test_auth_disclosure_produces_finding():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/auth/disclosure",
                        authentication_required=True,
                    )
                ],
                http_client=client,
            )
            findings = await AuthenticationScanner().scan(context)

    assert any(f.vulnerability_type == "AUTH_INFORMATION_DISCLOSURE" for f in findings)
