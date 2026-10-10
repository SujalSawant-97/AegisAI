import pytest

from core.endpoint import Endpoint, Parameter, ParameterLocation
from core.http_client import HttpClient
from core.scan_context import AuthContext, ScanContext
from core.target import Target
from scanners.authorization.scanner import AuthorizationScanner
from tests.test_app import TestApp


@pytest.mark.asyncio
async def test_bfla_vulnerable_admin_produces_finding():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[Endpoint(method="GET", path="/authz/admin-vulnerable")],
                http_client=client,
                auth=AuthContext(
                    scheme="Bearer",
                    low_privilege_token="user-token",
                    high_privilege_token="admin-token",
                ),
            )
            findings = await AuthorizationScanner().scan(context)

    assert len(findings) > 0
    assert any(f.vulnerability_type == "BROKEN_FUNCTION_LEVEL_AUTHORIZATION" for f in findings)
    assert any(f.severity.value == "HIGH" for f in findings)


@pytest.mark.asyncio
async def test_bfla_secure_admin_produces_no_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[Endpoint(method="GET", path="/authz/admin-secure")],
                http_client=client,
                auth=AuthContext(
                    scheme="Bearer",
                    low_privilege_token="user-token",
                    high_privilege_token="admin-token",
                ),
            )
            findings = await AuthorizationScanner().scan(context)

    assert findings == []


@pytest.mark.asyncio
async def test_bola_vulnerable_user_endpoint_produces_finding():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/authz/user-vulnerable/{id}",
                        parameters=[
                            Parameter(
                                name="id",
                                location=ParameterLocation.PATH,
                                example="1",
                            )
                        ],
                    )
                ],
                http_client=client,
                auth=AuthContext(
                    scheme="Bearer",
                    low_privilege_token="user-1-token",
                ),
            )
            findings = await AuthorizationScanner().scan(context)

    assert len(findings) > 0
    assert any(f.vulnerability_type == "BROKEN_OBJECT_LEVEL_AUTHORIZATION" for f in findings)


@pytest.mark.asyncio
async def test_bola_secure_user_endpoint_produces_no_findings():
    with TestApp() as app:
        target = Target(base_url=app.base_url)
        async with HttpClient(base_url=target.base_url) as client:
            context = ScanContext(
                target=target,
                endpoints=[
                    Endpoint(
                        method="GET",
                        path="/authz/user-secure/{id}",
                        parameters=[
                            Parameter(
                                name="id",
                                location=ParameterLocation.PATH,
                                example="1",
                            )
                        ],
                    )
                ],
                http_client=client,
                auth=AuthContext(
                    scheme="Bearer",
                    low_privilege_token="user-1-token",
                ),
            )
            findings = await AuthorizationScanner().scan(context)

    assert findings == []
