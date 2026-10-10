import httpx
import pytest

from app.api import app
from tests.test_app import TestApp


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_list_scanners_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/api/v1/scanners")
        assert response.status_code == 200
        scanners = response.json()
        assert len(scanners) == 6
        names = [s["name"] for s in scanners]
        assert "sqli" in names
        assert "xss" in names
        assert "cors" in names


@pytest.mark.asyncio
async def test_discover_endpoint():
    with TestApp() as test_app:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post("/api/v1/discover", json={"target": test_app.base_url})
            assert response.status_code == 200
            endpoints = response.json()
            assert isinstance(endpoints, list)
            assert len(endpoints) > 0


@pytest.mark.asyncio
async def test_discover_rejects_external_target():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/api/v1/discover", json={"target": "http://example.com"})
        assert response.status_code == 400
        assert "Target validation failed" in response.json()["detail"]


@pytest.mark.asyncio
async def test_one_shot_scan_endpoint():
    with TestApp() as test_app:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/api/v1/scan",
                json={
                    "target": test_app.base_url,
                    "scanners": ["security_headers"],
                },
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "completed"
            assert "findings" in data
            assert "summary" in data


@pytest.mark.asyncio
async def test_session_lifecycle():
    with TestApp() as test_app:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. Create session
            res_create = await client.post(
                "/api/v1/sessions",
                json={"target": test_app.base_url},
            )
            assert res_create.status_code == 200
            session_id = res_create.json()["session_id"]

            # 2. Get session
            res_get = await client.get(f"/api/v1/sessions/{session_id}")
            assert res_get.status_code == 200
            assert res_get.json()["scan_id"] == session_id

            # 3. Discover inside session
            res_disc = await client.post(f"/api/v1/sessions/{session_id}/discover")
            assert res_disc.status_code == 200
            assert res_disc.json()["total_endpoints"] > 0

            # 4. Scan inside session
            res_scan = await client.post(
                f"/api/v1/sessions/{session_id}/scan",
                json={"scanners": ["security_headers"]},
            )
            assert res_scan.status_code == 200
            assert "summary" in res_scan.json()

            # 5. Delete session
            res_del = await client.delete(f"/api/v1/sessions/{session_id}")
            assert res_del.status_code == 200

            # 6. Verify 404 after deletion
            res_deleted_get = await client.get(f"/api/v1/sessions/{session_id}")
            assert res_deleted_get.status_code == 404


@pytest.mark.asyncio
async def test_agent_run_endpoint():
    with TestApp() as test_app:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/api/v1/agent/run",
                json={"target": test_app.base_url},
            )
            assert response.status_code == 200
            data = response.json()
            assert "session_id" in data
            assert "response" in data
            assert data["response"] != ""
