import json
import pytest

from agent.graph import build_security_agent
from agent.tools import (
    discover_endpoints_tool,
    list_available_scanners_tool,
    run_all_scanners_tool,
    run_scanner_tool,
)
from tests.test_app import TestApp


@pytest.mark.asyncio
async def test_list_available_scanners_tool():
    result_str = await list_available_scanners_tool.ainvoke({})
    scanners = json.loads(result_str)
    assert len(scanners) == 6
    names = {s["name"] for s in scanners}
    assert "sqli" in names
    assert "xss" in names
    assert "authentication" in names
    assert "authorization" in names


@pytest.mark.asyncio
async def test_discover_endpoints_tool():
    with TestApp() as app:
        result_str = await discover_endpoints_tool.ainvoke({"target": app.base_url})
        endpoints = json.loads(result_str)
        assert len(endpoints) > 0


@pytest.mark.asyncio
async def test_run_scanner_tool_headers():
    with TestApp() as app:
        result_str = await run_scanner_tool.ainvoke({
            "target": app.base_url,
            "scanner_name": "security_headers",
        })
        result = json.loads(result_str)
        assert result["scanner"] == "security_headers"
        assert "findings" in result
        assert "summary" in result


@pytest.mark.asyncio
async def test_run_all_scanners_tool():
    with TestApp() as app:
        result_str = await run_all_scanners_tool.ainvoke({"target": app.base_url})
        result = json.loads(result_str)
        assert result["status"] == "completed"
        assert "findings" in result
        assert "summary" in result
        assert result["summary"]["total_findings"] >= 0


@pytest.mark.asyncio
async def test_langgraph_agent_execution():
    with TestApp() as app:
        agent = build_security_agent()
        config = {"configurable": {"thread_id": "test_thread_1"}}
        result = await agent.ainvoke(
            {
                "messages": [("user", f"Audit {app.base_url} for security issues")],
                "target": app.base_url,
            },
            config=config,
        )

        assert "messages" in result
        assert len(result["messages"]) >= 2
        last_msg = result["messages"][-1]
        assert last_msg.content != ""
