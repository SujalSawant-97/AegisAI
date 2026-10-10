"""
LangChain tool wrappers for the Security Engine.

Exposes endpoint discovery, scanner execution, and summary inspection as
strongly typed LangChain tools callable by LangGraph and LLMs.
"""

from __future__ import annotations

import json
from typing import Any, Optional
from langchain_core.tools import tool

from app.config import DEFAULT_TIMEOUT_SECONDS, build_scanner_manager
from core.endpoint import Endpoint
from core.http_client import HttpClient
from core.scan_context import AuthContext, ScanContext
from core.target import Target
from discovery.openapi import OpenApiDiscovery


async def _perform_discovery(target: Target, http_client: HttpClient) -> list[Endpoint]:
    discovery = OpenApiDiscovery()
    try:
        endpoints = await discovery.discover(target, http_client)
    except Exception:  # noqa: BLE001
        endpoints = []

    if not endpoints:
        endpoints = [Endpoint(method="GET", path="/")]
    return endpoints


@tool
async def list_available_scanners_tool() -> str:
    """
    List all available security vulnerability scanners in the engine with their
    descriptions, vulnerability types, and risk levels.
    """
    manager = build_scanner_manager()
    scanners = [
        {
            "name": meta.name,
            "description": meta.description,
            "vulnerability_types": meta.vulnerability_types,
            "risk_level": meta.risk_level,
        }
        for meta in manager.list_scanners()
    ]
    return json.dumps(scanners, indent=2)


@tool
async def discover_endpoints_tool(target: str) -> str:
    """
    Discovers API routes and endpoints on a local target application (e.g. http://localhost:8080).
    Returns list of HTTP methods, paths, and parameter definitions.
    """
    target_obj = Target(base_url=target)
    async with HttpClient(base_url=target_obj.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS) as client:
        endpoints = await _perform_discovery(target_obj, client)

    formatted = [
        {
            "method": e.method,
            "path": e.path,
            "authentication_required": e.authentication_required,
            "parameters": [
                {"name": p.name, "location": p.location.value, "type": p.schema_type}
                for p in e.parameters
            ],
        }
        for e in endpoints
    ]
    return json.dumps(formatted, indent=2)


@tool
async def run_scanner_tool(
    target: str,
    scanner_name: str,
    auth_token: Optional[str] = None,
    low_priv_token: Optional[str] = None,
) -> str:
    """
    Executes a single vulnerability scanner on the target.
    Available scanner names:
    - 'security_headers': Checks missing or misconfigured security response headers.
    - 'cors': Checks cross-origin resource sharing misconfigurations and origin reflection.
    - 'authentication': Checks for unauthenticated access to protected routes and invalid token acceptance.
    - 'authorization': Checks for Broken Function Level Authorization (BFLA) and Broken Object Level Authorization (BOLA/IDOR).
    - 'sqli': Tests parameters for SQL Injection using error-based and boolean differential techniques.
    - 'xss': Tests parameters for Reflected Cross-Site Scripting (XSS).
    """
    target_obj = Target(base_url=target)
    manager = build_scanner_manager()

    auth = AuthContext(
        scheme="Bearer",
        valid_token=auth_token,
        low_privilege_token=low_priv_token,
    )

    async with HttpClient(base_url=target_obj.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS) as client:
        endpoints = await _perform_discovery(target_obj, client)
        context = ScanContext(
            target=target_obj,
            endpoints=endpoints,
            http_client=client,
            auth=auth,
        )
        result = await manager.run([scanner_name], context)

    response = {
        "scanner": scanner_name,
        "findings_count": len(result.findings),
        "findings": [f.to_dict() for f in result.findings],
        "summary": context.get_summary(),
        "errors": [e.to_dict() for e in result.errors],
    }
    return json.dumps(response, indent=2)


@tool
async def run_all_scanners_tool(
    target: str,
    auth_token: Optional[str] = None,
    low_priv_token: Optional[str] = None,
) -> str:
    """
    Executes all 6 security vulnerability scanners concurrently on the target.
    Returns the comprehensive list of findings and severity summary breakdown.
    """
    target_obj = Target(base_url=target)
    manager = build_scanner_manager()
    all_scanner_names = [meta.name for meta in manager.list_scanners()]

    auth = AuthContext(
        scheme="Bearer",
        valid_token=auth_token,
        low_privilege_token=low_priv_token,
    )

    async with HttpClient(base_url=target_obj.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS) as client:
        endpoints = await _perform_discovery(target_obj, client)
        context = ScanContext(
            target=target_obj,
            endpoints=endpoints,
            http_client=client,
            auth=auth,
        )
        result = await manager.run(all_scanner_names, context)

    response = {
        "status": "completed",
        "total_findings": len(result.findings),
        "findings": [f.to_dict() for f in result.findings],
        "summary": context.get_summary(),
        "errors": [e.to_dict() for e in result.errors],
    }
    return json.dumps(response, indent=2)


SECURITY_AGENT_TOOLS = [
    list_available_scanners_tool,
    discover_endpoints_tool,
    run_scanner_tool,
    run_all_scanners_tool,
]
