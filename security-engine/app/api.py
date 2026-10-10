"""
FastAPI REST API for Security Engine and LangGraph AI Agent.

Exposes endpoints for:
1. Scanner metadata and discovery
2. One-shot and stateful session security scans (for Spring Boot integration)
3. LangGraph autonomous agent execution and conversational chat
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from agent.graph import build_security_agent
from app.config import DEFAULT_TIMEOUT_SECONDS, build_scanner_manager
from core.endpoint import Endpoint
from core.exceptions import InvalidTargetError, ScannerNotFoundError
from core.http_client import HttpClient
from core.scan_context import AuthContext, ScanContext
from core.target import Target
from discovery.openapi import OpenApiDiscovery
from utils.logging import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="Security Engine REST API",
    description="Local web application vulnerability scanner engine and LangGraph AI agent service.",
    version="1.0.0",
)

# Active stateful sessions repository: session_id -> ScanContext
_ACTIVE_SESSIONS: dict[str, ScanContext] = {}

# Initialized LangGraph agent workflow
_AGENT = build_security_agent()


# --- Request and Response Schemas ---

class DiscoverRequest(BaseModel):
    target: str = Field(..., description="Target base URL, e.g. http://localhost:8080")


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target base URL, e.g. http://localhost:8080")
    scanners: list[str] = Field(default=["all"], description="List of scanner names or ['all']")
    auth_token: Optional[str] = Field(None, description="Valid authentication token")
    low_priv_token: Optional[str] = Field(None, description="Low-privilege token for BFLA/BOLA tests")


class SessionCreateRequest(BaseModel):
    target: str = Field(..., description="Target base URL, e.g. http://localhost:8080")
    auth_token: Optional[str] = None
    low_priv_token: Optional[str] = None


class SessionScanRequest(BaseModel):
    scanners: list[str] = Field(default=["all"], description="Scanners to run in this session")


class AgentRunRequest(BaseModel):
    target: str = Field(..., description="Target base URL, e.g. http://localhost:8080")
    prompt: Optional[str] = Field(
        None, description="Optional custom instruction for the security audit"
    )
    session_id: Optional[str] = Field(None, description="Optional conversation session ID")


class AgentChatRequest(BaseModel):
    message: str = Field(..., description="User message or follow-up question")
    target: Optional[str] = Field(None, description="Target base URL if starting new target")
    session_id: Optional[str] = Field(None, description="Session ID for conversation continuity")


# --- Helper Functions ---

def _validate_target(url: str) -> Target:
    try:
        return Target(base_url=url)
    except InvalidTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target validation failed: {exc}",
        ) from exc


async def _run_discovery(target: Target, http_client: HttpClient) -> list[Endpoint]:
    discovery = OpenApiDiscovery()
    try:
        endpoints = await discovery.discover(target, http_client)
    except Exception:  # noqa: BLE001
        endpoints = []

    if not endpoints:
        endpoints = [Endpoint(method="GET", path="/")]
    return endpoints


# --- Routes ---

@app.get("/health", tags=["System"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "security-engine"}


@app.get("/api/v1/scanners", tags=["Metadata"])
async def list_scanners() -> list[dict[str, Any]]:
    """List all registered vulnerability scanners and their metadata."""
    manager = build_scanner_manager()
    return [
        {
            "name": meta.name,
            "description": meta.description,
            "vulnerability_types": meta.vulnerability_types,
            "risk_level": meta.risk_level,
        }
        for meta in manager.list_scanners()
    ]


@app.post("/api/v1/discover", tags=["Discovery"])
async def discover_endpoints(request: DiscoverRequest) -> list[dict[str, Any]]:
    """Discover endpoints on a target application."""
    target = _validate_target(request.target)
    async with HttpClient(base_url=target.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS) as client:
        endpoints = await _run_discovery(target, client)

    return [
        {
            "method": e.method,
            "path": e.path,
            "authentication_required": e.authentication_required,
            "description": e.description,
            "parameters": [
                {
                    "name": p.name,
                    "location": p.location.value,
                    "required": p.required,
                    "type": p.schema_type,
                }
                for p in e.parameters
            ],
        }
        for e in endpoints
    ]


@app.post("/api/v1/scan", tags=["Scanning"])
async def execute_scan(request: ScanRequest) -> dict[str, Any]:
    """Execute a one-shot security scan on the target."""
    target = _validate_target(request.target)
    manager = build_scanner_manager()

    if "all" in request.scanners:
        scanner_names = [meta.name for meta in manager.list_scanners()]
    else:
        scanner_names = []
        for s in request.scanners:
            try:
                canonical = manager.get(s).name
                if canonical not in scanner_names:
                    scanner_names.append(canonical)
            except ScannerNotFoundError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
                ) from exc

    auth = AuthContext(
        scheme="Bearer",
        valid_token=request.auth_token,
        low_privilege_token=request.low_priv_token,
    )

    async with HttpClient(base_url=target.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS) as client:
        endpoints = await _run_discovery(target, client)
        context = ScanContext(
            target=target,
            endpoints=endpoints,
            http_client=client,
            auth=auth,
        )
        result = await manager.run(scanner_names, context)

    return {
        "scan_id": context.scan_id,
        "target": target.base_url,
        "status": "completed",
        "summary": context.get_summary(),
        "findings": [f.to_dict() for f in result.findings],
        "scanner_errors": [e.to_dict() for e in result.errors],
    }


# --- Stateful Session Routes ---

@app.post("/api/v1/sessions", tags=["Sessions"])
async def create_session(request: SessionCreateRequest) -> dict[str, Any]:
    """Create a persistent ScanContext session for iterative testing."""
    target = _validate_target(request.target)
    session_id = f"SESSION-{uuid.uuid4().hex[:10]}"

    auth = AuthContext(
        scheme="Bearer",
        valid_token=request.auth_token,
        low_privilege_token=request.low_priv_token,
    )
    context = ScanContext(target=target, auth=auth, scan_id=session_id)
    _ACTIVE_SESSIONS[session_id] = context

    return {"session_id": session_id, "summary": context.get_summary()}


@app.get("/api/v1/sessions/{session_id}", tags=["Sessions"])
async def get_session(session_id: str) -> dict[str, Any]:
    """Retrieve current state and findings of an active session."""
    context = _ACTIVE_SESSIONS.get(session_id)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found.",
        )
    return context.to_dict()


@app.post("/api/v1/sessions/{session_id}/discover", tags=["Sessions"])
async def session_discover(session_id: str) -> dict[str, Any]:
    """Run endpoint discovery and attach routes to the active session."""
    context = _ACTIVE_SESSIONS.get(session_id)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found.",
        )

    async with HttpClient(base_url=context.target.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS) as client:
        endpoints = await _run_discovery(context.target, client)
        context.add_endpoints(endpoints)

    return {"session_id": session_id, "total_endpoints": len(context.endpoints)}


@app.post("/api/v1/sessions/{session_id}/scan", tags=["Sessions"])
async def session_scan(session_id: str, request: SessionScanRequest) -> dict[str, Any]:
    """Run one or more scanners within an active session, updating its state."""
    context = _ACTIVE_SESSIONS.get(session_id)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found.",
        )

    manager = build_scanner_manager()
    if "all" in request.scanners:
        scanner_names = [meta.name for meta in manager.list_scanners()]
    else:
        scanner_names = []
        for s in request.scanners:
            try:
                canonical = manager.get(s).name
                if canonical not in scanner_names:
                    scanner_names.append(canonical)
            except ScannerNotFoundError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
                ) from exc

    async with HttpClient(base_url=context.target.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS) as client:
        if not context.endpoints:
            context.add_endpoints(await _run_discovery(context.target, client))
        context.http_client = client
        result = await manager.run(scanner_names, context)

    return {
        "session_id": session_id,
        "new_findings_count": len(result.findings),
        "summary": context.get_summary(),
        "findings": [f.to_dict() for f in result.findings],
    }


@app.delete("/api/v1/sessions/{session_id}", tags=["Sessions"])
async def delete_session(session_id: str) -> dict[str, str]:
    """Close and remove an active session."""
    if session_id in _ACTIVE_SESSIONS:
        del _ACTIVE_SESSIONS[session_id]
        return {"status": "deleted", "session_id": session_id}
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Session '{session_id}' not found.",
    )


def _format_agent_response(messages: list[Any]) -> str:
    """Extract plain text string from the final agent message(s)."""
    if not messages:
        return "No response generated by agent."

    for msg in reversed(messages):
        content = getattr(msg, "content", None)
        if not content and isinstance(msg, dict):
            content = msg.get("content")

        if content:
            if isinstance(content, str):
                return content.strip()
            if isinstance(content, list):
                parts = []
                for item in content:
                    if isinstance(item, str):
                        parts.append(item)
                    elif isinstance(item, dict):
                        if "text" in item and item["text"]:
                            parts.append(str(item["text"]))
                        elif "content" in item and item["content"]:
                            parts.append(str(item["content"]))
                    else:
                        parts.append(str(item))
                if parts:
                    return "\n\n".join(parts).strip()

    last = messages[-1]
    raw = getattr(last, "content", str(last))
    return str(raw).strip() if raw else "Audit completed."


# --- LangGraph Agent Routes ---

@app.post("/api/v1/agent/run", tags=["Agent"])
async def run_agent(request: AgentRunRequest) -> dict[str, Any]:
    """Execute the LangGraph security agent to autonomously audit a target."""
    target = _validate_target(request.target)
    session_id = request.session_id or f"THREAD-{uuid.uuid4().hex[:10]}"
    prompt = request.prompt or f"Perform a comprehensive security audit of {target.base_url}."

    config = {"configurable": {"thread_id": session_id}}
    try:
        result = await _AGENT.ainvoke(
            {
                "messages": [("user", prompt)],
                "target": target.base_url,
            },
            config=config,
        )
        msgs = result.get("messages", [])
        response_text = _format_agent_response(msgs)
        count = len(msgs)
    except Exception as exc:  # noqa: BLE001
        logger.error("agent_run_failed", extra={"error": str(exc), "target": target.base_url})
        response_text = f"Agent audit encountered an issue: {exc}. Please verify target connectivity or LLM quota."
        count = 1

    return {
        "session_id": session_id,
        "target": target.base_url,
        "response": response_text,
        "messages_count": count,
    }


@app.post("/api/v1/agent/chat", tags=["Agent"])
async def chat_agent(request: AgentChatRequest) -> dict[str, Any]:
    """Interactive multi-turn conversation with the LangGraph security agent."""
    session_id = request.session_id or f"THREAD-{uuid.uuid4().hex[:10]}"
    config = {"configurable": {"thread_id": session_id}}

    state_input: dict[str, Any] = {"messages": [("user", request.message)]}
    if request.target:
        _validate_target(request.target)
        state_input["target"] = request.target

    try:
        result = await _AGENT.ainvoke(state_input, config=config)
        msgs = result.get("messages", [])
        response_text = _format_agent_response(msgs)
        count = len(msgs)
    except Exception as exc:  # noqa: BLE001
        logger.error("agent_chat_failed", extra={"error": str(exc), "session_id": session_id})
        response_text = f"Agent chat encountered an issue: {exc}. Please verify LLM quota or retry."
        count = 1

    return {
        "session_id": session_id,
        "response": response_text,
        "messages_count": count,
    }
