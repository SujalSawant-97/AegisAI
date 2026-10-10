"""
LangGraph state definition for the Security Engine Agent.

Maps the engine's ScanContext into a typed LangGraph State, maintaining
conversation messages, discovered endpoints, accumulated findings, and summary.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional, TypedDict
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class SecurityAgentState(TypedDict, total=False):
    """The central state flowing through the LangGraph security agent."""

    # Chat history / message exchange between user/Spring Boot and the LLM
    messages: Annotated[list[BaseMessage], add_messages]

    # Target URL being audited (strictly validated to localhost/127.0.0.1)
    target: str

    # Discovered routes and endpoints
    endpoints: list[dict[str, Any]]

    # Accumulated vulnerability findings
    findings: list[dict[str, Any]]

    # Names of scanners that have completed execution
    completed_scanners: list[str]

    # Specific endpoint paths that have been tested
    scanned_endpoints: list[str]

    # High-level summary breakdown (counts by severity, etc.)
    summary: dict[str, Any]

    # Optional credentials for authenticated scanning
    auth: dict[str, Any]
