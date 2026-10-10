"""
Endpoint model.

Represents a single API endpoint discovered on the target application.
Scanners operate on Endpoint objects rather than performing their own
discovery, so discovery logic lives in exactly one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ParameterLocation(str, Enum):
    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"


@dataclass
class Parameter:
    name: str
    location: ParameterLocation
    required: bool = False
    schema_type: Optional[str] = None  # e.g. "string", "integer"
    example: Any = None
    description: Optional[str] = None


@dataclass
class Endpoint:
    method: str
    path: str
    parameters: list[Parameter] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    request_body: Any = None
    content_type: Optional[str] = None
    authentication_required: bool = False
    description: Optional[str] = None

    # Free-form bag for discovery-specific extras (e.g. OpenAPI operationId).
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if not self.path.startswith("/"):
            self.path = "/" + self.path

    @property
    def query_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == ParameterLocation.QUERY]

    @property
    def path_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == ParameterLocation.PATH]

    @property
    def header_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == ParameterLocation.HEADER]

    @property
    def body_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == ParameterLocation.BODY]

    def identifier(self) -> str:
        """A stable string identifier, useful for logging and findings."""
        return f"{self.method} {self.path}"

    def resolved_path(self, path_values: Optional[dict[str, Any]] = None) -> str:
        """
        Substitute {param} placeholders in the path with concrete values.
        Falls back to leaving the placeholder in place if no value is given,
        so callers can decide how to handle missing path params.
        """
        path_values = path_values or {}
        resolved = self.path
        for param in self.path_parameters:
            if param.name in path_values:
                resolved = resolved.replace(
                    "{" + param.name + "}", str(path_values[param.name])
                )
        return resolved

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.identifier()
