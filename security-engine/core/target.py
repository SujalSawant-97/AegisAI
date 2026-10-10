"""
Target model.

A Target represents the application under test. This engine is intentionally
restricted to local, authorized targets (localhost / 127.0.0.1 / ::1) to keep
the tool safe for local development / authorized testing use only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

from core.exceptions import InvalidTargetError

# Hosts that are considered "local" and therefore in-scope by default.
ALLOWED_LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "[::1]",
    "host.docker.internal",
}


class TargetScope(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    # Placeholder for future, explicitly-opted-in scopes (e.g. authorized
    # staging environments). Not used by default and not enabled by this
    # version of the engine.
    EXPLICIT_ALLOWLIST = "EXPLICIT_ALLOWLIST"


@dataclass
class Target:
    base_url: str
    host: str = field(init=False)
    port: int | None = field(init=False)
    protocol: str = field(init=False)
    scope: TargetScope = TargetScope.LOCAL_ONLY

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)

        if parsed.scheme not in ("http", "https"):
            raise InvalidTargetError(
                f"Unsupported protocol '{parsed.scheme}' in target '{self.base_url}'. "
                "Only http and https are supported."
            )

        if not parsed.hostname:
            raise InvalidTargetError(f"Could not parse host from target '{self.base_url}'.")

        self.protocol = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port

        # Normalize base_url (strip trailing slash) so path joining is predictable.
        self.base_url = self.base_url.rstrip("/")

        # If running inside Docker and AUTO_MAP_LOCALHOST_TO_HOST_DOCKER_INTERNAL=true,
        # seamlessly map localhost targets to host.docker.internal so container can reach the host
        if os.environ.get("AUTO_MAP_LOCALHOST_TO_HOST_DOCKER_INTERNAL", "false").lower() in ("true", "1", "yes"):
            if self.host.lower() in ("localhost", "127.0.0.1", "::1", "[::1]"):
                netloc_replacement = f"host.docker.internal:{self.port}" if self.port else "host.docker.internal"
                parsed = parsed._replace(netloc=netloc_replacement)
                self.base_url = parsed.geturl().rstrip("/")
                self.host = "host.docker.internal"

        self._validate_scope()

    def _validate_scope(self) -> None:
        """
        Enforce local-only scope by default.

        This is a deliberate safety guardrail: the engine must not be usable
        to scan arbitrary external targets without an explicit, separate
        opt-in mechanism that does not exist in this version.
        """
        if self.scope == TargetScope.LOCAL_ONLY:
            host_lower = self.host.lower()
            is_local = (
                host_lower in {h.lower() for h in ALLOWED_LOCAL_HOSTS}
                or host_lower.endswith(".internal")
                or host_lower.endswith(".local")
                or "." not in host_lower  # Docker container names (e.g. vulnerable-app, juice-shop)
            )
            if not is_local:
                raise InvalidTargetError(
                    f"Target host '{self.host}' is not a recognized local or container address. "
                    f"This engine only supports local targets ({sorted(ALLOWED_LOCAL_HOSTS)}) "
                    "to ensure it is only used against applications you are authorized to test."
                )
        else:
            # No other scope is implemented yet.
            raise InvalidTargetError(
                f"Scope '{self.scope}' is not supported in this version of the engine."
            )

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.base_url
