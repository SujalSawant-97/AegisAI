"""
OpenAPI-based discovery.

Attempts to retrieve an OpenAPI/Swagger document from common Spring Boot
locations (springdoc-openapi / springfox defaults) and converts it into
Endpoint objects.
"""

from __future__ import annotations

from typing import Any, Optional

from core.endpoint import Endpoint, Parameter, ParameterLocation
from core.exceptions import DiscoveryError
from core.http_client import HttpClient
from core.target import Target
from discovery.base import BaseDiscovery
from utils.logging import get_logger

logger = get_logger(__name__)

# Common locations where Spring Boot apps (springdoc-openapi / springfox)
# expose their OpenAPI specification.
DEFAULT_OPENAPI_PATHS = [
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/swagger.json",
    "/openapi.json",
]

_PARAM_LOCATION_MAP = {
    "query": ParameterLocation.QUERY,
    "path": ParameterLocation.PATH,
    "header": ParameterLocation.HEADER,
    "cookie": ParameterLocation.COOKIE,
}


COMMON_FALLBACK_ROUTES: list[tuple[str, str, list[tuple[str, str, str]]]] = [
    ("GET", "/rest/products/search", [("q", "query", "string")]),
    ("GET", "/api/Users", [("id", "query", "string")]),
    ("GET", "/api/BasketItems", [("id", "query", "string")]),
    ("GET", "/api/Feedbacks", [("comment", "query", "string")]),
    ("GET", "/api/Products", [("q", "query", "string")]),
    ("GET", "/api/Cards", []),
    ("GET", "/api/SecurityQuestions", []),
    ("POST", "/rest/user/login", [("email", "body", "string"), ("password", "body", "string")]),
    ("GET", "/rest/admin/application-version", []),
    ("GET", "/api/users", [("id", "query", "string")]),
    ("GET", "/api/search", [("q", "query", "string")]),
    ("GET", "/api/admin", []),
    ("GET", "/api/login", []),
    ("GET", "/api/profile", []),
    ("GET", "/users", [("id", "query", "string")]),
    ("GET", "/search", [("q", "query", "string")]),
]


class OpenApiDiscovery(BaseDiscovery):
    def __init__(self, candidate_paths: Optional[list[str]] = None) -> None:
        self._candidate_paths = candidate_paths or DEFAULT_OPENAPI_PATHS

    @property
    def name(self) -> str:
        return "openapi"

    async def discover(self, target: Target, http_client: HttpClient) -> list[Endpoint]:
        spec = await self._fetch_spec(http_client)
        if spec is None:
            logger.info(
                "openapi_not_found_probing_fallback_routes",
                extra={"target": target.base_url, "paths_tried": self._candidate_paths},
            )
            return await self._probe_fallback_endpoints(http_client)

        return self._spec_to_endpoints(spec)

    async def _probe_fallback_endpoints(self, http_client: HttpClient) -> list[Endpoint]:
        endpoints: list[Endpoint] = [Endpoint(method="GET", path="/")]
        for method, path, params in COMMON_FALLBACK_ROUTES:
            try:
                probe_path = path if "?" in path else f"{path}?id=1&q=test"
                resp = await http_client.get(probe_path)
                if resp.status_code in (200, 201, 400, 401, 403, 500):
                    ct = resp.headers.get("content-type", "").lower()
                    if "json" in ct or resp.status_code in (401, 403, 500) or path.startswith("/rest") or path.startswith("/api"):
                        param_objs = [
                            Parameter(
                                name=p_name,
                                location=ParameterLocation.QUERY if p_loc == "query" else ParameterLocation.BODY,
                                schema_type=p_type,
                            )
                            for p_name, p_loc, p_type in params
                        ]
                        endpoints.append(
                            Endpoint(
                                method=method,
                                path=path.split("?")[0],
                                parameters=param_objs,
                                authentication_required=(resp.status_code in (401, 403)),
                            )
                        )
            except Exception:
                continue
        return endpoints

    async def _fetch_spec(self, http_client: HttpClient) -> Optional[dict[str, Any]]:
        for path in self._candidate_paths:
            try:
                response = await http_client.get(path)
            except Exception as exc:  # noqa: BLE001
                logger.debug("openapi_probe_failed", extra={"path": path, "error": str(exc)})
                continue

            if response.status_code != 200:
                continue

            try:
                spec = response.json()
            except ValueError:
                continue

            if isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec):
                logger.info("openapi_spec_found", extra={"path": path})
                return spec

        return None

    def _spec_to_endpoints(self, spec: dict[str, Any]) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Parameters defined at the path-item level apply to all operations.
            shared_params = path_item.get("parameters", [])

            for method, operation in path_item.items():
                if method.lower() not in {"get", "post", "put", "delete", "patch", "options", "head"}:
                    continue
                if not isinstance(operation, dict):
                    continue

                try:
                    endpoint = self._operation_to_endpoint(
                        method=method,
                        path=path,
                        operation=operation,
                        shared_params=shared_params,
                    )
                    endpoints.append(endpoint)
                except Exception as exc:  # noqa: BLE001
                    # Don't let one malformed operation break the whole discovery run.
                    logger.warning(
                        "openapi_operation_parse_failed",
                        extra={"path": path, "method": method, "error": str(exc)},
                    )

        if not endpoints:
            raise DiscoveryError("OpenAPI spec was retrieved but contained no usable operations.")

        return endpoints

    def _operation_to_endpoint(
        self,
        method: str,
        path: str,
        operation: dict[str, Any],
        shared_params: list[dict[str, Any]],
    ) -> Endpoint:
        parameters: list[Parameter] = []

        for raw_param in [*shared_params, *operation.get("parameters", [])]:
            location = _PARAM_LOCATION_MAP.get(raw_param.get("in", "query"))
            if location is None:
                continue
            schema = raw_param.get("schema", {})
            parameters.append(
                Parameter(
                    name=raw_param.get("name", ""),
                    location=location,
                    required=bool(raw_param.get("required", False)),
                    schema_type=schema.get("type"),
                    description=raw_param.get("description"),
                )
            )

        request_body_spec = operation.get("requestBody")
        content_type = None
        request_body = None
        if request_body_spec:
            content = request_body_spec.get("content", {})
            if content:
                content_type = next(iter(content.keys()), None)
                schema = content.get(content_type, {}).get("schema") if content_type else None
                request_body = schema
                if request_body_spec.get("required"):
                    parameters.append(
                        Parameter(
                            name="body",
                            location=ParameterLocation.BODY,
                            required=True,
                            schema_type="object",
                        )
                    )

        security = operation.get("security")
        auth_required = bool(security)

        return Endpoint(
            method=method,
            path=path,
            parameters=parameters,
            request_body=request_body,
            content_type=content_type,
            authentication_required=auth_required,
            description=operation.get("summary") or operation.get("description"),
            metadata={"operation_id": operation.get("operationId")},
        )
