"""
Reusable asynchronous HTTP client for all scanners.

Scanners must never issue raw httpx/requests calls themselves — everything
goes through this client so that timeouts, headers, cookies, redirect
handling, and response normalization behave consistently, and so that
request/response logging happens in exactly one place.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from core.exceptions import HttpClientError
from utils.logging import get_logger

logger = get_logger(__name__)

# Headers that must never be written to logs.
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}


@dataclass
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_seconds: float
    url: str
    request_method: str
    redirected: bool = False
    history: list[str] = field(default_factory=list)

    def json(self) -> Any:
        import json

        return json.loads(self.body)


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        k: ("<redacted>" if k.lower() in SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


class HttpClient:
    """
    Thin, consistent async wrapper around httpx.AsyncClient.

    One HttpClient instance is expected to be shared (via ScanContext) across
    all scanners in a single scan.
    """

    def __init__(
        self,
        base_url: str,
        default_headers: Optional[dict[str, str]] = None,
        default_cookies: Optional[dict[str, str]] = None,
        timeout_seconds: float = 10.0,
        follow_redirects: bool = True,
        verify_tls: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._default_headers = default_headers or {}
        self._default_cookies = default_cookies or {}
        self._timeout = httpx.Timeout(timeout_seconds)
        self._follow_redirects = follow_redirects
        self._client: Optional[httpx.AsyncClient] = None
        self._verify_tls = verify_tls

    async def __aenter__(self) -> "HttpClient":
        await self.start()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._default_headers,
                cookies=self._default_cookies,
                timeout=self._timeout,
                follow_redirects=self._follow_redirects,
                verify=self._verify_tls,
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Any] = None,
        auth_header: Optional[str] = None,
    ) -> HttpResponse:
        if self._client is None:
            raise HttpClientError("HttpClient used before start() was called.")

        merged_headers = dict(headers or {})
        if auth_header:
            merged_headers["Authorization"] = auth_header

        start = time.perf_counter()
        try:
            response = await self._client.request(
                method,
                path,
                headers=merged_headers or None,
                cookies=cookies,
                params=params,
                json=json_body,
                data=data,
            )
        except httpx.TimeoutException as exc:
            raise HttpClientError(f"Request to {path} timed out: {exc}") from exc
        except httpx.RequestError as exc:
            raise HttpClientError(f"Request to {path} failed: {exc}") from exc

        elapsed = time.perf_counter() - start

        logger.debug(
            "http_request_completed",
            extra={
                "method": method,
                "path": path,
                "status_code": response.status_code,
                "elapsed_seconds": round(elapsed, 4),
                "request_headers": _redact_headers(merged_headers),
            },
        )

        return HttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text,
            elapsed_seconds=elapsed,
            url=str(response.url),
            request_method=method,
            redirected=len(response.history) > 0,
            history=[str(r.url) for r in response.history],
        )

    async def get(
        self,
        path: str,
        *,
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        auth_header: Optional[str] = None,
    ) -> HttpResponse:
        return await self._request(
            "GET", path, headers=headers, cookies=cookies, params=params, auth_header=auth_header
        )

    async def post(
        self,
        path: str,
        *,
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Any] = None,
        auth_header: Optional[str] = None,
    ) -> HttpResponse:
        return await self._request(
            "POST",
            path,
            headers=headers,
            cookies=cookies,
            params=params,
            json_body=json_body,
            data=data,
            auth_header=auth_header,
        )

    async def put(
        self,
        path: str,
        *,
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        data: Optional[Any] = None,
        auth_header: Optional[str] = None,
    ) -> HttpResponse:
        return await self._request(
            "PUT",
            path,
            headers=headers,
            cookies=cookies,
            params=params,
            json_body=json_body,
            data=data,
            auth_header=auth_header,
        )

    async def delete(
        self,
        path: str,
        *,
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        auth_header: Optional[str] = None,
    ) -> HttpResponse:
        return await self._request(
            "DELETE", path, headers=headers, cookies=cookies, params=params, auth_header=auth_header
        )

    async def patch(
        self,
        path: str,
        *,
        headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        auth_header: Optional[str] = None,
    ) -> HttpResponse:
        return await self._request(
            "PATCH",
            path,
            headers=headers,
            cookies=cookies,
            params=params,
            json_body=json_body,
            auth_header=auth_header,
        )
