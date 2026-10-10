"""
CLI entrypoint for the security scanner engine.

Usage:
    python -m app.main scanners
    python -m app.main discover --target http://localhost:8080
    python -m app.main scan --target http://localhost:8080 --scanners headers,cors
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from app.config import DEFAULT_TIMEOUT_SECONDS, build_scanner_manager
from core.endpoint import Endpoint
from core.exceptions import ScannerEngineError
from core.http_client import HttpClient
from core.scan_context import AuthContext, ScanContext
from core.target import Target
from discovery.openapi import OpenApiDiscovery

# Map user-facing short scanner names (as used on the CLI) to the
# ScannerManager's registered names.
SCANNER_ALIASES = {
    "headers": "security_headers",
    "security_headers": "security_headers",
    "cors": "cors",
    "auth": "authentication",
    "authentication": "authentication",
    "authz": "authorization",
    "authorization": "authorization",
    "sqli": "sqli",
    "sql": "sqli",
    "xss": "xss",
}


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scanners_parser = subparsers.add_parser("scanners", help="List available scanners.")
    scanners_parser.set_defaults(func=_cmd_scanners)

    discover_parser = subparsers.add_parser("discover", help="Discover API endpoints for a target.")
    discover_parser.add_argument("--target", required=True, help="Base URL, e.g. http://localhost:8080")
    discover_parser.set_defaults(func=_cmd_discover)

    scan_parser = subparsers.add_parser("scan", help="Run one or more scanners against a target.")
    scan_parser.add_argument("--target", required=True, help="Base URL, e.g. http://localhost:8080")
    scan_parser.add_argument(
        "--scanners",
        required=True,
        help="Comma-separated scanner names, e.g. headers,cors,sqli,xss or 'all'",
    )
    scan_parser.add_argument(
        "--auth-token",
        required=False,
        default=None,
        help="Valid authentication token for authenticated scans",
    )
    scan_parser.add_argument(
        "--low-priv-token",
        required=False,
        default=None,
        help="Low-privilege authentication token for authorization/BOLA/BFLA scans",
    )
    scan_parser.set_defaults(func=_cmd_scan)

    server_parser = subparsers.add_parser("server", help="Start the FastAPI REST server.")
    server_parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    server_parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    server_parser.set_defaults(func=_cmd_server)

    return parser


def _cmd_scanners(args: argparse.Namespace) -> int:
    manager = build_scanner_manager()
    print("Available scanners:\n")
    for meta in manager.list_scanners():
        print(f"{meta.name}")
        print(f"    {meta.description}")
        print(f"    vulnerability_types: {', '.join(meta.vulnerability_types) or 'n/a'}")
        print(f"    risk_level: {meta.risk_level}")
        print()
    return 0


def _cmd_server(args: argparse.Namespace) -> int:
    import uvicorn

    print(f"Starting Security Engine FastAPI server on {args.host}:{args.port}...")
    uvicorn.run("app.api:app", host=args.host, port=args.port, reload=False)
    return 0


async def _discover_endpoints(target: Target, http_client: HttpClient) -> list[Endpoint]:
    discovery = OpenApiDiscovery()
    try:
        endpoints = await discovery.discover(target, http_client)
    except ScannerEngineError as exc:
        print(f"Discovery warning: {exc}", file=sys.stderr)
        endpoints = []

    if not endpoints:
        # Fall back to at least scanning the root path so scanners that
        # sample "a few GET endpoints" still have something to work with.
        endpoints = [Endpoint(method="GET", path="/")]

    return endpoints


def _cmd_discover(args: argparse.Namespace) -> int:
    async def run() -> int:
        target = Target(base_url=args.target)
        async with HttpClient(
            base_url=target.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
        ) as http_client:
            endpoints = await _discover_endpoints(target, http_client)

        print(json.dumps([_endpoint_to_dict(e) for e in endpoints], indent=2))
        return 0

    return asyncio.run(run())


def _endpoint_to_dict(endpoint: Endpoint) -> dict:
    return {
        "method": endpoint.method,
        "path": endpoint.path,
        "authentication_required": endpoint.authentication_required,
        "description": endpoint.description,
        "parameters": [
            {
                "name": p.name,
                "location": p.location.value,
                "required": p.required,
                "type": p.schema_type,
            }
            for p in endpoint.parameters
        ],
    }


def _cmd_scan(args: argparse.Namespace) -> int:
    requested_names = [s.strip() for s in args.scanners.split(",") if s.strip()]
    manager = build_scanner_manager()

    if "all" in requested_names:
        resolved_names = [meta.name for meta in manager.list_scanners()]
    else:
        try:
            resolved_names = [SCANNER_ALIASES[n] for n in requested_names]
        except KeyError as exc:
            print(f"Unknown scanner: {exc.args[0]}. Run 'scanners' to see available options.", file=sys.stderr)
            return 1

    async def run() -> int:
        target = Target(base_url=args.target)

        auth = AuthContext(
            scheme="Bearer",
            valid_token=args.auth_token,
            low_privilege_token=args.low_priv_token,
        )

        async with HttpClient(
            base_url=target.base_url, timeout_seconds=DEFAULT_TIMEOUT_SECONDS
        ) as http_client:
            endpoints = await _discover_endpoints(target, http_client)
            context = ScanContext(
                target=target,
                endpoints=endpoints,
                http_client=http_client,
                auth=auth,
            )
            result = await manager.run(resolved_names, context)

        output = {
            "scan_id": context.scan_id,
            "target": target.base_url,
            "status": "completed",
            "summary": context.get_summary(),
            "findings": [f.to_dict() for f in context.findings],
            "scanner_errors": [e.to_dict() for e in context.scanner_errors],
        }
        print(json.dumps(output, indent=2))
        return 0

    return asyncio.run(run())


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except ScannerEngineError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
