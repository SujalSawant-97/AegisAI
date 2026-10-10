# Security Engine

A local-only web application security testing engine, designed to be driven
later by an AI agent. This version implements the core framework plus two
scanners (`security_headers`, `cors`) end-to-end, per the project's
development order.

## Scope and safety

This engine **only targets local applications** — `localhost`, `127.0.0.1`,
and `::1`. `core/target.py` enforces this; there is no flag to scan arbitrary
external hosts. Use it only against applications you own or are explicitly
authorized to test.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI usage

List available scanners:

```bash
python -m app.main scanners
```

Discover endpoints (tries OpenAPI locations like `/v3/api-docs`, falls back
to `/` if none are found):

```bash
python -m app.main discover --target http://localhost:8080
```

Run scanners:

```bash
python -m app.main scan --target http://localhost:8080 --scanners headers,cors
```

Output is JSON:

```json
{
  "scan_id": "SCAN-...",
  "target": "http://localhost:8080",
  "status": "completed",
  "findings": [...],
  "scanner_errors": []
}
```

## Architecture

```
AI Agent (future)
      |
Scanner Manager  --  registers/looks up/executes scanners, isolates failures
      |
  +---+----+----------+
  |        |          |
Headers   CORS   (Auth, SQLi, XSS — later)
  |        |          |
  +--------+----------+
           |
      HTTP Client (httpx, shared, one place for timeouts/logging)
           |
      Local Application (localhost only)
```

- `core/` — Target, Endpoint, Finding, ScanContext, BaseScanner, ScannerManager, HttpClient.
- `discovery/` — OpenAPI discovery + a basic HTML-link crawler fallback. No vulnerability logic.
- `scanners/` — one vulnerability category per package. Each scanner only depends on `core/`.
- `payloads/` — payload provider abstraction (used by future SQLi/XSS scanners).
- `utils/` — URL helpers, structured JSON logging (redacts secrets), response-comparison helpers.
- `tests/` — includes a tiny stdlib-only local test app with matched
  vulnerable/secure endpoints, so every scanner is checked for both true
  positives and false positives.

## Running tests

```bash
pytest
```

## What's implemented vs. planned

Implemented:
Target, Endpoint, Finding, HttpClient, ScanContext, BaseScanner,
ScannerManager, OpenAPI discovery, crawler discovery, Security Headers
scanner, CORS scanner, Authentication scanner, Authorization scanner,
SQL Injection scanner (with `payloads/sqli.py` provider), XSS scanner
(with `payloads/xss.py` provider), CLI (supporting individual scanners or `--scanners all`),
test fixtures and test suites.

Planned next: FastAPI REST interface, then AI agent integration.
The AI agent will only ever *select and interpret* scanner runs — it will not
implement HTTP requests or vulnerability detection itself.
