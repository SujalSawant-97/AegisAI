"""
Vulnerable Dummy Application for Testing the AI Security Scanning Platform.

This application intentionally contains realistic vulnerabilities to verify and benchmark
the 6 core security engine scanners:
  1. Security Headers Scanner (Missing CSP, X-Frame-Options, X-Content-Type-Options)
  2. CORS Scanner (Overly permissive reflection of Origin + Allow-Credentials: true)
  3. Authentication Scanner (Unauthenticated access to sensitive endpoints, invalid token acceptance, stack trace leak)
  4. Authorization Scanner (BFLA on admin endpoints, BOLA/IDOR on path and query parameters)
  5. SQL Injection Scanner (Error-based via SQLite syntax error, and Boolean-based differential)
  6. Reflected XSS Scanner (Unescaped parameter reflection in HTML)

Port: 8082
Target URL: http://localhost:8082
OpenAPI Specification: http://localhost:8082/openapi.json
Interactive Swagger UI: http://localhost:8082/docs
"""

import sqlite3
from typing import Optional
from fastapi import FastAPI, Request, Query, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

app = FastAPI(
    title="Vulnerable Test Application",
    description="Intentionally vulnerable API designed for security scanner evaluation",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
)

# ------------------------------------------------------------------------------
# In-Memory SQLite Database Setup
# ------------------------------------------------------------------------------
db_conn = sqlite3.connect(":memory:", check_same_thread=False)
db_cursor = db_conn.cursor()

db_cursor.execute("""
    CREATE TABLE products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        price REAL,
        description TEXT
    )
""")

db_cursor.executemany("""
    INSERT INTO products (id, name, price, description) VALUES (?, ?, ?, ?)
""", [
    (1, "Enterprise Laptop X1", 1499.99, "Flagship developer workstation"),
    (2, "Ergonomic Mechanical Keyboard", 129.50, "Tactile switches with RGB backlight"),
    (3, "Noise-Cancelling Headphones", 249.00, "Wireless over-ear headset with ANC"),
    (4, "Ultra-Wide 4K Monitor", 699.00, "34-inch curved display for productivity"),
])
db_conn.commit()


# ------------------------------------------------------------------------------
# 1 & 2. Vulnerable CORS & Security Headers Middleware
# ------------------------------------------------------------------------------
@app.middleware("http")
async def security_testing_middleware(request: Request, call_next):
    """
    Middleware that:
    1. Deliberately reflects any incoming Origin with Access-Control-Allow-Credentials: true (Vulnerable CORS)
    2. Leaves out Content-Security-Policy, X-Frame-Options, X-Content-Type-Options (Vulnerable Headers)
    """
    origin = request.headers.get("origin")
    response = await call_next(request)

    # DELIBERATELY VULNERABLE CORS:
    # Reflects probe origins (such as 'https://attacker-controlled.example' or 'null')
    # and combines with Allow-Credentials: true
    if origin is not None:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"

    return response


# ------------------------------------------------------------------------------
# Root Endpoint
# ------------------------------------------------------------------------------
@app.get("/", summary="Application Status", tags=["General"])
async def root():
    return {
        "status": "online",
        "service": "Vulnerable Security Engine Benchmark Target",
        "port": 8082,
        "endpoints": [
            "/api/products/search?id=1",
            "/api/items/filter?id=1",
            "/api/search?q=test",
            "/api/user/profile",
            "/api/secure/analytics",
            "/api/auth/debug-login",
            "/api/admin/system-metrics",
            "/api/users/{id}",
            "/api/documents?document_id=1"
        ],
        "openapi": "/openapi.json"
    }


# ------------------------------------------------------------------------------
# 3. SQL Injection Endpoints (SQLi Scanner)
# ------------------------------------------------------------------------------
@app.get("/api/products/search", summary="Search product by ID (Error-based SQLi)", tags=["SQL Injection"])
async def search_product_error_sqli(id: str = Query("1", description="Product ID to look up")):
    """
    DELIBERATELY VULNERABLE: Direct SQL concatenation triggering raw sqlite3.OperationalError
    when quotes or escape characters are injected.
    """
    raw_query = f"SELECT id, name, price, description FROM products WHERE id = {id}"
    try:
        cursor = db_conn.cursor()
        cursor.execute(raw_query)
        rows = cursor.fetchall()
        if not rows:
            return JSONResponse(status_code=404, content={"message": f"Product id '{id}' not found"})
        return [
            {"id": r[0], "name": r[1], "price": r[2], "description": r[3]}
            for r in rows
        ]
    except Exception as exc:
        # Deliberately expose raw sqlite3.OperationalError string in 500 response
        return PlainTextResponse(f"Database error: sqlite3.OperationalError: {exc}", status_code=500)


@app.get("/api/items/filter", summary="Filter catalog item (Boolean-based Blind SQLi)", tags=["SQL Injection"])
async def filter_item_boolean_sqli(id: str = Query("1", description="Item ID")):
    """
    DELIBERATELY VULNERABLE: Responds normally (200 OK) when condition is TRUE,
    and diverges (404 Not Found) when condition is FALSE.
    """
    raw_query = f"SELECT id, name, price FROM products WHERE id = {id}"
    try:
        cursor = db_conn.cursor()
        cursor.execute(raw_query)
        rows = cursor.fetchall()
        if rows:
            # Consistent baseline response
            return {
                "status": "success",
                "total_matched": len(rows),
                "item": {"id": rows[0][0], "name": rows[0][1], "price": rows[0][2]}
            }
        else:
            # Divergent FALSE response
            return JSONResponse(
                status_code=404,
                content={"status": "not_found", "message": "No catalog item matched your query filter."}
            )
    except Exception:
        return JSONResponse(status_code=500, content={"status": "error", "message": "Query evaluation failed"})


# ------------------------------------------------------------------------------
# 4. Reflected Cross-Site Scripting (XSS Scanner)
# ------------------------------------------------------------------------------
@app.get("/api/search", response_class=HTMLResponse, summary="Catalog search (Reflected XSS)", tags=["Cross-Site Scripting"])
async def search_catalog_xss(q: str = Query("test", description="Search query string")):
    """
    DELIBERATELY VULNERABLE: Directly reflects query parameter 'q' into HTML response
    without HTML entity encoding or Content-Security-Policy header.
    """
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Catalog Search Results</title>
</head>
<body>
    <div class="header">
        <h1>Vulnerable Store Catalog Search</h1>
    </div>
    <div class="search-feedback">
        <p>Results for search query: <strong>{q}</strong></p>
    </div>
    <div class="results-list">
        <p>No products matched your search criteria.</p>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html_content)


# ------------------------------------------------------------------------------
# 5. Authentication Vulnerabilities (Authentication Scanner)
# ------------------------------------------------------------------------------
@app.get("/api/user/profile", summary="User profile (Unauthenticated Access Bypass)", tags=["Authentication"])
async def get_user_profile():
    """
    DELIBERATELY VULNERABLE: Sensitive user profile route that permits unauthenticated access
    and returns HTTP 200 OK instead of requiring an Authorization header.
    """
    return {
        "status": "authenticated",
        "user_id": 101,
        "username": "sarah_connor",
        "email": "sarah@resistance.corp",
        "role": "standard_user",
        "profile_type": "sensitive_internal_data"
    }


@app.get("/api/secure/analytics", summary="Secure telemetry analytics (Invalid Token Acceptance)", tags=["Authentication"])
async def get_secure_analytics(authorization: Optional[str] = Header(None)):
    """
    DELIBERATELY VULNERABLE: Rejects unauthenticated requests (401), but accepts ANY
    bearer token—even invalid or corrupted ones—without cryptographic verification (200 OK).
    """
    if not authorization:
        return JSONResponse(status_code=401, content={"error": "Missing Authorization header"})

    # Deliberately skips token validation and grants access to any provided token!
    return {
        "status": "authorized",
        "authenticated_token": authorization[:15] + "...",
        "telemetry": {
            "active_nodes": 12,
            "bandwidth_usage_mbps": 450.2,
            "security_alerts_cleared": True
        }
    }


@app.get("/api/auth/debug-login", summary="Authentication debug handler (Information Disclosure)", tags=["Authentication"])
async def debug_login(authorization: Optional[str] = Header(None)):
    """
    DELIBERATELY VULNERABLE: Returns unhandled Python traceback upon authentication failure,
    leaking internal stack frames.
    """
    traceback_str = (
        'Traceback (most recent call last):\n'
        '  File "vulnerable_app/auth/verifier.py", line 47, in verify_jwt_signature\n'
        '    decoded = jwt.decode(token, secret_key, algorithms=["HS256"])\n'
        '  File "vulnerable_app/core/crypto.py", line 112, in parse_claims\n'
        '    raise NullPointerException("Invalid signature or expired token context")\n'
        'NullPointerException: Signature verification failed for token context'
    )
    return PlainTextResponse(traceback_str, status_code=500)


# ------------------------------------------------------------------------------
# 6. Authorization Vulnerabilities (Authorization Scanner)
# ------------------------------------------------------------------------------
@app.get("/api/admin/system-metrics", summary="Administrative Metrics (BFLA)", tags=["Authorization"])
async def get_admin_system_metrics(authorization: Optional[str] = Header(None)):
    """
    DELIBERATELY VULNERABLE: Broken Function Level Authorization (BFLA / Privilege Escalation).
    Administrative path (/api/admin/...) that permits access to low-privilege tokens.
    """
    return {
        "status": "admin_granted",
        "endpoint": "/api/admin/system-metrics",
        "admin_privileges": {
            "root_access": True,
            "cluster_restart_allowed": True,
            "database_dump_allowed": True,
            "active_admin_session": "admin-session-98432"
        }
    }


@app.get("/api/users/{id}", summary="Get user account by ID (BOLA/IDOR in Path)", tags=["Authorization"])
async def get_user_by_path_id(id: str = "1", authorization: Optional[str] = Header(None)):
    """
    DELIBERATELY VULNERABLE: Broken Object Level Authorization (BOLA/IDOR).
    Path parameter {id} allows switching to any other user's record (e.g. id=2)
    without verifying ownership.
    """
    users_db = {
        "1": {"id": "1", "name": "Alice Johnson (You)", "email": "alice@example.com", "balance": 1250.00},
        "2": {"id": "2", "name": "Bob Smith (Victim User)", "email": "bob@example.com", "balance": 985000.00},
        "3": {"id": "3", "name": "Charlie Davis", "email": "charlie@example.com", "balance": 4320.00},
    }
    user_data = users_db.get(id, {"id": id, "name": f"User {id}", "email": f"user{id}@example.com", "balance": 0.00})
    return {
        "status": "success",
        "user": user_data
    }


@app.get("/api/documents", summary="Get confidential document (BOLA/IDOR in Query Param)", tags=["Authorization"])
async def get_document_by_query_id(document_id: str = Query("1", description="Document ID"), authorization: Optional[str] = Header(None)):
    """
    DELIBERATELY VULNERABLE: Broken Object Level Authorization (BOLA/IDOR).
    Query parameter ?document_id= allows arbitrary document retrieval.
    """
    docs_db = {
        "1": {"document_id": "1", "title": "Company Public Guidelines", "classification": "PUBLIC", "content": "Welcome to our public company guide."},
        "2": {"document_id": "2", "title": "Confidential Merger & Acquisition Plan", "classification": "TOP SECRET", "content": "Confidential details on acquiring competitor X for $50M."},
        "3": {"document_id": "3", "title": "Executive Payroll Records", "classification": "RESTRICTED", "content": "CEO: $2.4M, CTO: $1.8M, CFO: $1.6M."},
    }
    doc_data = docs_db.get(document_id, {"document_id": document_id, "title": f"Document #{document_id}", "classification": "INTERNAL", "content": "Content placeholder."})
    return {
        "status": "success",
        "document": doc_data
    }
