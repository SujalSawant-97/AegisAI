# Vulnerable Test Application (Port 8082)

This is a deliberately vulnerable application built specifically for testing and evaluating the **AI-Powered Vulnerability Detection Platform**.

It runs on **port 8082** using FastAPI and an in-memory SQLite database, requiring **no external databases or extra setup** (it reuses the existing `.venv` environment).

---

## 🚀 How to Run

### Method 1: Double-Click Batch File
Run `start_vulnerable_app.bat` in the project root.

### Method 2: Command Line
```powershell
cd "C:\Users\sujal\AI Powered Vurnabllity Detection Platform"
.\security-engine\.venv\Scripts\python.exe vulnerable-app\run.py
```

The app will start on:
- **Base URL:** `http://localhost:8082`
- **Swagger Docs:** `http://localhost:8082/docs`
- **OpenAPI Schema:** `http://localhost:8082/openapi.json`

---

## 🎯 Vulnerability Matrix vs Platform Scanners

| Scanner | Endpoint | Method | How It Works & Vulnerability Triggered |
| :--- | :--- | :---: | :--- |
| **Security Headers** | `/` (and all routes) | `GET` | Missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`. |
| **CORS Scanner** | `/` (and all routes) | `GET` | Middleware reflects untrusted `Origin: https://attacker-controlled.example` and `null` with `Access-Control-Allow-Credentials: true`. |
| **SQLi Scanner (Error-based)** | `/api/products/search?id=1` | `GET` | Raw SQL concatenation. Injecting `'` produces raw `sqlite3.OperationalError` syntax error in HTTP 500 response. |
| **SQLi Scanner (Boolean-based)** | `/api/items/filter?id=1` | `GET` | Injecting `1 OR 1=1` produces 200 OK (item found), while `1 AND 1=2` produces 404 (divergence). |
| **XSS Scanner (Reflected)** | `/api/search?q=test` | `GET` | Injected `<xss_canary>` payload is reflected directly in `text/html` response without entity encoding. |
| **Authentication Scanner** | `/api/user/profile` | `GET` | Sensitive endpoint permits unauthenticated access without tokens (returns 200 OK). |
| **Authentication Scanner** | `/api/secure/analytics` | `GET` | Returns 401 when unauthenticated, but accepts intentionally forged/invalid tokens with 200 OK. |
| **Authentication Scanner** | `/api/auth/debug-login` | `GET` | Leaks internal Python traceback / `NullPointerException` stack trace in HTTP 500 response. |
| **Authorization Scanner (BFLA)** | `/api/admin/system-metrics` | `GET` | Admin endpoint grants access to low-privilege tokens without role check (returns 200 OK). |
| **Authorization Scanner (BOLA / IDOR)** | `/api/users/{id}` | `GET` | Path IDOR: Swapping `{id}` from 1 to 2 exposes victim user account without ownership check. |
| **Authorization Scanner (BOLA / IDOR)** | `/api/documents?document_id=1` | `GET` | Query IDOR: Changing `document_id` to 2 exposes confidential M&A documents. |

---

## 🔍 How to Test from Platform

1. Make sure your complete platform is running (`start_all.bat` or individual services).
2. Start this test app (`start_vulnerable_app.bat`).
3. Open the Frontend at `http://localhost:5173`.
4. Go to **Targets** $\rightarrow$ Click **Add Target**:
   - **Target URL:** `http://localhost:8082`
   - **Description:** `Vulnerable Test Benchmark Target`
5. Click **Start Scan** (or use Interactive AI Chat).
6. Observe all 6 scanners automatically discovering endpoints via `/openapi.json` and reporting findings with full evidence!
