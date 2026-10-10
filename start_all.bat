@echo off
title AI Powered Vulnerability Platform Launcher
echo ======================================================================
echo    Starting Complete AI Vulnerability Detection Platform
echo ======================================================================
echo.

cd /d "%~dp0"

echo [1/4] Launching Python Security Engine (Port 8000)...
start "SecEngine - Python FastAPI (8000)" cmd /k "cd security-engine && call .venv\Scripts\activate.bat && .venv\Scripts\python.exe run.py"

timeout /t 3 /nobreak >nul

echo [2/4] Launching Spring Boot Backend (Port 8081)...
start "SecEngine - Spring Boot (8081)" cmd /k "cd backend && call ""C:\Program Files\Apache\apache-maven-3.9.12\bin\mvn.cmd"" spring-boot:run"

timeout /t 3 /nobreak >nul

echo [3/4] Launching React Frontend (Port 5173)...
start "SecEngine - React Frontend (5173)" cmd /k "cd frontend && npm run dev"

timeout /t 3 /nobreak >nul

echo [4/4] Launching Vulnerable Test Target (Port 8082)...
start "SecEngine - Vulnerable Test App (8082)" cmd /k "call start_vulnerable_app.bat"

timeout /t 4 /nobreak >nul

echo Opening Browser...
start http://localhost:5173

echo.
echo ======================================================================
echo  Platform is running!
echo  - Frontend: http://localhost:5173
echo  - Spring Boot: http://localhost:8081
echo  - Python FastAPI: http://localhost:8000 (Docs at /docs)
echo  - Vulnerable Target App: http://localhost:8082 (Docs at /docs)
echo ======================================================================
pause
