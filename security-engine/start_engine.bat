@echo off
title Security Engine (FastAPI on Port 8000)
cd /d "%~dp0"
echo =========================================================
echo    Starting Security Engine on http://localhost:8000
echo =========================================================
call .venv\Scripts\activate.bat
".venv\Scripts\python.exe" run.py
pause
