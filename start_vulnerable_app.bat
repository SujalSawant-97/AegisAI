@echo off
title Vulnerable Test Application (Port 8082)
echo ======================================================================
echo    Starting Vulnerable Target Application on Port 8082
echo    (Used for testing AI Security Engine Scanners)
echo ======================================================================
echo.

cd /d "%~dp0"

echo Launching application using security-engine Python environment...
call "security-engine\.venv\Scripts\activate.bat"
cd vulnerable-app
python run.py

pause
