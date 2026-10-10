"""
Convenience entry point for the Security Engine.
Run this file directly using:
    python run.py
"""

import os
import subprocess
import sys

# Auto-detect and switch to .venv if running outside the virtual environment
_venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv", "Scripts", "python.exe")
if os.path.exists(_venv_python) and os.path.abspath(sys.executable).lower() != os.path.abspath(_venv_python).lower():
    sys.exit(subprocess.call([_venv_python] + sys.argv))

import uvicorn
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Starting Security Engine API & LangGraph Agent...")
    print("  URL: http://localhost:8000")
    print("  Docs: http://localhost:8000/docs")
    print("=" * 60 + "\n")
    
    uvicorn.run(
        "app.api:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
