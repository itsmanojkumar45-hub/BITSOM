@echo off
REM CyberDefend AI Sentinel - one-click start (Windows). Double-click this file.
cd /d "%~dp0"
where python >nul 2>nul || (echo Python not found. Install Python 3.10+ from python.org and tick "Add Python to PATH". & pause & exit /b 1)
python -m pip install -q -r requirements.txt
python -m pytest -q
start "" http://localhost:8000
python -m uvicorn app:app --port 8000
pause
