#!/bin/bash
# CyberDefend AI Sentinel - one-click start (macOS/Linux). Double-click in Finder, or run: bash start_mac.command
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "Python 3.10+ not found. Install from python.org"; read; exit 1; }
python3 -m pip install -q -r requirements.txt || python3 -m pip install -q --user -r requirements.txt
python3 -m pytest -q
( sleep 2; open http://localhost:8000 2>/dev/null || xdg-open http://localhost:8000 ) &
python3 -m uvicorn app:app --port 8000
