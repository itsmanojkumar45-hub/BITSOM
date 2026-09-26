#!/usr/bin/env bash
set -e
python3 -m pip install -q -r requirements.txt
[ -f rules/rules.json ] || echo "note: rules/rules.json not found - input-gate rules empty; copy rules/rules.template.json and fill it in."
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
