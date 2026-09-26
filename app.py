"""AI Sentinel demo server:  uvicorn app:app --reload  ->  http://localhost:8000"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sentinel import evaluate
from sentinel.gateway import Gateway
from agent.bank_agent import SYSTEM_PROMPT
import json

ROOT = Path(__file__).parent
app = FastAPI(title="CyberDefend AI Sentinel - Indic BFSI demo")
gw = Gateway()


class ChatIn(BaseModel):
    message: str
    document: str = ""
    mode: str = "sentinel"


@app.post("/api/chat")
def chat(body: ChatIn):
    return gw.process(body.message, body.document, body.mode)


@app.post("/api/reset")
def reset():
    gw.bank.reset()
    gw.audit.clear()
    return gw.bank.snapshot()


@app.get("/api/state")
def state():
    return {"state": gw.bank.snapshot(), "rules_loaded": len(gw.detector.rules), "session": gw.session.__dict__}


@app.post("/api/reload-rules")
def reload_rules():
    return {"rules_loaded": gw.reload_rules()}


@app.get("/api/presets")
def presets():
    a = ROOT / "attacks"
    out = {"benign": json.loads((a / "benign.json").read_text("utf-8")),
           "policy": json.loads((a / "policy_cases.json").read_text("utf-8")), "red-team": []}
    if (a / "attacks.json").exists():
        out["red-team"] = [c for c in json.loads((a / "attacks.json").read_text("utf-8"))["cases"] if c["message"] != "TODO"]
    return out


@app.post("/api/eval")
def run_eval():
    res = evaluate.run()
    gw.bank.reset()
    return res


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
