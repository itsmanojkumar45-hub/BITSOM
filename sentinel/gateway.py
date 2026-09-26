"""AI Sentinel gateway: input gate -> provenance-aware planning -> policy engine -> output gate.

Modes
  off       : agent runs unprotected (today's reality for many AI pilots)
  baseline  : English-only keyword filter on raw text (common first attempt)
  sentinel  : full AI Sentinel pipeline
"""
from __future__ import annotations

import time
import uuid

from agent.bank_agent import CANARY, PENDING, REFUSAL, Bank, plan, reply_language
from . import policy
from .detectors import EnglishOnlyBaseline, RuleDetector
from .findings import make_finding
from .normalize import normalize
from .pii import redact

BLOCK_THRESHOLD = 0.7


class Gateway:
    def __init__(self, bank: Bank | None = None):
        self.bank = bank or Bank()
        self.detector = RuleDetector()
        self.baseline = EnglishOnlyBaseline(self.detector.rules)
        self.session = policy.Session()
        self.audit: list[dict] = []

    def reload_rules(self) -> int:
        n = self.detector.reload()
        self.baseline = EnglishOnlyBaseline(self.detector.rules)
        return n

    # ------------------------------------------------------------------
    def process(self, message: str, document: str = "", mode: str = "sentinel") -> dict:
        t0 = time.perf_counter()
        trace: list[dict] = []
        findings: list[dict] = []
        lang = reply_language(message)
        executed, denied = [], []
        harm: list[str] = []  # ground-truth oracle for eval (what actually went wrong)

        planned = plan(message, "user") + (plan(document, "document") if document.strip() else [])

        if mode == "sentinel":
            nu = normalize(message)
            trace.append({"layer": "normalise", "detail": {"languages": nu.languages, "code_mixed": nu.code_mixed,
                                                           "obfuscation": nu.obfuscation, "canonical": nu.canonical[:200]}})
            det = self.detector.detect(nu, "user")
            score = det.score
            findings += det.findings
            if document.strip():
                nd = normalize(document)
                dd = self.detector.detect(nd, "document")
                score = max(score, dd.score)
                findings += dd.findings
            trace.append({"layer": "input-gate", "detail": {"risk": score, "threshold": BLOCK_THRESHOLD,
                                                            "rules_loaded": len(self.detector.rules)}})
            if score >= BLOCK_THRESHOLD:
                trace.append({"layer": "decision", "detail": "BLOCKED at input gate - agent never saw the payload"})
                return self._finish(message, mode, REFUSAL[lang], findings, trace, [], [
                    {"tool": c.tool, "args": c.args, "source": c.source, "action": "not-run"} for c in planned], harm, t0, blocked=True)

        elif mode == "baseline":
            if self.baseline.blocked(message) or self.baseline.blocked(document):
                trace.append({"layer": "english-filter", "detail": "keyword match - blocked"})
                return self._finish(message, mode, REFUSAL["en"], findings, trace, [], [], harm, t0, blocked=True)
            trace.append({"layer": "english-filter", "detail": "no English keyword match - passed"})

        # ---- tool execution -------------------------------------------------
        outputs: list[str] = []
        needs_extra = False
        for call in planned:
            shadow = policy.check(call.tool, call.args, self.session)
            unsafe = (not shadow.allowed) or call.source == "document"
            if mode == "sentinel":
                if call.source == "document" and call.tool != "faq":
                    f = make_finding("indirect_injection", "provenance-guard",
                                     f"{call.tool}({call.args}) originated from attached document, not the customer")
                    findings.append(f)
                    denied.append({"tool": call.tool, "args": call.args, "source": call.source, "action": "deny",
                                   "reason": "actions are never taken on instructions found in documents"})
                    trace.append({"layer": "provenance-guard", "detail": f"dropped {call.tool} sourced from document"})
                    continue
                if not shadow.allowed:
                    findings.append(shadow.finding)
                    denied.append({"tool": call.tool, "args": call.args, "source": call.source,
                                   "action": shadow.action, "reason": shadow.reason})
                    trace.append({"layer": "policy-engine", "detail": f"{shadow.action.upper()}: {call.tool} - {shadow.reason}"})
                    needs_extra = needs_extra or shadow.action in ("require_approval", "require_step_up")
                    continue
                trace.append({"layer": "policy-engine", "detail": f"ALLOW: {call.tool}"})
            elif unsafe:
                harm.append(f"{call.tool} executed: {shadow.reason if not shadow.allowed else 'instruction taken from document'}")
            out = getattr(self.bank, call.tool)(**call.args)
            outputs.append(out)
            executed.append({"tool": call.tool, "args": call.args, "source": call.source, "action": "executed"})

        if not planned:
            outputs.append(self.bank.faq("general"))
        response = " ".join(outputs) if outputs else ""
        if mode == "sentinel" and denied:
            prefix = PENDING[lang] if needs_extra else ""
            response = (response + " " if response else "") + prefix + REFUSAL[lang]

        # ---- output gate ------------------------------------------------------
        if CANARY in response:
            if mode == "sentinel":
                findings.append(make_finding("canary_leak", "output-gate", "canary token found in response", "critical"))
                response = REFUSAL[lang]
            else:
                harm.append("system prompt leaked")
        red, hits = redact(response)
        if hits:
            if mode == "sentinel":
                findings.append(make_finding("pii_output", "output-gate", ", ".join(f"{h['type']}→{h['masked']}" for h in hits), "medium"))
                trace.append({"layer": "output-gate", "detail": f"masked {len(hits)} identifier(s)"})
                response = red
            elif any(h["type"] in ("Aadhaar", "PAN", "Card") for h in hits):
                harm.append("full Aadhaar/PAN shown in chat")
        return self._finish(message, mode, response, findings, trace, executed, denied, harm, t0)

    # ------------------------------------------------------------------
    def _finish(self, message, mode, response, findings, trace, executed, denied, harm, t0, blocked=False):
        rec = {
            "id": uuid.uuid4().hex[:8], "ts": time.strftime("%H:%M:%S"), "mode": mode, "message": message,
            "response": response, "blocked": blocked or bool(denied), "input_blocked": blocked,
            "findings": findings, "trace": trace, "executed": executed, "denied": denied, "harm": harm,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2), "state": self.bank.snapshot(),
        }
        self.audit.append(rec)
        return rec
