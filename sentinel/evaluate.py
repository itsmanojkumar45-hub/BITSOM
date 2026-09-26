"""Before/after evaluation across three modes.

python -m sentinel.evaluate            # prints table, writes docs/eval_results.json
"""
from __future__ import annotations

import json
from pathlib import Path

from .gateway import Gateway

ROOT = Path(__file__).resolve().parent.parent
A = ROOT / "attacks"
MODES = ("off", "baseline", "sentinel")


def load_cases() -> tuple[list, list]:
    attacks = json.loads((A / "policy_cases.json").read_text(encoding="utf-8"))
    for c in attacks:
        c["suite"] = "policy"
    for name in ("attacks.json",):
        p = A / name
        if p.exists():
            for c in json.loads(p.read_text(encoding="utf-8")).get("cases", []):
                if c.get("message", "TODO") != "TODO":
                    c["suite"] = "red-team"
                    attacks.append(c)
    benign = json.loads((A / "benign.json").read_text(encoding="utf-8"))
    return attacks, benign


def _prevented(rec: dict) -> bool:
    if rec["harm"]:
        return False
    if rec["blocked"]:
        return True
    return any(f["id"] == "pii_output" for f in rec["findings"])


def run() -> dict:
    attacks, benign = load_cases()
    gw = Gateway()
    rows = []
    summary = {m: {"attacks": len(attacks), "prevented": 0, "benign": len(benign), "benign_ok": 0, "latency_ms": []} for m in MODES}
    for mode in MODES:
        for c in attacks:
            gw.bank.reset()
            r = gw.process(c["message"], c.get("document", ""), mode)
            ok = _prevented(r)
            summary[mode]["prevented"] += ok
            summary[mode]["latency_ms"].append(r["latency_ms"])
            rows.append({"mode": mode, "id": c["id"], "suite": c["suite"], "lang": c["lang"], "category": c["category"],
                         "prevented": ok, "harm": r["harm"], "layers": sorted({f["layer"] for f in r["findings"]})})
        for c in benign:
            gw.bank.reset()
            r = gw.process(c["message"], "", mode)
            ok = (not r["input_blocked"]) and not r["denied"] and any(e["tool"] == c["expected_tool"] for e in r["executed"])
            summary[mode]["benign_ok"] += ok
            rows.append({"mode": mode, "id": c["id"], "suite": "benign", "lang": c["lang"], "category": "benign",
                         "prevented": None, "benign_ok": ok})
    for m in MODES:
        lat = summary[m].pop("latency_ms")
        summary[m]["avg_latency_ms"] = round(sum(lat) / max(len(lat), 1), 2)
        summary[m]["prevention_rate"] = round(summary[m]["prevented"] / max(summary[m]["attacks"], 1), 3)
        summary[m]["benign_pass_rate"] = round(summary[m]["benign_ok"] / max(summary[m]["benign"], 1), 3)
    gw.bank.reset()
    return {"summary": summary, "rows": rows, "rules_loaded": len(gw.detector.rules)}


if __name__ == "__main__":
    res = run()
    print(f"rules loaded: {res['rules_loaded']}")
    print(f"{'mode':10} {'attacks prevented':>20} {'benign served':>16} {'avg ms':>8}")
    for m, s in res["summary"].items():
        print(f"{m:10} {s['prevented']:>9}/{s['attacks']:<3} ({s['prevention_rate']:.0%}) {s['benign_ok']:>6}/{s['benign']:<3} ({s['benign_pass_rate']:.0%}) {s['avg_latency_ms']:>7}")
    for r in res["rows"]:
        if r["mode"] == "sentinel" and r["suite"] != "benign" and not r["prevented"]:
            print("  MISSED:", r["id"], r["category"])
        if r["mode"] == "sentinel" and r["suite"] == "benign" and not r["benign_ok"]:
            print("  FALSE POSITIVE / FAIL:", r["id"])
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "eval_results.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
