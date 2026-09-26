"""Data-driven input detectors.

The detector engine is generic: rule patterns are loaded from a JSON file
(`rules/rules.json`, see `rules/rules.template.json`). Patterns run on the
*canonical* text produced by `normalize()` so a single rule catches Devanagari,
Hinglish and obfuscated variants. Native-script rules (e.g. Tamil) run on the
cleaned native text.

Rule file schema:
{
  "categories": {
    "<finding_id from findings.CATALOG>": [
      {"pattern": "<regex>", "weight": 0.0-1.0, "label": "<short description>",
       "on": "canonical" | "native", "channels": ["user", "document"]}
    ]
  }
}
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .findings import make_finding
from .normalize import Normalized

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = ROOT / "rules" / "rules.json"
TEMPLATE_RULES = ROOT / "rules" / "rules.template.json"


@dataclass
class Rule:
    category: str
    pattern: re.Pattern
    weight: float
    label: str
    on: str = "canonical"
    channels: tuple = ("user", "document")


@dataclass
class DetectionResult:
    score: float = 0.0
    findings: list = field(default_factory=list)
    matched: list = field(default_factory=list)


def load_rules(path: Path | None = None) -> list[Rule]:
    path = Path(path) if path else (DEFAULT_RULES if DEFAULT_RULES.exists() else TEMPLATE_RULES)
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    rules: list[Rule] = []
    for cat, items in data.get("categories", {}).items():
        for it in items:
            pat = it.get("pattern", "").strip()
            if not pat or pat.startswith("TODO"):
                continue  # unfilled template slot
            rules.append(Rule(cat, re.compile(pat, re.I), float(it.get("weight", 0.5)),
                              it.get("label", cat), it.get("on", "canonical"),
                              tuple(it.get("channels", ["user", "document"]))))
    return rules


class RuleDetector:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else load_rules()

    def reload(self, path: Path | None = None) -> int:
        self.rules = load_rules(path)
        return len(self.rules)

    def detect(self, norm: Normalized, channel: str = "user") -> DetectionResult:
        res = DetectionResult()
        keep = 1.0
        per_cat: dict[str, list[str]] = {}
        for r in self.rules:
            if channel not in r.channels:
                continue
            text = norm.canonical if r.on == "canonical" else norm.cleaned
            m = r.pattern.search(text)
            if m:
                keep *= (1 - r.weight)
                per_cat.setdefault(r.category, []).append(f"{r.label}: \"{m.group(0)[:60]}\"")
                res.matched.append({"category": r.category, "label": r.label, "match": m.group(0)[:60], "weight": r.weight})
        score = 1 - keep
        if per_cat and norm.obfuscation:
            score = min(1.0, score + 0.2)
            per_cat.setdefault("obfuscation", []).append(", ".join(norm.obfuscation))
        if per_cat and channel == "document":
            per_cat.setdefault("indirect_injection", []).append("instruction-like content inside attached document")
        for cat, ev in per_cat.items():
            res.findings.append(make_finding(cat, "input-gate", "; ".join(ev)))
        res.score = round(score, 3)
        return res


class EnglishOnlyBaseline:
    """What many teams ship today: English keyword filter on the raw text,
    no normalisation, no Indic awareness. Used only for comparison in eval."""

    def __init__(self, rules: list[Rule]):
        # keep only rules that are pure-ASCII patterns flagged as English
        self.rules = [r for r in rules if r.label.upper().startswith("EN")]

    def blocked(self, raw: str) -> bool:
        return any(r.pattern.search(raw.lower()) for r in self.rules)
