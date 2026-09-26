"""Output gate: detect and mask Indian financial / identity identifiers.

Aadhaar numbers are validated with the Verhoeff checksum and cards with Luhn to
keep false positives low (a random 12-digit reference number is not masked).
"""
from __future__ import annotations

import re

# ---- Verhoeff (Aadhaar checksum) --------------------------------------------
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]


def verhoeff_valid(num: str) -> bool:
    c = 0
    for i, d in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(d)]]
    return c == 0


def verhoeff_generate(base: str) -> str:
    c = 0
    for i, d in enumerate(reversed(base)):
        c = _D[c][_P[(i + 1) % 8][int(d)]]
    return base + str(_INV[c])


def luhn_valid(num: str) -> bool:
    s, alt = 0, False
    for d in reversed(num):
        n = int(d)
        if alt:
            n *= 2
            n -= 9 if n > 9 else 0
        s += n
        alt = not alt
    return s % 10 == 0


AADHAAR = re.compile(r"(?<!\d)([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?!\d)")
PAN = re.compile(r"\b([A-Z]{3}[PCHABGJLFT][A-Z])(\d{4})([A-Z])\b")
CARD = re.compile(r"(?<!\d)(\d[ -]?){12,18}\d(?!\d)")
MOBILE = re.compile(r"(?<!\d)(\+?91[ -]?)?([6-9]\d{4})[ -]?(\d{5})(?!\d)")
UPI = re.compile(r"\b[\w.\-]{2,}@(okaxis|okhdfcbank|oksbi|okicici|ybl|ibl|axl|paytm|upi|apl)\b", re.I)
IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")


def redact(text: str) -> tuple[str, list[dict]]:
    hits: list[dict] = []

    def aadhaar(m):
        digits = "".join(m.groups())
        if not verhoeff_valid(digits):
            return m.group(0)
        hits.append({"type": "Aadhaar", "masked": f"XXXX XXXX {digits[-4:]}"})
        return f"XXXX XXXX {digits[-4:]}"

    def card(m):
        digits = re.sub(r"\D", "", m.group(0))
        if not (13 <= len(digits) <= 19 and luhn_valid(digits)):
            return m.group(0)
        hits.append({"type": "Card", "masked": f"**** {digits[-4:]}"})
        return f"**** **** **** {digits[-4:]}"

    def pan(m):
        hits.append({"type": "PAN", "masked": f"{m.group(1)[:2]}XXXXXXX{m.group(3)}"})
        return f"{m.group(1)[:2]}XXXXXXX{m.group(3)}"

    def mobile(m):
        hits.append({"type": "Mobile", "masked": f"XXXXXX{m.group(3)[-4:]}"})
        return f"XXXXXX{m.group(3)[-4:]}"

    def upi(m):
        hits.append({"type": "UPI ID", "masked": "****@" + m.group(1)})
        return "****@" + m.group(1)

    text = CARD.sub(card, text)
    text = AADHAAR.sub(aadhaar, text)
    text = PAN.sub(pan, text)
    text = MOBILE.sub(mobile, text)
    text = UPI.sub(upi, text)
    return text, hits
