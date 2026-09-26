"""Indic-aware text normalisation.

Attackers bypass English-only guardrails by switching script (Devanagari, Tamil),
writing Hindi in Roman script (Hinglish), or hiding characters (zero-width,
homoglyphs, leetspeak). This module maps all of those onto one canonical,
lower-case Roman form so a single set of detectors can reason over it.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# --- invisible / bidi characters used to split trigger words -----------------
_INVISIBLE = re.compile("[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁪-⁯﻿]")

# --- Cyrillic / Greek look-alikes -> Latin ----------------------------------
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "Ү": "Y",
    "α": "a", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u",
})

# leetspeak is only applied to letters sandwiched in words, so amounts survive
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}

# --- Devanagari -> Roman (lightweight, tuned for keyword matching) ----------
_DEV_CONS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j",
    "झ": "jh", "ञ": "n", "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t",
    "थ": "th", "द": "d", "ध": "dh", "न": "n", "प": "p", "फ": "f", "ब": "b", "भ": "bh",
    "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh", "ष": "sh", "स": "s",
    "ह": "h", "ळ": "l",
}
_DEV_NUKTA = {"क": "q", "ख": "kh", "ग": "g", "ज": "j", "ड": "r", "ढ": "rh", "फ": "f"}
_DEV_VOWELS = {
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu", "ए": "e", "ऐ": "ai",
    "ओ": "o", "औ": "au", "ऋ": "ri", "ऑ": "o", "ऍ": "e",
}
_DEV_MATRA = {
    "ा": "aa", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu", "े": "e", "ै": "ai", "ो": "o",
    "ौ": "au", "ृ": "ri", "ॉ": "o", "ॅ": "e",
}
_VIRAMA, _NUKTA = "्", "़"
_SCHWA = "\x01"  # placeholder for the inherent vowel, resolved per word

_INDIC_DIGITS = str.maketrans("०१२३४५६७८९௦௧௨௩௪௫௬௭௮௯", "01234567890123456789")


def devanagari_to_roman(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in _DEV_CONS:
            base = _DEV_CONS[ch]
            if i + 1 < n and text[i + 1] == _NUKTA:
                base = _DEV_NUKTA.get(ch, base)
                i += 1
            out.append(base)
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt in _DEV_MATRA:
                out.append(_DEV_MATRA[nxt])
                i += 1
            elif nxt == _VIRAMA:
                i += 1
            else:
                out.append(_SCHWA)
        elif ch in _DEV_VOWELS:
            out.append(_DEV_VOWELS[ch])
        elif ch in ("ं", "ँ"):
            out.append("n")
        elif ch == "ः":
            out.append("h")
        elif ch in ("।", "॥"):
            out.append(".")
        elif ch == _NUKTA:
            pass
        else:
            out.append(ch)
        i += 1
    s = "".join(out)
    # schwa deletion: drop the inherent vowel at the end of a word
    s = re.sub(_SCHWA + r"(?=[^a-z\x01]|$)", "", s)
    return s.replace(_SCHWA, "a")


def canonical_roman(text: str) -> str:
    """Collapse spelling variation common in Hinglish (bhool/bhul, aadhaar/adhar)."""
    s = text.lower()
    s = s.replace("ph", "f").replace("w", "v").replace("z", "j")
    s = s.replace("oo", "u").replace("ee", "i").replace("aa", "a").replace("ii", "i").replace("uu", "u")
    s = re.sub(r"([a-z])\1+", r"\1", s)
    return s


def _deleet(text: str) -> str:
    # replace a leet char only when it sits between letters: "1gn0re" -> "ignore", "50000" stays
    def repl(m: re.Match) -> str:
        return "".join(_LEET.get(c, c) for c in m.group(0))
    return re.sub(r"(?<=[a-z])[013457@$]+(?=[a-z])|\b[013457@$](?=[a-z]{2})", repl, text)


def detect_scripts(text: str) -> dict[str, int]:
    counts = {"latin": 0, "devanagari": 0, "tamil": 0, "other": 0}
    for ch in text:
        cp = ord(ch)
        if ch.isascii() and ch.isalpha():
            counts["latin"] += 1
        elif 0x0900 <= cp <= 0x097F:
            counts["devanagari"] += 1
        elif 0x0B80 <= cp <= 0x0BFF:
            counts["tamil"] += 1
        elif ch.isalpha():
            counts["other"] += 1
    return {k: v for k, v in counts.items() if v}


_HINGLISH_MARKERS = re.compile(r"\b(hai|hain|ho|karo|kar|mera|meri|mujhe|batao|bata|nahi|kya|ka|ki|ke|ko|se|jao|tum|aap|bhai|abhi|sab|saare|sabhi|pichle|chahiye|dikhao|bhejo|wapas|vapas)\b")
_TANGLISH_MARKERS = re.compile(r"\b(enna|enaku|ennoda|pannu|pannunga|venum|illa|marandhu|anuppu|sollu|ellam)\b")


@dataclass
class Normalized:
    raw: str
    cleaned: str               # invisible chars removed, NFKC, homoglyphs fixed
    roman: str                 # Devanagari transliterated, leet removed, lower-case
    canonical: str             # spelling-collapsed form used by detectors
    scripts: dict = field(default_factory=dict)
    languages: list = field(default_factory=list)
    obfuscation: list = field(default_factory=list)

    @property
    def code_mixed(self) -> bool:
        return len(self.languages) > 1


def normalize(text: str) -> Normalized:
    text = text or ""
    obf: list[str] = []
    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        obf.append("unicode-compatibility-forms")
    stripped = _INVISIBLE.sub("", nfkc)
    if stripped != nfkc:
        obf.append("zero-width/bidi characters")
    fixed = stripped.translate(_HOMOGLYPHS)
    if fixed != stripped:
        obf.append("homoglyph substitution")
    cleaned = fixed.translate(_INDIC_DIGITS)

    roman = devanagari_to_roman(cleaned).lower()
    deleeted = _deleet(roman)
    if deleeted != roman:
        obf.append("leetspeak")
    roman = deleeted
    canonical = canonical_roman(roman)

    scripts = detect_scripts(cleaned)
    langs: list[str] = []
    if "devanagari" in scripts:
        langs.append("hi")
    if "tamil" in scripts:
        langs.append("ta")
    if "latin" in scripts:
        latin_only = re.sub(r"[^\x00-\x7f]", " ", _deleet(cleaned.lower()))
        if _HINGLISH_MARKERS.search(latin_only):
            langs.append("hi-Latn")
        if _TANGLISH_MARKERS.search(latin_only):
            langs.append("ta-Latn")
        if re.search(r"\b(the|is|my|please|what|and|to|of|you|your|all|ignore|now)\b", latin_only) or not langs:
            langs.append("en")
    return Normalized(text, cleaned, roman, canonical, scripts, langs, obf)


if __name__ == "__main__":  # python -m sentinel.normalize "text"
    import sys
    n = normalize(" ".join(sys.argv[1:]))
    print("canonical:", n.canonical)
    print("languages:", n.languages, "| obfuscation:", n.obfuscation or "none")
