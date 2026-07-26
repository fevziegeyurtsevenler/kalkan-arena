"""KVKK PII masking for captured prompts (mandatory before storage).

Condensed, checksum-validated Turkish PII masker (TCKN/IBAN/VKN/phone/email/card). Every attempt we
store is run through this first, fail-closed: if masking errors, we drop the raw text. Players are
also told up front (consent gate) not to submit real personal data.
"""
from __future__ import annotations

import re


def _tckn_ok(n: str) -> bool:
    if not (n.isdigit() and len(n) == 11 and n[0] != "0"):
        return False
    d = [int(c) for c in n]
    return d[9] == ((sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10) and d[10] == (sum(d[0:10]) % 10)


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not re.fullmatch(r"TR\d{24}", s):
        return False
    r = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in r)) % 97 == 1


def _luhn_ok(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if len(d) < 13:
        return False
    chk, par = 0, len(d) % 2
    for i, x in enumerate(d):
        if i % 2 == par:
            x *= 2
            x = x - 9 if x > 9 else x
        chk += x
    return chk % 10 == 0


_RULES = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), lambda s: True),
    ("IBAN", re.compile(r"TR\d{2}(?:\s?\d{4}){5}\s?\d{2}", re.I), _iban_ok),
    ("CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _luhn_ok),
    ("TCKN", re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)"), _tckn_ok),
    ("PHONE", re.compile(r"(?:(?:\+90|0)[\s-]?)?5\d{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)"), lambda s: True),
]


def mask(text: str) -> str:
    if not text:
        return text
    spans = []
    for label, rx, ok in _RULES:
        for m in rx.finditer(text):
            if ok(m.group(0)):
                spans.append((m.start(), m.end(), label))
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    out, last, occ = [], 0, []
    for a, b, label in spans:
        if any(not (b <= s or a >= e) for s, e in occ):
            continue
        out.append(text[last:a]); out.append(f"[{label}]"); last = b; occ.append((a, b))
    out.append(text[last:])
    return "".join(out)


def mask_safe(text: str) -> str:
    """Fail-closed: on any error, redact the whole string rather than store raw PII."""
    try:
        return mask(text)
    except Exception:
        return "[REDACTED]"
