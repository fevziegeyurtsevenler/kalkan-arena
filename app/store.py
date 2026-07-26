"""SQLite storage — sessions, per-attempt log (incl. PASSED prompts, the valuable data), leaderboard.

The whole point is the data engine, so we log EVERY attempt — especially the ones the guard let
through — with the guard verdict/score and the canary success label. Prompts are PII-masked before
insert (mask_safe). Nothing here writes to or reads from the production Guardian.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager

DB = os.getenv("ARENA_DB", os.path.join(os.path.dirname(__file__), "..", "arena.db"))


@contextmanager
def _conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS sessions(
          sid TEXT PRIMARY KEY, alias TEXT, consented INTEGER DEFAULT 0,
          created REAL, secrets TEXT, solved TEXT DEFAULT '[]');
        CREATE TABLE IF NOT EXISTS attempts(
          id INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT, level INTEGER, ts REAL,
          prompt_masked TEXT, guard_engine TEXT, guard_score REAL, threshold REAL,
          input_blocked INTEGER, block_reason TEXT, leaked INTEGER, ip_hash TEXT);
        CREATE INDEX IF NOT EXISTS ix_att_leaked ON attempts(leaked, input_blocked);
        """)


def new_session(alias: str = "") -> dict:
    sid = secrets.token_urlsafe(12)
    per_level_secret = {}
    for lvl in range(1, 5):
        per_level_secret[str(lvl)] = "ALT-" + secrets.token_hex(4).upper()
    with _conn() as c:
        c.execute("INSERT INTO sessions(sid,alias,consented,created,secrets,solved) VALUES(?,?,?,?,?,?)",
                  (sid, (alias or "anon")[:24], 0, time.time(), json.dumps(per_level_secret), "[]"))
    return {"sid": sid, "secrets": per_level_secret}


def consent(sid: str):
    with _conn() as c:
        c.execute("UPDATE sessions SET consented=1 WHERE sid=?", (sid,))


def get_session(sid: str):
    with _conn() as c:
        r = c.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
    return dict(r) if r else None


def secret_for(sid: str, level: int):
    s = get_session(sid)
    if not s:
        return None
    return json.loads(s["secrets"]).get(str(level))


def mark_solved(sid: str, level: int):
    s = get_session(sid)
    solved = set(json.loads(s["solved"]))
    solved.add(level)
    with _conn() as c:
        c.execute("UPDATE sessions SET solved=? WHERE sid=?", (json.dumps(sorted(solved)), sid))


def log_attempt(sid, level, prompt_masked, engine, gscore, threshold, blocked, reason, leaked, ip_hash):
    with _conn() as c:
        c.execute("""INSERT INTO attempts(sid,level,ts,prompt_masked,guard_engine,guard_score,
                     threshold,input_blocked,block_reason,leaked,ip_hash)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                  (sid, level, time.time(), prompt_masked, engine, gscore, threshold,
                   int(blocked), reason, int(leaked), ip_hash))


def leaderboard(limit=20):
    """ATTACKER leaderboard (not the guard's win-rate). Ranked by levels solved, then speed."""
    with _conn() as c:
        rows = c.execute("""SELECT alias, solved, created FROM sessions
                            WHERE solved != '[]' ORDER BY created""").fetchall()
    board = []
    for r in rows:
        solved = json.loads(r["solved"])
        board.append({"alias": r["alias"], "levels": len(solved), "top": max(solved) if solved else 0})
    board.sort(key=lambda x: (-x["levels"], -x["top"]))
    return board[:limit]


def stats():
    with _conn() as c:
        total = c.execute("SELECT COUNT(*) n FROM attempts").fetchone()["n"]
        leaked = c.execute("SELECT COUNT(*) n FROM attempts WHERE leaked=1").fetchone()["n"]
        # the GOLD: prompts that PASSED the guard but leaked the secret (confirmed hard-negatives)
        gold = c.execute("SELECT COUNT(*) n FROM attempts WHERE leaked=1 AND input_blocked=0").fetchone()["n"]
    return {"attempts": total, "leaks": leaked, "confirmed_bypasses": gold}


def export_jsonl():
    """Admin export for the data flywheel. Highlights confirmed bypasses (passed guard + leaked)."""
    with _conn() as c:
        rows = c.execute("SELECT * FROM attempts ORDER BY id").fetchall()
    lines = []
    for r in rows:
        d = dict(r)
        d["confirmed_bypass"] = bool(d["leaked"] and not d["input_blocked"])
        lines.append(json.dumps(d, ensure_ascii=False))
    return "\n".join(lines)
