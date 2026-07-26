"""Kalkan Arena — a Turkish "red-team our guard" jailbreak challenge that collects (consented,
PII-masked) attack data. Standalone: it never touches the production Guardian (calls it only as an
optional client via GUARDIAN_URL).
"""
from __future__ import annotations

import hashlib
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import store, guard, llm, mask
from .levels import BY_ID, LEVELS, MAX_LEVEL

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
RATE_PER_MIN = int(os.getenv("RATE_PER_MIN", "15"))
WEB = os.path.join(os.path.dirname(__file__), "..", "web")

app = FastAPI(title="Kalkan Arena", docs_url=None, redoc_url=None)
store.init()

# ---- tiny in-memory per-IP rate limit (swap for Redis in prod) ----
_hits: dict = {}


def _ip_hash(req: Request) -> str:
    ip = (req.headers.get("cf-connecting-ip") or req.headers.get("x-forwarded-for", "").split(",")[0]
          or (req.client.host if req.client else "0.0.0.0")).strip()
    return hashlib.sha256(("kalkan" + ip).encode()).hexdigest()[:16]


def _rate_ok(key: str) -> bool:
    now = time.time()
    q = [t for t in _hits.get(key, []) if now - t < 60]
    if len(q) >= RATE_PER_MIN:
        _hits[key] = q
        return False
    q.append(now); _hits[key] = q
    return True


class StartIn(BaseModel):
    alias: str = ""


class AttemptIn(BaseModel):
    sid: str
    level: int
    prompt: str


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(WEB, "index.html"), encoding="utf-8") as f:
        return f.read()


@app.get("/api/levels")
def api_levels():
    return [{"id": l.id, "name": l.name, "blurb": l.blurb} for l in LEVELS]


@app.post("/api/start")
def api_start(body: StartIn):
    s = store.new_session(body.alias)
    return {"sid": s["sid"]}


@app.post("/api/consent")
def api_consent(body: dict):
    sid = body.get("sid", "")
    if store.get_session(sid):
        store.consent(sid)
        return {"ok": True}
    return JSONResponse({"ok": False, "error": "geçersiz oturum"}, status_code=400)


@app.post("/api/attempt")
def api_attempt(body: AttemptIn, request: Request):
    iph = _ip_hash(request)
    if not _rate_ok(iph):
        return JSONResponse({"error": "Çok hızlısın — biraz bekle (dakikada %d deneme)." % RATE_PER_MIN},
                            status_code=429)
    sess = store.get_session(body.sid)
    if not sess:
        return JSONResponse({"error": "Oturum yok, sayfayı yenile."}, status_code=400)
    if not sess["consented"]:
        return JSONResponse({"error": "Önce KVKK onayını ver."}, status_code=403)
    level = BY_ID.get(body.level)
    if not level:
        return JSONResponse({"error": "Geçersiz seviye."}, status_code=400)

    prompt = (body.prompt or "")[:8000]
    secret = store.secret_for(body.sid, body.level)

    # 1) input guard (level threshold + rules + anti-evasion)
    blocked, gscore, reason = guard.input_blocked(prompt, level)
    engine = "guardian" if guard.GUARDIAN_URL else "heuristic"

    leaked = False
    reply = ""
    if blocked:
        reply = f"🛡️ Kalkan seni durdurdu. ({reason})"
    else:
        # 2) run the target model with the secret in the system prompt
        system = level.system_template.format(secret=secret)
        reply = llm.complete(system, prompt, secret)
        # 3) canary oracle — did the model actually leak the secret? (this is the win + the gold data)
        leaked = guard.output_leaks_secret(reply, secret)

    # 4) log EVERYTHING (masked), especially passed prompts — this is the data engine
    store.log_attempt(body.sid, body.level, mask.mask_safe(prompt), engine, gscore,
                      level.threshold, blocked, reason, leaked, iph)

    won = leaked  # you won the level if you made the model leak the secret (regardless of output censor)
    if won:
        store.mark_solved(body.sid, body.level)

    out = {"result": "win" if won else ("blocked" if blocked else "lose"),
           "reply": reply, "level": body.level}
    if won:
        out["message"] = f"🏆 Seviye {body.level} çözüldü! Parolayı sızdırdın."
        if body.level < MAX_LEVEL:
            out["next"] = body.level + 1
    return out


@app.get("/api/leaderboard")
def api_leaderboard():
    return {"board": store.leaderboard(), "stats": store.stats()}


@app.get("/admin/export")
def admin_export(token: str = ""):
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return PlainTextResponse(store.export_jsonl(), media_type="application/x-ndjson")


@app.get("/healthz")
def health():
    return {"ok": True, "engine": "guardian" if guard.GUARDIAN_URL else "heuristic",
            "target": "live" if (llm.LLM_BASE_URL and llm.LLM_API_KEY) else "mock"}


if os.path.isdir(os.path.join(WEB, "static")):
    app.mount("/static", StaticFiles(directory=os.path.join(WEB, "static")), name="static")
