# 🛡️ Kalkan Arena

**A Turkish "red-team our guard" prompt-injection challenge — that turns every attempt into training
data.** Players try to trick a target LLM into leaking a per-session secret; the AltaySec **Kalkan**
guard sits in front and gets harder each level. Every (consented, PII-masked) attempt is logged —
especially the ones that get through — so real, human-invented Turkish attacks flow back into
improving the guard.

Standalone by design: it **never touches the production Guardian**. It ships its own heuristic guard,
and can *optionally* call the real Guardian API as a read-only client (`GUARDIAN_URL`).

> Educational / defensive security research, in the spirit of HackAPrompt & Gandalf. No weaponization
> content. Authorized, consented data collection only.

## Why it exists
- **Data engine (the point):** English injection corpora dominate; human-invented **Turkish**
  adversarial prompts are scarce and unbuyable. A challenge produces exactly those — the confirmed
  bypasses (passed the guard **and** leaked the secret) are gold hard-negatives for the detector.
- **Live demo + funnel** for AltaySec's Turkish LLM security work, framed honestly as *"kır bizi"*
  (break us) — we publish the **attacker leaderboard**, never a guard win-rate.

## How it works
```
player prompt → Kalkan guard (level threshold + rules + anti-evasion) → blocked?  → log + "durduruldu"
                                        └ passed → target LLM (secret in system prompt)
                                                     → canary oracle: did it leak the secret? → WIN
                                                     → log EVERYTHING (masked), esp. passed prompts
```
- **Levels** (`app/levels.py`) = a guard config. Difficulty rises by lowering `threshold` and adding
  banned keywords. MVP is regex/heuristic-only (safe to co-host); the ML tier is intentionally left
  out (a 1.1 GB model under public load will melt a shared box — see DEPLOY).
- **Guard adapter** (`app/guard.py`): built-in heuristic (normalize + decode-and-rescan + Noisy-OR)
  or the real Guardian via `GUARDIAN_URL` (fail-soft).
- **Secrets** are random **per session** — nothing secret is in this repo, so it's safe to open-source.

## Data & KVKK (non-negotiable)
- Consent gate before play; players are told attempts become training/research data.
- Every stored prompt is **PII-masked** (`app/mask.py`, checksum-validated TCKN/IBAN/VKN/phone/email/
  card), fail-closed.
- We log **passed** prompts too (the valuable ones) + a canary success label. Export the corpus with
  `GET /admin/export?token=...`; the `confirmed_bypass` flag marks passed-guard + leaked = gold.
- We return only **win/lose** to the player (never the raw score) to limit model-extraction.

## Run it
```bash
pip install -r requirements.txt
cp .env.example .env         # no LLM key = MOCK mode (works offline)
uvicorn app.main:app --reload --port 8000
# open http://localhost:8000
```
Docker: `docker compose up -d` (binds loopback; put Cloudflare/Nginx in front). Deploy notes +
server-load guidance: [`deploy/DEPLOY.md`](deploy/DEPLOY.md).

## Endpoints
`GET /` UI · `GET /api/levels` · `POST /api/start` · `POST /api/consent` · `POST /api/attempt` ·
`GET /api/leaderboard` · `GET /admin/export?token=` · `GET /healthz`

## Tests
`pytest -q` — guard blocks/passes, anti-evasion casefold, canary oracle, KVKK masking, data flow.

## Honesty
The built-in guard is a heuristic (not the full mDeBERTa product). Brand this as **"kır bizi / red-team
our guard,"** publish the attacker leaderboard, and never quote a threshold-tuned block-rate as a
Guardian datasheet number. Related: [guardrail-arena](https://github.com/fevziegeyurtsevenler/guardrail-arena)
· [AltaySec](https://altaysec.com.tr).

Apache-2.0 · by **[AltaySec](https://altaysec.com.tr)**.

---

## İlgili AltaySec Kaynakları

- 📖 [Bekçi: Türkçe LLM Prompt Injection Lab Mimarisi](https://altaysec.com.tr/arastirmalar/bekci-llm-prompt-injection-lab) — konunun derinlemesine Türkçe analizi
- 🌐 [AltaySec Araştırmalar](https://altaysec.com.tr/arastirmalar/) — Türkçe yapay zekâ güvenliği yazıları

## Atıf

```bibtex
@software{altaysec_kalkan_arena_2026,
  author = {{AltaySec}},
  title  = {kalkan-arena},
  year   = {2026},
  url    = {https://github.com/fevziegeyurtsevenler/kalkan-arena}
}
```
