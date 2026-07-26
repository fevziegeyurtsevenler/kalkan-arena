# Deploy & server-load notes

## The one rule: keep the ML model OFF the shared box
The MVP guard is **regex/heuristic-only** (~1–2 ms/scan) — it is safe to run next to the academy.
The real Guardian's 1.1 GB fp32 mDeBERTa is **not** in this MVP on purpose: at WORKERS=4 it needs
~5 GB RAM (one model copy per worker) and 200–500 ms CPU-bound inference per request, which will
OOM/CPU-starve a shared VPS under public traffic. Guardian's own code warns: public model inference =
"free inference, CPU abuse and model extraction."

If you ever want the ML tier:
- Run it as ONE shared worker (`ML_SCANNER_MODE=service`), int8-quantized (~300 MB), on a SEPARATE box.
- Point this arena at it via `GUARDIAN_URL` (the adapter already fails soft).

## Safe topology (MVP)
1. `docker compose up -d` — the arena binds `127.0.0.1:8010` only.
2. Nginx reverse-proxy `arena.altaysec.com.tr` → `127.0.0.1:8010`.
3. **Cloudflare (free)** in front + **Turnstile** on the page to kill scripted extraction.
4. Per-IP rate limit is built in (`RATE_PER_MIN`, default 15); for scale move it to Redis.
5. Do NOT run this in the academy's Node process — it's a separate container.

## Target model
Use a free OpenAI-compatible endpoint (Groq Llama-3.3-70B → Cerebras → SambaNova). Scoring-only, same
model every level, so cost is ~0. Set `LLM_BASE_URL` + `LLM_API_KEY` + `LLM_MODEL` in `.env`.

## The data flywheel (monthly)
1. `GET /admin/export?token=$ADMIN_TOKEN > corpus-$(date +%F).jsonl`
2. Filter `confirmed_bypass=true` (passed the guard AND leaked) — these are the gold hard-negatives.
3. Human-triage a few dozen; add the novel ones to `rules/injection_patterns.yaml` + the held-out
   benchmark now; fine-tune the mDeBERTa detector later. Feed `guard-blindspots-tr` too.
> If you won't commit to this monthly triage, the data is worthless — don't run the arena.
