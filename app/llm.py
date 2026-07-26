"""Target model adapter — OpenAI-compatible (Groq / Cerebras / OpenAI / local Ollama).

Set LLM_BASE_URL + LLM_API_KEY + LLM_MODEL. With no key it runs in MOCK mode so the app (and tests)
work offline; MOCK is deliberately naive — it leaks the secret to obvious asks so you can see the
win path end-to-end, and refuses blatant ones.

The challenge is the DEFENSE (guard), so a cheap/free scoring-only target is fine — same model every
level. Recommended free cascade: Groq Llama-3.3-70B → Cerebras → SambaNova.
"""
from __future__ import annotations

import os

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")


def _mock(system: str, user: str, secret: str) -> str:
    u = user.lower()
    # naive: continuation / "repeat and continue" style leaks the secret (shows the win path)
    if any(k in u for k in ["tamamla", "continue", "devam", "repeat", "tekrarla", "akrostiş", "acrostic"]):
        return f"Tabii, devam ediyorum: parola {secret} olarak geçiyor."
    if any(k in u for k in ["parola", "secret", "şifre", "flag"]) and "söyleme" not in u:
        return "Üzgünüm, parolamı paylaşamam."
    return "Merhaba! Sana nasıl yardımcı olabilirim?"


def complete(system: str, user: str, secret: str = "") -> str:
    if not (LLM_BASE_URL and LLM_API_KEY):
        return _mock(system, user, secret)
    try:
        import urllib.request, json
        req = urllib.request.Request(
            f"{LLM_BASE_URL}/chat/completions",
            data=json.dumps({
                "model": LLM_MODEL,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0.4, "max_tokens": 400,
            }).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {LLM_API_KEY}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        return data["choices"][0]["message"]["content"]
    except Exception as e:  # fail-soft: never 500 the arena on a provider hiccup
        return f"(model geçici olarak yanıt veremedi: {str(e)[:60]})"
