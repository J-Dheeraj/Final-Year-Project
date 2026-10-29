# llm-council skill

Use this skill when working on, setting up, or modifying [karpathy/llm-council](https://github.com/karpathy/llm-council) — a local web app that routes each query through several LLMs, has them anonymously rank each other, and produces a synthesised final answer via a Chairman model.

---

## Architecture — 3 stages

1. **First opinions** — every council model answers independently; results shown in a tab view
2. **Anonymized review** — each model sees the others' answers with identities hidden, ranks them for accuracy and insight
3. **Chairman synthesis** — one designated model writes the final response from all answers and rankings

Anonymization in stage 2 eliminates inter-model favoritism. Ranking parsing falls back gracefully when a model ignores the required format.

---

## Key files

| Path | Role |
|------|------|
| `backend/config.py` | `COUNCIL_MODELS` list + `CHAIRMAN_MODEL` — the only place to swap models |
| `backend/main.py` | FastAPI server (port **8001**) |
| `backend/council.py` | Core 3-stage logic: collection → anonymized ranking → synthesis |
| `frontend/src/` | React + Vite UI; stage 2 de-anonymizes labels for display |
| `data/conversations/` | JSON conversation store (metadata not persisted) |
| `.env` | `OPENROUTER_API_KEY=...` |

---

## Setup

```bash
# 1. Python deps
uv sync

# 2. Frontend deps
cd frontend && npm install && cd ..

# 3. API key
echo "OPENROUTER_API_KEY=sk-or-..." > .env

# 4. Run
./start.sh
# or manually:
uv run python -m backend.main   # terminal 1 — must run as module from project root
cd frontend && npm run dev       # terminal 2
```

Open `http://localhost:5173`.

---

## Configuring models

Edit `backend/config.py`:

```python
COUNCIL_MODELS = [
    "anthropic/claude-sonnet-4-5",
    "openai/gpt-4o",
    "google/gemini-2.0-flash-001",
    "x-ai/grok-3-mini-beta",
]

CHAIRMAN_MODEL = "anthropic/claude-opus-4-5"
```

Model IDs are OpenRouter slugs. Check [openrouter.ai/models](https://openrouter.ai/models) for the current list.

---

## Gotchas

- **Run backend as a module** from the project root: `uv run python -m backend.main`. Running `python backend/main.py` directly breaks relative imports.
- **CORS**: if the frontend port changes from 5173, update the allowed origins list in `backend/main.py`.
- **Partial results**: if one model fails or times out, the pipeline continues with the others — don't treat a missing tab as a crash.
- **Ranking format**: models that ignore the strict format are handled by a fallback parser; check the stage 2 "parsed rankings" display to verify.
- **API connectivity**: run the bundled test script to confirm OpenRouter is reachable before debugging the UI.

---

## Development workflow

- Backend changes: restart `uv run python -m backend.main`; hot-reload is not enabled.
- Frontend changes: Vite HMR handles them automatically.
- New stage logic goes in `backend/council.py`; new UI panels go in `frontend/src/`.
- To add a new council stage, add it to the pipeline in `council.py` and wire up a new tab component in the frontend.
