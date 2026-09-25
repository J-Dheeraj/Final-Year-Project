# Claude Code comparison protocol (pipeline-vs-agent Step 2)

Frozen before any run, per the same rigor pattern `docs/BENCHMARK_PROTOCOL.md`
already follows for this project. Codex is explicitly out of scope for this
protocol - it will get its own comparison after this one, per the user's
2026-09-25 direction. Do not add Codex results here later; give them a
separate document.

## 1. What "Claude Code as an agent" means here

Per the user's explicit choice: Claude Code runs the **same pipeline
code**, swapped in as the model backend, not as an independent agent
briefed only with the advisory. Concretely: `cve_pipeline.py`'s
`_call_live_model()` already prefers the `claude` CLI over Ollama whenever
`_claude_available()` is true (checked via `claude --version`); since the
`claude` CLI is genuinely installed and authenticated on this machine
(confirmed: `claude --version` -> `2.1.280 (Claude Code)`), running the
pipeline with no extra configuration already selects this backend
deterministically - no code change needed for this comparison, only a
frozen run protocol.

This is a **direct model swap**, not a new agent design: same prompts,
same stages, same validator (including the Step 1 corrected verdict
fields), same catalogue - only the backend answering `_call_live_model()`
changes from `ollama` to `claude`.

## 2. Real cost, stated before running

`_call_claude` shells out to `claude -p <prompt> --output-format text`
using this machine's own Claude Code CLI authentication. Unlike the
Ollama rounds (`$0.0000`, local inference), **every call in this run
consumes real usage against the user's actual Claude account** - this
pipeline does not, and cannot, estimate a token cost for CLI calls
(`_call_claude_metered` leaves `cost_usd=None` for exactly this reason -
`claude -p --output-format text` does not expose usage data). Get explicit
confirmation before running the full catalogue, not just before this
protocol is written.

## 3. Case selection (frozen)

The same six CVEs already used throughout every other round in this
project, per the user's explicit choice to keep this comparable to the
existing catalogue:

| # | CVE | Package | Class |
|---|---|---|---|
| 1 | CVE-2026-42208 | litellm | SQL Injection |
| 2 | CVE-2026-27602 | modoboa | OS Command Injection |
| 3 | CVE-2026-23949 | jaraco.context | Path Traversal |
| 4 | CVE-2026-78683 | nltk | Insecure Deserialization |
| 5 | CVE-2026-54729 | dssrf | SSRF |
| 6 | CVE-2026-46492 | md-fileserver | XSS |

## 4. Attempt limits and settings (frozen)

- **One shot per CVE**, `--no-cache`, sandboxed via a dedicated
  `--cache-dir` so canonical `reports/<CVE-ID>/` folders are never
  touched by this run - identical protocol discipline to every prior
  round (`reports/LIVE_LLM_CATALOG_RUN.md`).
- Self-improvement (Stage 3.7): bounded at `max_iterations=3`, same as
  every other round - not raised or lowered for this comparison.
- Patch generation (Stage 3.8): attempted once per confirmed exploit,
  same as every other round.
- Sampling: `claude -p` has no exposed temperature/seed controls (unlike
  the Ollama path's `temperature=0, seed=42`) - this is a real,
  acknowledged asymmetry between the two backends' reproducibility, not
  glossed over. Any single-CVE result from this run can vary between
  invocations for reasons this protocol cannot control, the same
  single-shot caveat already standing for every Ollama round.

## 5. Scoring rules (frozen, uses the Step 1 corrected validator)

Every metric already defined in `docs/BENCHMARK_PROTOCOL.md` applies
unchanged (DYNAMICALLY CONFIRMED, generation provenance tags, etc.), plus
the three fields added in this project's 2026-09-25 patch-validator fix:

- **`patch_exploit_blocked`**: did the exploit fail without an unhandled
  exception in the target's own log.
- **`patch_function_preserved`**: does a benign request to the same route
  still succeed.
- **`patch_verdict`**: `confirmed_fix` / `regression_broke_route` /
  `inconclusive_crash` / `not_blocked`.

**This run reports `patch_verdict`, not the raw `patch_validated` flag
alone, as its headline patch metric.** Any comparison table built from
this run's results must show `patch_verdict`'s full breakdown, not just a
validated/not-validated count - collapsing back to the old flag would
silently undo the point of Step 1.

## 6. Provenance and reporting rules (frozen)

- Raw reports go to `reports/claude_code_catalog_run_<date>/<CVE-ID>.json`
  - a new directory, never overwriting or mixing with any Ollama round's
  own report directory.
- Report every entry, including any that don't confirm, with the real
  reason - same "no highlight reel" rule as every prior round.
- `generation_backend`/`generation_model` fields must read `"claude"` /
  `"claude-cli"` for every entry in this run; if any entry shows `ollama`
  instead, that means `_claude_available()` returned false for that call
  (e.g. a transient CLI hiccup) and the entry must be flagged, not
  silently reported as a Claude Code result.
- This run is compared against the **existing Ollama rounds** (5 rounds,
  `reports/llm_catalog_run_*`), not against a new Ollama re-run - the
  Ollama side of this comparison is already frozen historical data, not
  re-collected for parity.

## 7. Exit criterion

Same shape as every prior round's own exit criterion: report every one of
the six CVEs honestly, including failures, with `patch_verdict`'s full
breakdown. Not "all six confirm" - a complete, honestly-reported single
run under this frozen protocol.
