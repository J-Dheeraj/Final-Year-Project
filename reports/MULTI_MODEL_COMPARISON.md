# Multi-model comparison — 2026-09-23

Follow-on to `reports/LIVE_LLM_CATALOG_RUN.md`: instead of one model
(qwen2.5-coder:7b), run the **same frozen catalog protocol across 8 local
Ollama models** spanning size and family, now with sampling pinned
(`temperature=0`, fixed seed) so results are deterministic and comparable
run-to-run — the exact gap identified and fixed after round 1/round 2 of
the single-model run.

Claude and OpenAI were explicitly **dropped from this round** (user
decision): no `claude` CLI or API key is available in this environment,
and neither should be silently worked around. Ollama only serves local
open-weight models — there is no "Claude via Ollama" path.

## Setup

- **Protocol**: identical to the single-model catalog run — one shot per
  CVE, `--no-cache`, sandboxed via `--cache-dir` (canonical
  `reports/<CVE-ID>/` folders verified untouched before and after — see
  the note on this in `LIVE_LLM_CATALOG_RUN.md`).
- **Prompt**: the version frozen at the end of step 3/round 2 (includes
  the URL-scheme fix). Not touched during this run.
- **Sampling**: `temperature=0`, `seed=42` for every model (Ollama
  `options`), added specifically to make this comparison valid.
- **8 models, 6 CVEs each = 48 runs.** Raw reports:
  `reports/multi_model_comparison_2026-09-23/<model>/<CVE-ID>.json`.

## A real interruption, handled honestly

This run was interrupted by a laptop sleep partway through `gemma2:9b`.
External network (DNS) dropped, breaking Stage 1's NVD advisory fetch —
**Ollama itself stayed up throughout (it's local)**, but a broken
advisory fetch degrades the vulnerability class to `UNKNOWN`, which
makes any resulting run scientifically invalid for that CVE regardless of
what the model did. Affected: 4/6 of `gemma2:9b`'s CVEs, and the pulls
for `codellama:13b`/`deepseek-coder-v2:16b` (DNS-dependent, never
downloaded at all that attempt). All affected work was **discarded, not
kept "close enough"** — network was confirmed restored, and the exact
broken pieces were re-run (`gemma2:9b`'s 4 CVEs) or fully redone from a
fresh pull (both un-pulled models). The 5 models unaffected by the outage
(both cache-hit and never touched during the outage window) were
verified clean (no `ConnectionError` in any log) and kept as-is.

## Results

| Model | Confirmed | Patch validated | Live generation | Total time (s) | Tokens in | Tokens out |
|---|---|---|---|---|---|---|
| qwen2.5-coder:1.5b | 3/6 | 0/6 | 0/6 (see caveat) | 37.3 | 9519 | 4669 |
| qwen2.5-coder:3b | 1/6 | 0/6 | 6/6 | 38.4 | 8167 | 3057 |
| qwen2.5-coder:7b | 5/6 | 0/6 | 6/6 | 114.9 | 10169 | 4578 |
| llama3.1:8b | 2/6 | 0/6 | 6/6 | 94.3 | 8341 | 3278 |
| mistral:7b | 0/6 | 0/6 | 6/6 | 106.8 | 8632 | 4037 |
| gemma2:9b | 0/6 | 0/6 | 6/6 | 763.7 | 7892 | 3282 |
| codellama:13b | 2/6 | 0/6 | 5/6 | 1544.1 | 8740 | 4241 |
| deepseek-coder-v2:16b | 4/6 | 0/6 | 6/6 | 176.6 | 10524 | 5478 |
| **Total (all 48 runs)** | **17/48** | **0/48** | | **2876.1** | **71984** | **32620** |

**Total cost: $0.0000** across all 48 runs — every model is local Ollama
inference; no API billing anywhere in this comparison.

## Findings, reported honestly rather than as a leaderboard

- **qwen2.5-coder:7b is the strongest confirmer** (5/6) among models
  actually generating live (`llm_live_success`). This is the same model
  used for the earlier single-model round 1/round 2 work, so it also has
  the most prior prompt-tuning exposure (step 3 was tuned against a CVE
  run on this model) — a real confound, not a clean apples-to-apples
  "best model" claim.
- **qwen2.5-coder:1.5b's "3/6 confirmed" is misleading on its own.**
  Every one of its 6 generations is `generation_outcome=llm_live_failed`
  — the 1.5B model never cleanly produced both required files in one
  shot. The 3 confirmations come from the pipeline's **template
  fallback**, not from the small model's own live output. Read as "1.5B
  model capability," the honest number is closer to 0/6; read as
  "pipeline robustness when the small model fails," 3/6 is a real,
  separate finding about the fallback path working correctly.
- **`patch_validated` is 0/48. Not one model, across every run,
  produced a patch that closed the vulnerability it found.** Several
  models attempted patches (visible per-CVE in the raw JSON) but every
  one failed validation — consistent with the same root cause found in
  the single-model work: generated patches tend to add generic-looking
  validation that doesn't address the actual injected condition. This is
  the strongest, most consistent finding in the whole comparison and
  should be stated plainly in any report of this work: **Stage 3.8 patch
  generation does not reliably work with any of these 8 local models on
  a single deterministic shot.**
- **Runtime does not track parameter count cleanly.** codellama:13b
  (1544s total) is dramatically slower than deepseek-coder-v2:16b (176s
  total) despite deepseek being the larger model — likely architecture
  and quantization differences, not raw size. Not investigated further;
  reported as observed, not explained by a plausible-sounding guess.
- **gemma2:9b has one unexplained extreme outlier**: 608.7s for
  CVE-2026-27602 versus 24.8-40.5s for its other 5 runs, with no
  correspondingly large output-token count to explain it. Flagged, not
  papered over with a guessed cause.
- **Confirmation rate does not track model size.** 7B (qwen) beat both
  9B (gemma2, 0/6) and 13B (codellama, 2/6). Bigger did not mean better
  at this specific task, in this comparison.

## What this does and does not establish

- **Does**: give a real, reproducible (pinned sampling), same-protocol
  comparison of 8 local models on the same 6 real CVEs, with every
  result's real time/token/cost recorded - none estimated.
- **Does not**: establish a general "best model" ranking. One
  deterministic shot per CVE per model is a single data point, not a
  statistically powered comparison; qwen2.5-coder:7b's prior tuning
  exposure is a real confound favoring it specifically.
- **Does not** include Claude or OpenAI - dropped this round per an
  explicit decision (no CLI/API key available; not worked around).
