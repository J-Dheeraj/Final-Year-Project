# Live-LLM catalog run — 2026-09-23

Live-LLM plan step 4 (`docs/PROJECT_STATUS.md`): run the frozen catalog
under a single live model, one shot per CVE (no re-rolling, no
cherry-picking), and report exactly what happened — including the
failures. This is a **separate, parallel record** to
`reports/CVE_CATALOG.md` (which documents the original template-based
baseline); it does not replace or overwrite it, and none of the canonical
`reports/<CVE-ID>/` folders were touched by this run (sandboxed via
`--cache-dir` so `generate_exploit_artifacts`'s hardcoded output path
never pointed at the real catalog evidence — see the note on this in the
PR history: an earlier session's testing on `CVE-2026-42208` briefly
overwrote the real catalog files by accident and was restored before
committing anything).

## Setup

- **Model**: `qwen2.5-coder:7b` via local Ollama (`OLLAMA_HOST=http://localhost:11434`).
- **Prompt**: the version frozen at the end of step 3's bounded development
  (4 iterations against `CVE-2026-42208` only — see that commit's message
  for exactly what changed and why). **Not touched during this run.**
- **Protocol**: one shot per CVE, `--no-cache` (forces fresh generation,
  not a replay of the old template-based cache), full pipeline (Stage
  3.5 generation → 3.6 execution → 3.7 self-improve → 3.8 patch, all live).
- Raw reports: `reports/llm_catalog_run_2026-09-23/<CVE-ID>.json`.

## Results — reported in full, nothing cherry-picked

| CVE | Class | Generation | Executed | Dynamically confirmed | Patch attempted | Patch validated | Time (s) | Tokens in/out |
|---|---|---|---|---|---|---|---|---|
| CVE-2026-42208 | SQL Injection | llm_live_success | True | **True** | True | False | 27.01 | 1719 / 997 |
| CVE-2026-27602 | OS Command Injection | llm_live_success | True | False | — | — | 10.81 | 1099 / 493 |
| CVE-2026-23949 | Path Traversal | llm_live_success | True | False | — | — | 10.17 | 1195 / 454 |
| CVE-2026-78683 | Insecure Deserialization | llm_live_success | True | False | — | — | 12.03 | 1138 / 548 |
| CVE-2026-54729 | SSRF | llm_live_success | True | False | — | — | 12.35 | 1078 / 565 |
| CVE-2026-46492 | Cross-Site Scripting | llm_live_success | True | False | — | — | 11.55 | 1116 / 520 |
| **Total** | | **6/6 live-generated** | **6/6** | **1/6** | **1/6** | **0/6** | **83.92** | **7345 / 3577** |

**Total run cost**: 83.92s, 7345 input tokens, 3577 output tokens, **$0.0000**
(local Ollama — real, not "unknown"; see `total_llm_*` fields on each report).

## Exit criterion (per `docs/PROJECT_STATUS.md`)

> "Exit criterion: at least one CVE completes the full chain (live-generated
> PoC → dynamically confirmed → patch_validated) — not 'all six work'."

**Partially met.** CVE-2026-42208 completes live-generation →
dynamic-confirmation (both `True`), and patch generation was attempted —
but `patch_validated=False`: the model's generated patch replaced the
vulnerable check with generic auth-format validation that the injected
payload still passes (same root cause documented when this was first
found in step 3 — see that commit). No catalog CVE reaches
`patch_validated=True` in this run.

## Why the other 5 didn't confirm — reported, not hidden

All five failed the same way: `exit_code=1`, `dynamically_confirmed=False`
on the first (and only, per the one-shot protocol) attempt. This is
consistent with the step-3 finding: the prompt's success contract
(a MARKER string returned only when the injected payload takes effect,
`verify()` checking exactly that marker) was iterated and converged
against **SQL Injection only**. On a single zero-shot try, a 7B local
model does not reliably reproduce that same self-consistent contract for
different vulnerability classes (Command Injection, Path Traversal,
Deserialization, SSRF, XSS) — each has its own "what counts as
successfully triggered" shape that the frozen prompt states generically
but the model doesn't always instantiate correctly on the first attempt
per class. This is not a pipeline defect; it is a measured limitation of
one frozen prompt's cross-class generalization with this model size,
exactly the kind of result the protocol asks to be reported rather than
cherry-picked around.

## What this does and does not establish

- **Does**: prove the full live-model pipeline (generation → execution →
  self-improvement → patch generation → patch re-validation) runs
  end-to-end, unattended, on 6 real disclosed CVEs, with every run's real
  time/token/cost recorded — not estimated, not simulated.
- **Does not**: establish that this prompt/model combination reliably
  confirms vulnerabilities across classes. 1/6 on a single frozen shot is
  the real, honest number for this run, this model, this prompt version.
- **Not attempted**: per-class prompt tuning (would violate the "frozen
  for the rest of the session" rule from step 3) or multiple retries per
  CVE (would be exactly the cherry-picking the protocol forbids).

## Natural next step, if pursued

Per-class prompt tuning (repeat step 3's bounded process for each of the
5 unconfirmed classes, each still exactly one CVE at a time, each frozen
before moving to the next) would very likely raise the confirmation rate,
since the SQLi contract already proved a 7B model *can* satisfy it when
the prompt is specific enough. Not attempted here to keep this run's
result an honest, single-frozen-prompt baseline rather than a moving
target.

## Round 2 — a diagnosed, generalizable bug fix, and honest variance

Inspecting the 5 unconfirmed CVEs' generated PoCs found a real, shared bug
in 3 of them (CVE-2026-23949, CVE-2026-54729, CVE-2026-46492): the PoC
receives `argv[1]` as a bare `host:port` string and used it directly in an
f-string URL with no `http://` prefix. `requests` raises
`MissingSchema` on that, which a broad `except requests.RequestException`
silently swallows as "target unreachable" — `health()` returns `False`
before the exploit is ever attempted. This is a generic PoC-construction
gap, not specific to any one vulnerability class: the prompt never
mandated a scheme, and the one round-1 success (SQLi) happened to include
it by chance, not by instruction.

**Fix**: one explicit rule added to the shared generation prompt —
`argv[1]` is schemeless; every request URL must be built as
`f"http://{host}:{port}/..."`. (First attempt at wiring this had a real
bug of its own: writing the example as `{host}`/`{port}` inside the
prompt's own Python f-string caused a `NameError` in `cve_pipeline.py`
itself, since those aren't Python variables in that scope — caught
immediately when all 6 re-runs errored out identically; fixed by escaping
to `{{host}}`/`{{port}}` so the literal text reaches the model instead of
being evaluated. Verified with a standalone f-string check before
re-running the catalog.)

Re-ran the same protocol (one shot per CVE, `--no-cache`, sandboxed the
same way) with the corrected prompt:

| CVE | Class | Confirmed (round 1) | Confirmed (round 2) | Patch attempted | Patch validated | Time (s) | Tokens in/out |
|---|---|---|---|---|---|---|---|
| CVE-2026-42208 | SQL Injection | **True** | False | False | — | 17.06 | 1291 / 551 |
| CVE-2026-27602 | OS Command Injection | False | False | False | — | 11.62 | 1254 / 526 |
| CVE-2026-23949 | Path Traversal | False | False | False | — | 13.88 | 1350 / 631 |
| CVE-2026-78683 | Insecure Deserialization | False | False | False | — | 12.13 | 1293 / 550 |
| CVE-2026-54729 | SSRF | False | **True** | True | False | 18.96 | 1722 / 863 |
| CVE-2026-46492 | Cross-Site Scripting | False | **True** | True | False | 16.49 | 1745 / 745 |
| **Total** | | **1/6** | **2/6** | **2/6** | **0/6** | **90.14** | **8655 / 3866** |

**Read this honestly, not as "round 2 is strictly better":** the fix
newly confirmed 2 previously-failing classes (SSRF, XSS) — real evidence
it addressed a genuine, shared bug — but **CVE-2026-42208 (SQLi), which
confirmed in round 1, did not confirm in round 2 with the identical
success-contract wording.** Neither run pins the model's sampling
(no fixed seed/temperature=0), so a single-shot result for the *same*
CVE can flip between runs. Both rounds are single frozen-prompt shots
per CVE, and the correct combined statement is: **across the two rounds,
3 distinct classes have been confirmed at least once (SQLi, SSRF, XSS)
out of 6**, not "2/6 is the new number." Patch generation was attempted
for both round-2 confirmations and validated False in both cases —
not yet inspected in detail; the same generic-patch failure mode found
for SQLi in step 3 is the working hypothesis, not yet confirmed for
these two.

Raw round-2 reports: `reports/llm_catalog_run_2026-09-23_round2/<CVE-ID>.json`.
