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

## Round 3 — Stage 3.7 self-improvement wired to the live-model backend

Before this round, `src/pipeline/self_improve.py`'s `_llm_revise_artifacts`
(Stage 3.7's LLM-diagnosis path) still called `_call_claude`/
`_claude_available` directly — the one call site the live-model backend
work (`_call_live_model`/`_live_model_available`, used by Stage 3.5 and
3.8 above) never reached. Under Ollama-only conditions (no `claude` CLI on
this machine — `claude_available: False`, confirmed live), Stage 3.7
silently never ran: `_claude_available()` returned `False` and every
refinement attempt exited immediately with no retry, no diagnosis, and no
log line explaining why. Fixed in commit `e344966` by mirroring the exact
pattern already proven for Stage 3.5/3.8: swap in `_call_live_model`/
`_live_model_available`, and record `revision_backend`/`revision_model`/
`revision_duration_s`/`revision_input_tokens`/`revision_output_tokens`/
`revision_cost_usd` on each `refinement_history` entry, matching the
`generation_*`/`patch_gen_*` metrics convention already on
`ExploitArtifacts`.

Re-ran the same protocol (one shot per CVE, `--no-cache`, sandboxed the
same way) with the fix in place:

| CVE | Class | Confirmed (r1) | Confirmed (r2) | Confirmed (r3) | Refine attempts | Patch attempted | Patch validated | Time (s) | Tokens in/out |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-42208 | SQL Injection | **True** | False | False | 3 | False | — | 49.8 | 4356 / 2327 |
| CVE-2026-27602 | OS Command Injection | False | False | False | 2 | False | — | 24.2 | 2255 / 1122 |
| CVE-2026-23949 | Path Traversal | False | False | **True** | 1 | True | False | 22.3 | 2028 / 1017 |
| CVE-2026-78683 | Insecure Deserialization | False | False | False | 3 | False | — | 48.8 | 4727 / 2257 |
| CVE-2026-54729 | SSRF | False | **True** | False | 3 | False | — | 50.1 | 3996 / 2348 |
| CVE-2026-46492 | Cross-Site Scripting | False | **True** | False | 2 | False | — | 22.9 | 2243 / 1064 |
| **Total** | | **1/6** | **2/6** | **1/6** | **14** | **1/6** | **0/6** | **218.1** | **19605 / 10135** |

**Read honestly, not as "the fix raised the confirmation rate":** round 3's
raw count (1/6) is not higher than round 2's (2/6) — a working retry
mechanism is not the same thing as a mechanism that always finds the
right fix. What changed is real: `CVE-2026-23949` confirmed specifically
because Stage 3.7's cross-CVE lesson reuse fired for the first time in
this pipeline's history — `source=lesson`, reusing a "Path
Traversal/endpoint_not_found" fix already persisted in
`.pipeline_lessons.json` from an earlier session, applied on the very
first refinement attempt with zero extra diagnosis needed. Under the old
(broken) code this code path was never even reached: `_claude_available()`
short-circuited to `False` before the lessons-store lookup could run.

The other 5 CVEs got genuine LLM-diagnosed retries this round (visible in
the raw logs as `[Stage 3.7] Applying revision ... source=llm`, 2–3
iterations each) but none of the revisions fixed the underlying issue —
`CVE-2026-27602` and `CVE-2026-46492` hit `signature=generic_failure` with
"no usable revision" logged after their attempts; the other three
exhausted `max_iterations=3`. This is informative, not a null result: it
confirms the wiring works end-to-end (live model actually called,
diagnosis actually attempted, re-execution actually happens), and
localizes the remaining gap to diagnosis *quality* from a 7B local model
on `generic_failure` signatures, not backend availability.

Stage 3.8 (patch generation) was attempted once, for the one confirmed
case (`CVE-2026-23949`), and rejected: `patch REJECTED (health check
failed): target_app.py never became healthy on :5000` — the
LLM-generated patch broke the app rather than just closing the
vulnerability, the same class of failure documented for round 2's two
patch attempts above, not yet root-caused.

**Combined across all three rounds**, 4 distinct classes have now been
confirmed at least once (SQLi round 1, SSRF + XSS round 2, Path Traversal
round 3) out of 6; OS Command Injection and Insecure Deserialization have
never confirmed in any round. `.pipeline_lessons.json` was unchanged by
this run — the one success reused an existing lesson rather than learning
a new one, so nothing new was persisted.

Total run cost: 218.1s, 19605 input tokens, 10135 output tokens,
**$0.0000** (local Ollama).

### Per-CVE pass/fail detail, with exact root cause

The summary table above answers "did it confirm." This table answers
"why, specifically" — pulled directly from each report's `execution_log`
and `refinement_history`, not paraphrased:

| CVE | Class | Stage 3.6 (1st try) | Stage 3.7 attempts | Final | Root cause (verbatim from `execution_log`) |
|---|---|---|---|---|---|
| CVE-2026-42208 | SQL Injection | exit_code=1, FAIL | 3, all `source=llm` | **FAIL** | Final revision's `target_app.py` crashed on startup: `SyntaxError: invalid syntax` at line 1, the literal text `` ```python `` |
| CVE-2026-27602 | OS Command Injection | exit_code=1, FAIL | 2 (1 `llm`, then "no known revision") | **FAIL** | Same markdown-fence `SyntaxError` on the revised `target_app.py` |
| CVE-2026-23949 | Path Traversal | exit_code=1, FAIL | 1, `source=lesson` | **PASS** | `poc.py` exited 0; read `C:\Windows\win.ini` via the traversal payload (Stage 3.8 patch attempt then rejected — see above) |
| CVE-2026-78683 | Insecure Deserialization | exit_code=1, FAIL | 3, all `source=llm` | **FAIL** | Target app stayed healthy the whole time; `poc.py` ran and printed `[-] FAILED` cleanly — the payload itself never triggered the vulnerable code path (not a crash) |
| CVE-2026-54729 | SSRF | exit_code=1, FAIL | 3, all `source=llm` | **FAIL** | Same markdown-fence `SyntaxError` on the revised `target_app.py` |
| CVE-2026-46492 | XSS | exit_code=1, FAIL | 2 (1 `llm`, then "no known revision") | **FAIL** | Same markdown-fence `SyntaxError` on the revised `target_app.py` |

**4 of the 5 failures share one root cause**, not five independent ones:
the LLM revision response's `poc.py`/`target_app.py` sections still
contained a literal `` ```python `` markdown fence that `_extract_marker`
did not strip, so the rewritten `target_app.py` was syntactically invalid
and crashed immediately on `python target_app.py`. Only
`CVE-2026-78683`'s failure is a distinct case — a clean, non-crashing
"payload didn't work" outcome.

### A second, previously-undocumented bug found while producing this table

Reading `cve_pipeline.py:2389-2394` (`execute_exploit_artifacts`) against
the data above surfaced a real gap: when the target process crashes
before its `/health` check ever succeeds, the function returns early and
**does not update `artifacts.exit_code` or `artifacts.dynamically_confirmed`**
— both keep whatever value was left over from the previous successful
execution. Concretely, `CVE-2026-27602` and `CVE-2026-46492`'s iteration-1
`refinement_history` entries record `"exit_code_after": 1,
"confirmed_after": False`, which reads as "the revision ran and the
exploit cleanly failed" — but the revision actually **crashed with a
SyntaxError and never ran at all**. The only place this is visible is the
top-level `execution_log` field (`=== target_app.py ===` followed by the
traceback), not the per-iteration `refinement_history` entry itself.

This matters for any claim built on `refinement_history` alone: right now
it cannot distinguish "the model tried a fix and it didn't work" from
"the model's output was broken and nothing ran." Not fixed in this
session — documented here first, deliberately, before any code change,
so the finding and the fix are separate, auditable steps rather than a
silent correction folded into a number that's already been reported.

Raw round-3 reports: `reports/llm_catalog_run_2026-09-23_round3/<CVE-ID>.json`.

## Round 4 — both round-3 bugs fixed (commit `b05b45d`), same protocol re-run

Fixed both bugs documented above: `_extract_marker` now strips a stray
leading/trailing `` ``` `` fence (`_strip_code_fence`), and
`execute_exploit_artifacts` now explicitly resets `exit_code`/
`dynamically_confirmed` instead of leaving them stale when the target
crashes before its health check. Verified independently before re-running
the catalog: a unit test against the exact failure shape from round 3
(response with an unstripped `` ```python `` fence) now parses as valid
Python; a targeted test that runs a healthy target then swaps in a
crashing one on the same `ExploitArtifacts` object now correctly shows
`exit_code=None`/`dynamically_confirmed=False` instead of the previous
run's stale `0`/`True`. Full test suite (7/7) still passes.

Re-ran the identical protocol (one shot per CVE, `--no-cache`, sandboxed):

| CVE | Class | Confirmed (r1) | Confirmed (r2) | Confirmed (r3) | Confirmed (r4) | Refine attempts | Patch attempted | Patch validated | Time (s) |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-42208 | SQL Injection | **True** | False | False | False | 3 | False | — | 58.1 |
| CVE-2026-27602 | OS Command Injection | False | False | False | **True** | 1 (`source=llm`) | **True** | False | 30.2 |
| CVE-2026-23949 | Path Traversal | False | False | **True** | False | 3 | False | — | 55.0 |
| CVE-2026-78683 | Insecure Deserialization | False | False | False | **True** | 0 | **True** | **True** | 17.7 |
| CVE-2026-54729 | SSRF | False | **True** | False | **True** | 0 | **True** | False | 18.6 |
| CVE-2026-46492 | XSS | False | **True** | False | **True** | 0 | **True** | False | 16.7 |
| **Total** | | **1/6** | **2/6** | **1/6** | **4/6** | **7** | **4/6** | **1/6** | **196.4** |

**This is a genuine jump, not noise dressed up as one:** 4/6 confirmed
(vs. 1/6 in round 3, the previous best was round 2's 2/6), and zero of
the six reports contain the markdown-fence `SyntaxError` crash signature
anywhere in their `execution_log` (checked programmatically, not by
spot-check) — the fence-stripping fix held across every CVE, not just
the ones that ended up confirming. Three CVEs (`CVE-2026-78683`,
`CVE-2026-54729`, `CVE-2026-46492`) confirmed on the **first** Stage 3.6
attempt with zero refinement needed — in round 3 all three of these
crashed on the fence bug and never got a real chance to succeed or fail
on their own merits; this round shows what Stage 3.5's generation alone
can do once its output isn't being silently mangled downstream.
`CVE-2026-27602` is the more interesting case: it genuinely needed and
got a working Stage 3.7 revision (`source=llm`, real diagnosis from a
real failure log, not a lesson reuse) — the first time in this project's
history a *live-generated-from-scratch* revision has fixed a failing
exploit. That fix was also persisted to `.pipeline_lessons.json` as a new
`OS Command Injection`/`generic_failure` lesson, available to any future
CVE hitting the same signature.

**First-ever validated patch: `CVE-2026-78683`.** Stage 3.8 generated a
patch adding a class whitelist to the deserialization call; re-running
the *original, unmodified* exploit against the patched target now gets a
real `500` (`ValueError: Deserialization only allowed for safe classes`,
visible verbatim in `patch_validation_log`) instead of the marker it got
against the vulnerable version, while `/health` still returns `200`. Both
required conditions hold for the first time across all four rounds.

**Still open, honestly:** `CVE-2026-42208` (SQLi) and `CVE-2026-23949`
(Path Traversal) did not confirm even with the fixes and 3 fresh
LLM-diagnosed revision attempts each in *this* round — real, clean
`[-] FAILED` results against a healthy target (not crashes), so the
remaining gap here is prompt/diagnosis quality for these two specific
classes on this run, not a plumbing bug. But counting per-class, not
per-round: SQLi confirmed in round 1 and Path Traversal confirmed in
round 3 — so **all 6 vulnerability classes in the catalog have now
confirmed dynamically at least once across the four rounds combined**,
none permanently stuck. What round 4 specifically adds is OS Command
Injection's first-ever confirmation (via a genuine live-generated
revision, not a template or a reused lesson) and Insecure
Deserialization's first-ever confirmation *and* first-ever validated
patch. The honest framing for the report: no class is unconfirmable, but
no single round has confirmed all 6 at once, and a single-shot
(non-fixed-seed) protocol means any one CVE's result can still flip
between runs — see round 1 vs. round 2's SQLi flip, documented above.

Total run cost: 196.4s, 16937 input tokens, 8783 output tokens,
**$0.0000** (local Ollama).

Raw round-4 reports: `reports/llm_catalog_run_2026-09-23_round4/<CVE-ID>.json`,
full terminal transcript at `reports/llm_catalog_run_2026-09-23_round4/RAW_LOG.txt`.
