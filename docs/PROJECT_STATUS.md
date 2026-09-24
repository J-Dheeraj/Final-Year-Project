# Project Status

## Session log

Format: date — what was attempted — exit criteria met or not. Newest
first. Add an entry at the end of every real work session so the next
one's opening move is unambiguous.

- **2026-09-24 (ProvTrail SARIF made the real default source)** — The
  user flagged that the just-published architecture diagram showed
  NVD/GHSA as the primary path and ProvTrail as a dotted "optional"
  feed - backwards from `provtrail_bridge.py`'s own documented
  `--source=auto` priority (ProvTrail then feed fallback), which only
  actually took effect if the caller remembered to pass `--scan`
  explicitly. Fixed both the framing and the real gap: added
  `_default_scan_path()`, which auto-discovers a scan at the
  conventional `.provtrail/latest-scan.{sarif,json,ai.txt}` location
  (SARIF preferred) when `--scan` isn't given, so ProvTrail is now the
  genuine default source with zero flags needed - `--source feeds`
  remains the explicit escape hatch to skip it entirely. Caught and
  fixed a real bug in my own first edit before it ever shipped: the
  function body still referenced the now-stale `args.scan` (always
  `None` on the auto-discovery path) instead of the resolved
  `scan_path`, which would have crashed with `Path(None)` the first
  time discovery actually found a file - caught by re-reading the
  function after the edit, not by running it. Two new offline tests
  added (`test_default_scan_auto_discovered_when_no_scan_given`,
  `test_source_feeds_skips_default_scan_discovery`); full suite (9/9,
  up from 7) passing. Both README.md's and architecture.html's Mermaid
  diagrams corrected to show ProvTrail as the solid/default path and
  NVD/GHSA as the dotted/fallback one, matching the code exactly.

- **2026-09-24 (ProvTrail JS/TS bounded validation — DONE)** — Picked up
  the ProvTrail integration item's step 3 (`provtrail_js_lab/`), the one
  remaining substantial open item after everything else this session had
  flagged was closed out. Full detail in the ProvTrail item's own entry
  above and `provtrail_js_lab/README.md`. Summary: `execute_exploit_artifacts`
  now spawns `node` instead of Python when the target is `.js` (the ONE
  pipeline change, additive - Python path re-verified unaffected after
  the change, not just before); built one hand-authored JS target
  (`CVE-2024-48910`, dompurify Prototype Pollution, CWE-1321, CRITICAL -
  picked from the real ProvTrail fixture over two other real candidates
  for being genuinely JS-native and honestly reproducible) and its PoC;
  ran it through the real Stage 3.6 mechanism via `run_demo.py`, not a
  parallel script. Caught and fixed a real false-positive during
  verification: a leftover node process from earlier manual testing
  made a broken spawn attempt (`EADDRINUSE`) look like a clean success
  by accident - found via `netstat`, killed the stale PID, re-ran
  genuinely clean. Exit criterion met: one real end-to-end case,
  `dynamically_confirmed: True`, verified twice. Auto-classification/
  auto-generation for JS classes and a second JS class remain explicitly
  out of scope, as planned from the start.

- **2026-09-24 (qwen2.5-coder:1.5b timing outlier, narrowed)** — Picked
  up the other open item from `reports/PATCH_VALIDATION_INVESTIGATION.md`:
  a 1636.5s generation call for the smallest model, flagged but never
  investigated. Structural read first, before any live call: the
  `(None, None)` `generation_input_tokens`/`generation_output_tokens`
  pairing on that historical record is only possible on
  `_call_ollama_metered`'s failure/timeout path - a successful `200`
  always carries Ollama's own `prompt_eval_count`/`eval_count` - so this
  was never a slow *successful* generation, it was a request that
  ultimately failed. Reproduced live to confirm: re-ran the exact same
  CVE/model (`CVE-2026-54729`/`qwen2.5-coder:1.5b`) and got the identical
  failure mode on demand - `generation_outcome: llm_live_failed`,
  `generation_duration_s: 180.001` (capped at the `timeout=180` default),
  tokens `None`/`None`. Narrowed, not fully root-caused: the *class* of
  failure (this CVE/model pairing genuinely struggles to converge within
  the timeout) is now confirmed and reproducible, not a one-off; the
  *exact* 1636.5s figure (9x the 180s timeout) remains unexplained in
  full - `requests`' `timeout=` is a per-read-chunk timeout, not a hard
  total-request cap, so a low-level connection event could in principle
  let a call run past its nominal timeout, but this wasn't directly
  observed, only plausible given how `requests` timeouts work. Read
  `reports/PATCH_VALIDATION_INVESTIGATION.md`'s updated note for the
  full reasoning - stated as narrowed, not solved, deliberately.

- **2026-09-24 (mistral:7b patch-parse bug, diagnosed and fixed)** —
  Picked up the open item from `reports/PATCH_VALIDATION_INVESTIGATION.md`:
  mistral:7b's confirmed CVEs showing `patch_skip_reason: "...didn't
  parse"`. Reproduced directly (replayed `_llm_generate_patch`'s exact
  prompt against `mistral:7b` outside the pipeline, printed the raw
  response) before touching any code. Root cause: mistral:7b's patch
  response never emits the literal `===PATCHED_TARGET_END===` marker -
  it goes straight from the patched code to `===SUMMARY_START===` - so
  `_extract_marker`'s strict `text.index(end, s)` raised and the whole
  patch was silently discarded as empty, even though real, usable code
  was sitting right there in the response. Fixed in the shared
  `_extract_marker` (used by Stage 3.5/3.7/3.8 alike): fall back to the
  next `===X_Y===`-shaped marker as an implicit boundary when the exact
  end marker is missing. Verified 4 ways before and after: a unit test
  against the exact captured failure shape (0 → 842 chars recovered,
  compiles), two control cases (normal both-markers response unaffected;
  a genuinely markerless response still safely returns empty), and a
  live unmodified pipeline re-run on `CVE-2026-42208`/`mistral:7b` -
  before: `patch_attempted: False`; after: `patch_attempted: True`, a
  real patch summary, and an honest `patch_validated: False` (the patch
  itself didn't work, evaluated and rejected for real, not skipped).
  Exit criterion met: the parsing gap is closed and independently
  verified live, not just theorized.

- **2026-09-24 (post-merge verification)** — Ran `CVE-2026-78683` end to
  end on the just-reconciled `main` (`5417c29`), since the merge combined
  two independently-tested code paths (this session's exit_code fix,
  the other session's multi-payload validation + pinned sampling) that
  had never actually run together. Result: `dynamically_confirmed=True`
  (exit_code 0), `patch_attempted=True`, `patch_validated=True`, and
  `payload_variants` populated with 2 real distinct alternate payloads —
  the patch survived re-probing with both, not just the original. This
  is the strongest single result across every round run so far: real
  generation → real dynamic confirmation → real patch → validated
  against 3 total distinct payloads, all on the merged code, with no
  stale `exit_code`/`dynamically_confirmed` anywhere in the run. One CVE,
  one shot - not a full catalog re-run (that's a larger, separate task if
  wanted later) - but it directly answers the open question from the
  reconciliation entry above: the merge did not silently break either
  side's capability. Exit criterion met: the two independently-fixed
  code paths coexist and both fire correctly in the same run.

- **2026-09-24 (reconciliation)** — Two Claude sessions worked this repo
  in parallel on 2026-09-23, both branching from the same commit
  (`4c1a386`) without initially knowing about each other: this session
  (on `main` directly) and a separate session on `feat/live-llm-gate1`.
  Both independently found and fixed the exact same Stage 3.7 dead-code
  bug (`main`'s `e344966` vs. the branch's `3f21eda` — functionally
  identical) and a markdown-fence-in-model-output bug (`main`'s
  `b05b45d` vs. the branch's fix earlier in its own sequence) via
  different-but-equivalent implementations. Cross-session messaging
  surfaced the divergence before either side merged or deleted anything;
  a side-by-side diff against the shared merge-base confirmed: the
  branch has strictly more capability (multi-payload patch validation —
  a genuinely new mechanism guarding against a patch that just
  blocklists one literal payload; the 8-model Ollama comparison; pinned
  sampling for reproducibility; 2 more real bugs fixed: a discarded
  patched-process diagnostic log, an IPv4/IPv6 `localhost` ambiguity
  flipping `_ollama_available()`'s answer); `main` had one real fix the
  branch was missing (`execute_exploit_artifacts` leaving `exit_code`/
  `dynamically_confirmed` stale on a crash instead of resetting them)
  plus two catalog re-runs (rounds 3/4) the branch never ran.
  **Resolution**: merged `feat/live-llm-gate1` into `main` (not a reset —
  both sessions' full commit history is preserved), keeping the branch's
  implementation for every case where both sides fixed the same thing
  (its `_strip_markdown_fence`, its `_extract_marker` shadowing pattern),
  and porting `main`'s exit_code/dynamically_confirmed fix on top since
  the branch was genuinely missing it. `execute_exploit_artifacts` on the
  merged code already carried that fix cleanly (no conflict there — only
  `cve_pipeline.py`'s duplicate fence-helper, `patch.py`'s duplicate
  `_extract_marker`, `self_improve.py`'s docstring/metrics-recording
  style, and this file's own session log needed manual resolution). Full
  test suite re-verified passing post-merge before push. Both original
  session-log entries below are kept as-written, not edited to match
  each other — each is what was actually known and true at the time it
  was written.

- **2026-09-23 (later same day)** — Found and fixed a real dead-code bug
  in Stage 3.7, then used the fix to run two more full catalog rounds
  (3 and 4), finding and fixing two more bugs along the way. Full detail
  in `reports/LIVE_LLM_CATALOG_RUN.md` and `docs/DEFENSE_PREP.md`; this
  entry is the index.

  1. **Stage 3.7 dead-code bug (commit `e344966`)**: `src/pipeline/
     self_improve.py`'s `_llm_revise_artifacts` called
     `_call_claude`/`_claude_available` directly instead of the
     provider-agnostic `_call_live_model`/`_live_model_available` helper
     Stage 3.5/3.8 already used. Under this machine's real conditions (no
     `claude` CLI, local Ollama only), that meant Stage 3.7 silently
     never ran at all — not "stub-tested," genuinely dead. Fixed by
     mirroring the proven Stage 3.5/3.8 pattern; also added
     `revision_backend`/`model`/`duration_s`/`input_tokens`/
     `output_tokens`/`cost_usd` per `refinement_history` entry. Verified
     live against a synthetic failing fixture before touching the real
     catalog: the fix correctly fell through to Ollama and confirmed a
     real revision.

  2. **Round 3 catalog run (commits `5ecd4d0`, `6f932b4`)**: re-ran the
     frozen 6-CVE catalog with the Stage 3.7 fix live. Only 1/6 confirmed
     (`CVE-2026-23949`, via genuine cross-CVE lesson reuse — the first
     time that code path ever fired) — not better than round 2's 2/6,
     but the *mechanism* now demonstrably runs. Digging into the raw
     `execution_log` (not just the summary numbers) to write an honest
     per-CVE pass/fail table surfaced two previously-undocumented bugs,
     deliberately documented in a separate commit *before* fixing them:
     (a) `_extract_marker` didn't strip a stray `` ``` `` markdown fence
     from the model's response, so 4/5 failures crashed with
     `SyntaxError` on `target_app.py`'s first line; (b)
     `execute_exploit_artifacts` left `exit_code`/`dynamically_confirmed`
     stale on a crash instead of resetting them, so `refinement_history`
     could misleadingly read a crash as "ran and cleanly failed."

  3. **Bug fixes (commit `b05b45d`)**: added `_strip_code_fence`; reset
     `exit_code`/`dynamically_confirmed` explicitly on the crash path;
     removed `src/pipeline/patch.py`'s duplicate `_extract_marker` in
     favor of importing the shared, now-fixed one. Each fix verified with
     a standalone targeted test before re-running anything: one against
     the exact round-3 failure shape (now parses as valid Python), one
     that runs a healthy target then swaps in a crashing one on the same
     artifacts object (now correctly resets instead of staying stale).

  4. **Round 4 catalog run (commit `9711fe5`)**: same protocol, both
     fixes live. **4/6 confirmed** (up from 1/6), and zero of the six
     reports contain the `SyntaxError` crash signature anywhere,
     confirmed programmatically. Two firsts for the project: `CVE-2026-27602`
     confirmed via a genuine from-scratch Stage 3.7 revision (not a
     reused lesson) — the first live-generated revision to ever fix a
     failing exploit; `CVE-2026-78683` got its Stage 3.8 patch
     **validated** — the first validated patch across all four rounds
     (0/8 prior attempts). `CVE-2026-42208` (SQLi) and `CVE-2026-23949`
     (Path Traversal) still didn't confirm — real clean failures, not
     crashes, so a diagnosis-quality gap for those two classes on this
     run, not a plumbing bug. Counting per-class across all 4 rounds
     combined (not per-round): **all 6 vulnerability classes in the
     catalog have now confirmed dynamically at least once.**

  5. **Documentation (commits `c7cfb19`, `39f0dc4`)**: added an explicit
     "what is a test case" section to `reports/LIVE_LLM_CATALOG_RUN.md`
     (real advisory data + the exact simulated route/payload/pass-condition
     each generated PoC uses, pulled from round 4's actual generated
     artifacts, not paraphrased); updated `docs/SCOPE_AND_LIMITATIONS.md`'s
     Limitation 6 (the "zero live-generated revisions succeeded" caveat
     no longer holds) and its summary table (patch validation now
     demonstrated once); updated `docs/DEFENSE_PREP.md`'s "weakest
     evidence" answer (no longer "LLM paths are stub-only") and added
     three new Q&A entries for this session's findings.

  **Exit criterion**: not formally re-stated here (see the live-LLM item
  below for the item's own framing) — but concretely, generation,
  dynamic confirmation, self-improvement, AND patch validation all
  succeeded together for the same CVE (`CVE-2026-78683`) in the same run
  for the first time. All 6 commits pushed to `fyp` only, per this
  project's git-remote convention; `git diff HEAD fyp/main --stat`
  verified empty (local and remote identical) as of `39f0dc4`.

- **2026-09-23 (live-LLM Gate 1/2, full session, branch
  `feat/live-llm-gate1`)** — Closed out the "wire in a live LLM" Phase 4
  item end to end across all three LLM-touching stages (3.5 generation,
  3.7 self-improve, 3.8 patch), with real per-call cost/time/token
  metrics throughout — not estimated, read directly from the Claude CLI
  or Ollama's own `prompt_eval_count`/`eval_count`/`total_duration`
  fields. Full commit sequence: `a6aec31` (Stage 3.5 + local Ollama
  backend) → `a3d802d` (Stage 3.8 wired) → `0eb4a29`/`25c2699` (per-call
  and per-pipeline metrics) → `390c316` (first full catalog run) →
  `4c1a386` (schemeless-URL bug fix, round 2) → `b0b3377` (pinned
  sampling: `temperature=0`, fixed seed) → `c2d76a5` (8-model comparison)
  → `ba24163` (2 patch-gen bugs + multi-payload validation) →
  `276f62f` (patch-validation investigation write-up + clean 48-run
  re-test) → `7c7cfbe` (2 payload-extraction bugs, found *after* that
  write-up — see correction below) → `3f21eda` (Stage 3.7 wired to the
  same backend, closing the one remaining unwired call site).

  **What exists now**: `_call_live_model`/`_live_model_available` in
  `cve_pipeline.py` — Claude CLI first, local Ollama fallback
  (`OLLAMA_HOST` defaults to explicit `http://127.0.0.1:11434` after a
  real IPv4/IPv6 localhost-ambiguity bug was found via `netstat`, see
  below) — is now the single call path for all three stages. Every call
  returns a `LiveModelResult` (`text, backend, model, duration_s,
  input_tokens, output_tokens, cost_usd`) that gets recorded on
  `ExploitArtifacts`/`PipelineReport` (`generation_*`, `patch_gen_*`,
  and now `revision_*` on `refinement_history` entries) and rolled up
  into `total_llm_*` in every report and `src/metrics.py`'s
  `METRICS.md`.

  **Full model catalog run**: 8 local Ollama models (qwen2.5-coder at
  1.5b/3b/7b, llama3.1:8b, mistral:7b, gemma2:9b, codellama:13b,
  deepseek-coder-v2:16b) × the 6-CVE frozen catalog, run twice (an
  initial comparison in `reports/MULTI_MODEL_COMPARISON.md`, then a
  clean re-test after the patch-gen bugs below were fixed, in
  `reports/PATCH_VALIDATION_INVESTIGATION.md`). Claude/OpenAI explicitly
  **dropped** for this round per direct instruction ("drop Claude for
  this round, Ollama only") — no CLI/API key available in this
  environment, never silently worked around. Headline, stated plainly
  rather than as a leaderboard: confirmation rate does not track model
  size (7B beat both 9B and 13B); qwen2.5-coder:7b is the strongest
  confirmer but also has the most prior prompt-tuning exposure (a real
  confound); patch generation does not reliably work with any of these
  8 models on a single deterministic shot even after the bugs below were
  fixed (3/48 "validated," and see the caveat on what that number
  actually means below).

  **Real bugs found by direct challenge, not by process** — the user's
  own words drove this: *"to validate a patch you have to try and probe
  the patch"*, then *"if you can potentially bypass them, that means the
  patch is not good"*. Investigating that surfaced four real bugs (all
  in `reports/PATCH_VALIDATION_INVESTIGATION.md`, commit `ba24163`):
  (1) all 17 patch attempts in the first comparison crashed on a
  markdown-fence artifact the model wrapped its output in; (2) once
  fixed, patches sometimes omitted the Flask `app.run()` startup block
  entirely, exiting silently with no traceback; (3) the patched
  process's real stdout/stderr was captured internally then discarded,
  which is why bugs 1–2 were invisible until fixed; (4) `localhost`
  resolved to two different services on this machine (`ollama.exe` on
  IPv4, an unrelated process on IPv6), silently flipping
  `_ollama_available()`'s answer call to call — found via `netstat
  -ano`, not guessed.

  **Built in direct response to that same challenge**: single-payload
  patch validation is not proof a vulnerability class is closed — a
  patch that blocklists one literal string would pass. Stage 3.5 now
  also asks for 2 structurally distinct alternate payloads
  (`ExploitArtifacts.payload_variants`); `poc.py`'s generated contract
  now accepts a payload override (`exploit(host, port, payload=None)`,
  `sys.argv[2]`); Stage 3.8 re-probes every would-be-validated patch
  with each alternate payload and overrides `patch_validated` back to
  `False` on the first one that still succeeds. Verified correct on a
  controlled synthetic case (a deliberately narrow blocklist patch
  passed the old single-payload check, then was correctly caught and
  rejected once a structurally different payload was tried) — no Ollama
  call needed for that proof.

  **Correction to `reports/PATCH_VALIDATION_INVESTIGATION.md`**: that
  report's "Bottom line" section states the payload-extraction quality
  gap (echoed placeholder text, unstripped backticks) was "not fixed
  here." That was true when written; it no longer is. Commit `7c7cfbe`
  (same day, after that report) fixed both: `_clean_payload_variants()`
  now drops a whole block that's a single parenthetical (the model
  echoing the prompt's own placeholder instructions back verbatim
  instead of real payloads) and strips a wrapping single backtick per
  line. Verified offline against the two real bad inputs that were
  found, plus a clean case and a mixed-line case, and with one live
  re-run (`qwen2.5-coder:1.5b` / `CVE-2026-46492`) confirming
  `payload_variants` now comes back clean or empty, never garbage. The
  report file itself was intentionally left as the honest record of
  what was true at the time it was written rather than rewritten after
  the fact — this entry is the correction, read both together.

  **Stage 3.7 wiring (`3f21eda`, last commit of the session)**: Stage
  3.7 (`src/pipeline/self_improve.py`) was the one remaining call site
  still checking `_claude_available()` only — under this session's
  Ollama-only conditions it silently never ran, the exact class of
  "silent fallback" gap Gate 1 was built to expose everywhere else.
  Mirrors the identical pattern already proven for Stage 3.5/3.8.
  Verified live: `CVE-2026-23949` / `qwen2.5-coder:7b` produced 3
  refinement attempts, each showing `revision_backend=ollama` with real
  duration/token counts — previously this returned `None` every time.

  **Exit criteria met**: all three LLM call sites use the unified
  backend with real recorded metrics (not estimated); multi-payload
  patch validation is built and proven correct; 4 real bugs found and
  fixed with direct evidence (not assumed).
  **Exit criteria explicitly NOT met / left open** (per
  `reports/PATCH_VALIDATION_INVESTIGATION.md`'s own honest framing —
  read that file for the full numbers): mistral:7b's patch responses
  fail to parse for a reason distinct from the `localhost` bug, not
  diagnosed; qwen2.5-coder:1.5b had one 1636.5s generation outlier,
  flagged not investigated; getting models to reliably produce
  well-formed alternate payloads in practice is still the real gap —
  the honest headline is **not** "3/48 patches validated," it's
  "0/48 patches have been tested against more than their original
  payload" (all 3 "validated" cases had `payload_variants: []`).
  ProvTrail's JS/TS dynamic-execution work (below) and further
  root-causing were both deliberately deferred given context budget,
  not silently dropped — see the plan file this session executed
  against for the explicit scope cut.

  **Also this session, but tooling, not project substance** (kept out
  of this project's own doc, noted here only for continuity): installed
  and started `claude-mem` (a separate, local, Claude-Code-native
  observation memory tool) at the user's explicit request, kept
  deliberately distinct from this project's own documentation/memory
  system — it does not replace or touch anything in this repo.

- **2026-09-23** — Built the *ingestion + orchestration* half of the
  Phase 4 ProvTrail item (`provtrail_bridge.py`, `package_labs.py`,
  `tests/test_provtrail_bridge.py` + SARIF/AI-text fixtures; pushed to
  `fyp` as `2e7a6b4`). The bridge reads a ProvTrail SARIF / AI-text / raw
  `provtrail_scan_v*` JSON scan, dedupes advisories, runs the existing
  `cve_pipeline` per advisory, and writes a combined detect+locate ->
  confirm+patch report; falls back to this project's own NVD/GHSA feeds
  when no scan is usable. **Gate 1 cleared** (see the ProvTrail item):
  a real sample from Elson confirms the CVE ID travels in
  `properties.provtrail.advisoryIds` (the generic properties bag, exactly
  as predicted), location in the standard `physicalLocation`,
  priority/confidence alongside; all three export formats resolve to the
  identical 6 advisories, verified by an offline test. **Exit criterion
  for the FULL item NOT met and not claimed**: the pipeline still
  generates only Python Flask targets, so every JS/npm advisory the bridge
  runs is honestly reported "static+patch only (no matching lab)" — zero
  dynamic confirmation of a ProvTrail finding yet. Steps 2-4 (JS/TS
  dynamic execution) remain; `package_labs.py` is the seam where a future
  Node/Express lab registers. JS/TS build still deferred per the Sept 28
  note in that item. Done this session at the user's direction, ahead of
  the item's original "revisit after Sept 28" framing — a deliberate
  divergence, not a silent one.

- **2026-09-15** — Extended the Stage 2 classification ablation from
  n=1 to the full 6-CVE catalog (`docs/BENCHMARK_PROTOCOL.md` §7), run
  directly against the real `_classify_from_text`/`_classify_from_cwe`
  functions and real stored advisory data. Exit criterion met: 1/6
  class-level failure, 2/6 CWE-level mismatches, both real and
  reproducible. Refined further same day: split into 3 metrics
  (class-match/exact-CWE-match/full-miss), cross-checked NVD's CWE
  against GitHub's independent advisory database for all 6 CVEs (6/6
  agree — real mitigation of the single-source circularity concern),
  pre-registered scoring methodology for the future live-LLM session.
  `origin` (AI-exploit-CVE) force-pushed back to `88844d2` at the user's
  explicit request — frozen for conference use; all work from here on
  goes to `fyp` (Final-Year-Project) only. Live-LLM wiring and the S1
  litellm stratum (below) were deliberately NOT attempted this
  session — still open.

Living checklist. Update after every real work session — mark nothing
done that isn't actually verified. Adapted from an external plan's
checklist pattern, applied to this project's actual stages, not a
parallel system.

## Phase 0 — Core pipeline (DONE)

- [x] Stages 1-4 implemented (`cve_pipeline.py`) — advisory fetch,
      classification, probe, report
- [x] Stage 3.5-3.7 implemented — exploit generation, dynamic execution,
      self-improvement
- [x] Stage 3.8 implemented — patch generation + two-check validation
- [x] 8 catalog entries run end-to-end, 6/8 dynamically confirmed
      (`reports/CVE_CATALOG.md`)
- [x] Can explain every stage without notes — **verified via Socratic
      walkthrough**; see corrections that were actually needed in
      `docs/SCOPE_AND_LIMITATIONS.md`

## Phase 1 — Refactor + metrics (DONE)

- [x] `cve_pipeline.py` extracted into `src/` package (3643 -> 2596 lines)
- [x] `src/metrics.py` reads `reports/*/report.json` for real numbers
      (no fuzzing/static baselines — deliberately not measured, see
      `docs/BENCHMARK_PROTOCOL.md` §2)
- [x] Stale duplicate folders + 12MB video removed from git history going
      forward

## Phase 2 — Real-source work (DONE, one case)

- [x] `src/reachability/` ported from reachcrs, reproduces its own known
      numbers exactly (102 functions, 4 reachable, 96.1% reduction)
- [x] Real free5GC/udr repo cloned, both vulnerable and fixed commits
      confirmed to build
- [x] Generated patch applied to the real cloned module, confirmed to
      still `go build ./...` — **new capability, not present in reachcrs**
- [ ] Real *dynamic* (HTTP-level) confirmation against the real free5GC
      service — blocked on standing up MongoDB + NRF registration, not
      attempted (`docs/SCOPE_AND_LIMITATIONS.md` Limitation 4)
- [ ] `free5gc_lab/` and `src/reachability/`'s free5GC case study unified
      into one effort — currently two disconnected pieces targeting the
      same bug family (Limitation 5)

## Phase 3 — Documentation & framing (DONE)

- [x] Project pitch corrected away from "fuzzing" (confirmed OK with
      professor; professor has since said they're open to whatever
      direction is taken — this project continues on engineering merit,
      not because fuzzing is off-limits)
- [x] `docs/CRS_MAPPING.md` — honest AIxCC/OSS-CRS alignment
- [x] `docs/SCOPE_AND_LIMITATIONS.md` — report-ready claim/evidence table
- [x] `docs/BENCHMARK_PROTOCOL.md` — frozen catalog, precise metrics,
      provenance tracking (adapted from external rigor pattern, no
      fuzzing baselines adopted)
- [x] `docs/DEFENSE_PREP.md` — Q&A built from actual walkthrough gaps

## Phase 4 — Open, not started (top two elevated to priority — see plans below)

- [ ] **Wire in a live LLM.** External supporting evidence this is worth
      doing, not just internally motivated: a September 2026 industry
      writeup (Val Marelox, ["Can AI weaponize new CVEs in under an
      hour?"](https://valmarelox.substack.com/p/can-ai-weaponize-new-cves-in-under))
      reports an independently-built pipeline with the same three-stage
      shape this project already has (advisory analysis -> generate
      vulnerable-app+exploit -> execute against vulnerable/patched
      versions) running end-to-end on a live model (Claude Sonnet 4.0),
      producing 10 working exploits across JS/Python/Ruby in ~10-15
      minutes and ~$1 per CVE. Useful as a rough benchmark for what to
      expect once this project's own live-LLM session runs — not
      equivalent evidence, since it's a blog post, not peer-reviewed,
      and the architecture match doesn't make its numbers this
      project's numbers. For contrast, Theori's own RoboDuck README
      (a real AIxCC finalist, not a blog post) warns their
      competition-tuned, multi-agent CRS "can easily spend $1,000 or
      more in under an hour" -- the two real data points bound a huge
      range (~$1/CVE vs. ~$1000/hour) depending entirely on model
      choice and agent count, useful context for scoping the frozen
      prompt set's cost before running it broadly. Also worth noting: the author's own caveat —
      "the refinement loop could generate exploits that worked but
      weren't genuinely exploitative" — is the same class of false-
      positive risk as the existence-only `verify()` bug found and
      fixed in this project's CVE-2026-78683 case (commit `da84781`),
      independently surfacing in someone else's pipeline too.

      **More precise first-party number, 2026-09-17**: FuzzingBrain's
      own README (correct current org is `fuzzingbrain`, not `o2lab` —
      same project, renamed) states one example run measured at
      **14.6 minutes and $2.14** against a $20 budget cap — a real,
      specific number from the tool's own docs, not an estimate.

      **Real citable paper found**: FuzzingBrain has an actual arXiv
      paper, not just a competition repo — "All You Need Is A Fuzzing
      Brain: An LLM-Powered System for Automated Vulnerability
      Detection and Patching" (Sheng, Xu, Huang, Woodcock, Huang,
      Donaldson, Gu, Huang, 2025), arXiv:2509.07225. Stronger and more
      specific than the generic DARPA AIxCC results-page citation
      already in the free5GC paper's Related Work — worth using in the
      *thesis*'s Related Work chapter (not the locked paper). Also
      genuinely runnable (`./FuzzingBrain.sh`, Docker mode, REST API,
      MCP server, Apache-2.0, active commits) unlike Atlantis/Buttercup,
      which need Kubernetes + Kythe/Sootup/SVF cloud infra to even start.

      **Buttercup (Trail of Bits)**: also deployment-focused at the top
      level, but confirms SARIF as a cross-team standard (`send_sarif.sh`
      is a real script in their orchestrator, independent of Atlantis) —
      further validating Elson's SARIF choice for ProvTrail against
      actual competition practice, not just one team's convention. Their
      `program-model/` (reachability-equivalent) uses Kythe + cscope +
      JanusGraph — again heavyweight, cloud-scale (n2-highmem-8 instance,
      70-minute Docker builds), not a porting candidate, same conclusion
      as Atlantis's Sootup/SVF.

      **Bug Buster (42-b3yond-6ug)**: README is deployment-only, no
      architecture detail without digging into individual `components/`
      subfolder READMEs, which the top-level README itself warns may be
      outdated. Not pursued further — diminishing returns.

      **SHERPA — real results, but a genuine fuzzing-framing tension,
      2026-09-17.** Checked the actual README, not just the one-line
      description. It's a real, results-backed tool: 127+ raw crashes
      across real OSS-Fuzz projects, auto-filtered by an LLM crash-triage
      agent down to 18 validated CVE-class bugs (67% precision, CWE
      breakdown published). Its core principle — prioritize
      attacker-controlled entry points over low-level internal APIs —
      is philosophically the same argument this project's reachability
      filtering already makes. **But its mechanism is explicit,
      proud, marketed fuzzing** ("Revolutionary LLM-powered fuzzing"),
      built on libFuzzer coverage-guided campaigns. This project
      deliberately dropped fuzzing framing this session, with the
      professor's blessing (see "Project framing" in `CLAUDE.md`).
      **Do not cite or adopt SHERPA's fuzzing mechanism without the
      user explicitly asking** — same rule as fuzzing language
      generally. The one separable, non-fuzzing part worth naming: its
      Stage 1 "Intelligent Target Selection" (attacker-controlled
      entry-point prioritization) is explicitly a distinct phase before
      any fuzzing starts — confirms the entry-point-first principle is
      sound industry practice, without requiring adoption of the
      fuzzing stages that consume it.

      **Repository Visualizer**: not a code-porting candidate (a
      Three.js-style data viz frontend, "Created by Undaunted," a
      contracted vendor). But it exposes real ground-truth data: the
      actual AIxCC Final Competition task list — real production C/Java
      projects (curl, wireshark, openssl, log4j2, xz, freerdp, poi,
      pdfbox...) with real per-task vulnerability counts and codebase
      scale (curl: ~4,000 files across many tasks; wireshark: ~7,000).
      Useful as an honest scale comparison for the thesis — AIxCC
      operates on huge, multi-thousand-file real projects at
      competition-grade cloud infrastructure scale; this project
      targets one CVE at a time with a lightweight, single-developer
      pipeline. Worth naming that contrast explicitly rather than
      letting page count silently imply equivalence.

      Per an external review of this project:
      the flagship worked example (`docs/CRS_MAPPING.md`,
      `materials_for_glm.md`) has zero live model calls end to end —
      fetch is an API call, classification is a lookup, generation was a
      hardcoded template, execution is LLM-independent, and patch
      generation was stubbed. That's a real gap for a project about
      using LLMs to secure OSS, not just a caveat. Concrete plan, in
      strict order — each step gates the next, not a checklist to
      reorder for convenience:
      1. **Gate**: fix the silent-fallback path in
         `generate_exploit_artifacts()` (`if not poc_code or not
         target_code: <template>` currently swallows a failed live
         attempt with no distinct signal). Add `generation_outcome`
         (`llm_live_success` / `llm_live_failed` / `template`) to
         `ExploitArtifacts`, surfaced through `compile_report()` into the
         final report — the live-generation failure rate becomes a
         measured result, not an invisible footnote. See
         `docs/BENCHMARK_PROTOCOL.md` §4's pre-registered rule. Nothing
         below runs until this gate clears.
      2. Install Ollama; pull a small code model (`qwen2.5-coder:7b` or
         similar). Add a provider-agnostic adapter alongside the existing
         `_call_claude()`/`_claude_available()` (same call sites Stage
         3.5/3.7/3.8 already use). Verify a single trivial call works
         before doing anything else.
      3. **Bounded prompt development**: draft prompts for each advisory
         condition (full/description-only/ID-only) and test freely
         against exactly ONE catalog CVE — iterate as much as needed here.
         The moment any catalog-condition run starts on a second CVE, the
         prompt set is **frozen** for the rest of the session. This is
         the line between honest prompt development and post-hoc tuning;
         don't let "draft inside the session" drift into "draft
         interactively, mid-condition."
      4. Run the catalog under the now-frozen conditions. Record
         `generation_mode`/`generation_outcome`, model ID, and
         temperature in every report. Exit criterion:  at least one CVE
         completes the full chain (live-generated PoC -> dynamically
         confirmed -> patch_validated) — not "all six work." Report
         degraded/failed generations honestly, don't cherry-pick.

         **Done, 2026-09-23 (branch `feat/live-llm-gate1`):** ran all 6
         catalog CVEs, one shot each, frozen prompt, real
         `qwen2.5-coder:7b` via local Ollama, real time/token/cost per
         report (see the live-LLM Gate-1/2 instrumentation above) — full
         results in `reports/LIVE_LLM_CATALOG_RUN.md`. **Exit criterion
         partially met**: CVE-2026-42208 reaches live-generation ->
         dynamic-confirmation (both True); patch was attempted but
         `patch_validated=False` (the model's patch used generic
         auth-format validation the injected payload still passes — a
         real, explained patch-quality failure). 5/6 other CVEs did not
         dynamically confirm on their single frozen shot (`exit_code=1`
         each) — reported honestly, not cherry-picked, not retried. Root
         cause: the prompt's success contract was iterated and converged
         against SQL Injection only (step 3); it does not reliably
         zero-shot transfer to the other 5 classes with a 7B model.
         Per-class prompt tuning (repeating step 3's bounded process per
         class) is the natural next step to raise the confirmation rate,
         not attempted here to keep this run an honest single-frozen-
         prompt baseline.

         **Round 2, same day:** found a real, shared bug in 3/5 failures
         (PoC used the schemeless `host:port` argv directly as a URL,
         silently swallowed by a broad `except`) and fixed it with one
         generalizable prompt rule. Re-ran the full catalog: 2/6 confirmed
         this round (SSRF, XSS — both new), but CVE-2026-42208 (SQLi,
         confirmed in round 1) did NOT confirm in round 2 with the
         identical wording — real model-sampling variance, not a
         regression. Correct combined statement: **3 distinct classes
         confirmed at least once across the two rounds (SQLi, SSRF, XSS),
         not "2/6."** Full honest comparison, including the fix's own
         first-attempt bug (an f-string escaping mistake that broke all 6
         re-runs identically before being caught and fixed), in
         `reports/LIVE_LLM_CATALOG_RUN.md`.

         **Done, same day (see the full session-log entry above)**: all
         three LLM call sites (Stage 3.5, 3.7, 3.8) wired to a single
         provider-agnostic backend with real per-call metrics; 8-model
         Ollama comparison run; multi-payload patch validation built and
         proven correct; 4 real bugs found and fixed (markdown fence,
         missing `app.run()`, discarded diagnostic, `localhost`
         ambiguity) plus 2 payload-extraction bugs. This Phase 4 item is
         now substantially closed — what remains open (mistral:7b parse
         failures, the 1.5b timing outlier, and reliably producing
         well-formed alternate payloads in practice) is tracked in
         `reports/PATCH_VALIDATION_INVESTIGATION.md`, not re-listed here.
- [ ] **S1 fidelity stratum — real litellm, not a reproduction, for one
      CVE.** The single highest-value upgrade to Limitation 1
      (`docs/SCOPE_AND_LIMITATIONS.md`). Concrete plan:
      1. `pip install litellm==<the CVE-2026-42208 vulnerable version>`
         in an isolated environment/container.
      2. Stand up litellm's actual proxy server with the config needed
         to reach the vulnerable database-backed API-key-check code path
         (real setup — litellm's proxy needs a master key and a DB
         backend configured; this is not a one-line run).
      3. Craft and confirm a real HTTP exploit against the real server
         (not `target_app.py`) — same dynamic-confirmation discipline as
         the rest of Stage 3.6, pointed at real code.
      4. Patch-validate against the real package if feasible, or state
         plainly why not (e.g. no upstream patch to apply cleanly).
      One successful S1 result turns Limitation 1 from a blanket
      disclaimer into a disclosed stratum with one real data point — a
      genuine strengthening, reportable either way it turns out.
- [ ] **ProvTrail integration — professor-suggested, 2026-09-16.** Combine
      this project with a classmate's FYP tool, ProvTrail (a local CLI
      that statically scans JS/TS codebases against a GHSA/OSV corpus and
      flags likely clones of known-vulnerable code, exact/inferred/
      needs-review, no runtime testing at all). Agreed shape: ProvTrail's
      static findings feed this project's dynamic-confirmation pipeline
      as a downstream stage — closing exactly the evidentiary gap
      ProvTrail itself doesn't close (a static resemblance match is not
      proof of exploitability). The other student is aware and has
      explicitly said their own implementation approach isn't binding —
      full freedom on how to build the integration.

      **Real size of this, stated honestly**: not a wire-up. Every
      existing exploit template (Stage 3.5) generates a Python Flask
      target; there is currently zero JS/TS dynamic-execution capability
      anywhere in this pipeline. Comparable in scope to when native-code
      memory-safety support was added, not a small addition.

      **Update, 2026-09-16**: the other student (Elson) is adding SARIF
      output to ProvTrail — a real OASIS-standardized, versioned JSON
      format for static-analysis results, not a bespoke schema
      (verified via sonarsource.com/resources/library/sarif, not taken
      on faith). A SARIF result carries a rule ID, message, source
      location, severity, and — directly relevant here — a CWE/CVE
      security mapping field. This meaningfully de-risks Gate 1 below:
      the integration parser can be designed against the public SARIF
      spec now, not blocked entirely on Elson's source. What still
      needs a real sample from him: exactly how ProvTrail populates the
      CVE-mapping field in practice (SARIF's security-mapping fields are
      somewhat tool-dependent in how strictly they're filled in), and
      whether the flagged snippet/file location comes through in the
      standard `physicalLocation` field or a custom `properties`
      extension.

      **Real SARIF field structure, verified against Microsoft's
      sarif-tutorials (not the marketing page), 2026-09-16:**
      - Base result shape (confirmed real ESLint example):
        `runs[].results[].{ruleId, level, message.text,
        locations[].physicalLocation.{artifactLocation.uri,
        region.startLine}}` — this part is standard, adapter-safe now.
      - CWE has a proper first-class path:
        `runs[].tool.driver.supportedTaxonomies` + a `taxonomies[]`
        block defining CWE as a taxonomy, and each `results[]` entry
        can carry `taxa: [{id, toolComponent: {name: "CWE"}}]`.
      - **CVE does not** — SARIF's taxonomy/`taxa` mechanism is built
        for stable classification systems (CWE, OWASP), not point-in-
        time identifiers like CVE numbers. ProvTrail's CVE ID will
        almost certainly travel through the generic `properties` bag
        (tool-specific, any name/value pairs) or be embedded in a
        rule's `helpUri`/`fullDescription`, not a dedicated field.
        This is the one thing genuinely still unknown without a real
        sample — everything else above is now designable from the
        public spec alone.

      **Progress, 2026-09-23**: the ingestion + orchestration layer is
      built and pushed (`provtrail_bridge.py`, `package_labs.py`, tests;
      commit `2e7a6b4`) — parses ProvTrail SARIF/AI-text/raw JSON, feeds
      each advisory to the existing `cve_pipeline`, writes a combined
      report, and falls back to NVD/GHSA feeds when no scan is usable.
      This is the wire-up the note above said is *not* the hard part; the
      hard part (steps 2-4, JS/TS dynamic execution) is untouched. Run
      today it dynamically confirms nothing — every JS advisory is
      "static+patch only (no matching lab)" — so the item stays open.

      **Gated plan, in order — each step gates the next:**
      1. **Gate — CLEARED 2026-09-23.** Real ProvTrail SARIF/AI-text
         samples are now in hand (`tests/fixtures/provtrail/`). The CVE ID
         travels in `properties.provtrail.advisoryIds` (the generic
         `properties` bag, exactly as predicted above — not a taxonomy),
         with `packages`, `confidence`, and `priority` alongside it, and
         the location in the standard `physicalLocation`. The raw
         `provtrail_scan_v*` scan JSON is ProvTrail's internal state, not a
         consumer contract — its advisory *selection* needs ProvTrail's own
         `finding_exports.project_findings`, so the bridge uses that when
         ProvTrail is importable and otherwise asks for the SARIF/AI-text
         export. Original gate text (kept for context): get one real sample
         SARIF report to see which `properties` key carries the CVE ID,
         since that's the one piece SARIF's standard doesn't fix; location
         and message fields were already known-good from the public spec.
      2. Decide integration mode explicitly, don't default to the
         harder one without weighing it:
         - **(a) Class-level confirmation (recommended MVP)**: build
           JS/TS exploit templates (Node/Express targets) mirroring the
           existing 6-class Python template architecture, keyed off the
           CVE's vulnerability class. Reuses Stage 3.5/3.6's already-
           proven pattern; confirms the *class* of bug is dynamically
           reachable, not literally the exact flagged line in the exact
           scanned project.
         - **(b) In-place confirmation (harder, more valuable, later)**:
           actually exercise the specific flagged function inside the
           real scanned codebase. Directly closes ProvTrail's evidentiary
           gap, but arbitrary third-party JS/TS projects have wildly
           inconsistent build/run requirements — closer in difficulty to
           the memory-safety harness-generation work than to the existing
           Python templates. Don't start here.
      3. **Bounded validation — DONE, 2026-09-24.** Built exactly ONE
         JS/TS template (`provtrail_js_lab/`), for exactly ONE
         ProvTrail-flagged CVE from the real fixture
         (`tests/fixtures/provtrail/latest-scan.ai.txt`):
         `CVE-2024-48910` (dompurify, Prototype Pollution, CWE-1321,
         CRITICAL) — chosen over the fixture's other two real
         high-confidence `VULN` entries (a Next.js HTTP-smuggling CVE, a
         fastify one) because prototype pollution is genuinely JS-native
         with no equivalent in this pipeline's existing 6 Python classes,
         and far more tractable to honestly reproduce than smuggling's
         precise HTTP-framing requirements. One real pipeline change,
         additive only: `execute_exploit_artifacts` now spawns `node`
         instead of the Python interpreter when the target file is
         `.js` — the Python path is otherwise completely untouched,
         verified by re-running an existing Python CVE end-to-end
         *after* the change (still confirms, still patches, still passes
         multi-payload validation, identical to before). `provtrail_js_lab/`
         has a hand-authored `target_app.js` (zero npm deps — Node's
         built-in `http`/`url` only) and `poc.py` (same 4-phase pattern
         as every other CVE's PoC), run through the *real*
         `execute_exploit_artifacts` (not a parallel script) via
         `run_demo.py`. Result: `dynamically_confirmed: True` — real
         global `Object.prototype` pollution, verified twice (once with
         a stale leftover process from manual testing giving a
         false-clean read, caught via `netstat`/`taskkill`, then re-run
         genuinely clean with a fresh spawned process).
      4. Exit criterion matches the live-LLM item's discipline above:
         **met** — one real end-to-end case (ProvTrail flag -> dynamic
         confirmation) succeeded. Explicitly not attempted: auto-
         classification (Stage 2) or auto-generation (Stage 3.5) for JS
         classes, or a second JS/TS class — both correctly out of scope
         for this bounded pass; "all classes work" was never the bar.

      **Strong precedent found, 2026-09-17**: Team Atlanta's Atlantis —
      the actual AIxCC Final Competition winner — has a real, working
      module for exactly this shape of integration:
      `example-crs-webservice/crs-sarif`. Verified against its own
      README (not the source itself): it runs as
      `python test_crs_sarif.py -s <sarif-report-path>`, taking a SARIF
      report as input and running reachability analysis against it to
      produce `sarif_analysis.json`. Sub-components: `sootup/`
      (callgraph generation via the established Sootup framework for
      Java), `tracer/` ("getting call traces from seed or pov" — a
      dynamic complement to static reachability), and a genuine TP/FP
      benchmark structure (SARIF reports from PoV-to-SARIF generation,
      commercial SAST, and custom generation, scored against known
      ground truth). This is real validation that "SARIF in ->
      reachability analysis -> validated output" is a legitimate,
      competition-winning architecture, not a shape this project
      invented in isolation. Not a code-porting candidate — Sootup/SVF
      are heavyweight academic frameworks, wrong scope for a student
      FYP — but worth citing as precedent, and their TP/FP benchmark
      methodology is worth a look for `docs/BENCHMARK_PROTOCOL.md`.

      **Explicitly NOT started before the free5GC paper's September 28
      deadline** — this needs the other student's actual code (not yet
      in hand) and is real new-language engineering, not something to
      rush alongside a submission. Revisit right after.
- [ ] **(Optional, low priority) Family-tolerant CWE matching** in
      `_classify_from_text()` — currently hardcodes one representative
      CWE per class (e.g. always CWE-79 for any XSS keyword hit), which
      is what causes the CVE-2026-46492 mismatch in
      `docs/BENCHMARK_PROTOCOL.md` §7. Deliberately NOT fixed now —
      patching the classifier after already running and reporting that
      ablation would turn a measurement into a moving target. If pursued
      later: accept any member of the real CWE family per class,
      sourced from the official CWE site at implementation time, not
      from memory.
- [ ] **LICENSE for this repo** — no LICENSE file exists yet. Explicitly
      deferred: check the university's IP policy for FYP work before
      publishing any license (some institutions claim rights over FYP
      code or restrict public licensing until after grading). Do not add
      a LICENSE file speculatively.
- [ ] `docs/BENCHMARK_PROTOCOL.md`'s freeze date — not yet set; catalog
      is still open to additions
- [ ] Second, independent CVE class for the free5GC reachability work
      (currently one case, CVE-2026-40248)
- [ ] Decision on whether to pursue full dynamic free5GC confirmation
      (needs a MongoDB + NRF deployment — real infrastructure work, not
      a quick add)
- [ ] Report/thesis writing — nothing in this repo constitutes report
      prose beyond the `docs/` reference material above; do not treat
      any `docs/*.md` file as report-ready without adapting the voice

See `docs/CONSIDERED_DIRECTIONS.md` for proposals evaluated and
deliberately not adopted, with reasoning — check there before revisiting
a direction that may have already been ruled out for a documented reason.

## What NOT to do without deliberately deciding to

- Don't add fuzzing (AFL++/libFuzzer/coverage-guided mutation) as a
  drive-by addition — if it happens, it should be a deliberate scope
  decision with its own rationale, not scope creep from an external plan.
- Don't build a second, parallel pipeline that duplicates
  `cve_pipeline.py` + `src/reachability/`'s existing capability.
- Don't claim `llm-live` provenance for any result until a real API key
  or `claude` CLI is actually configured and used in this environment.
