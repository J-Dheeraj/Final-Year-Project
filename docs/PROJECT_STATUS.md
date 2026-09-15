# Project Status

## Session log

Format: date — what was attempted — exit criteria met or not. Newest
first. Add an entry at the end of every real work session so the next
one's opening move is unambiguous.

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

- [ ] **Wire in a live LLM.** Per an external review of this project:
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
