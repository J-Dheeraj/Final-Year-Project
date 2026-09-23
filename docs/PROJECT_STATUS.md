# Project Status

## Session log

Format: date — what was attempted — exit criteria met or not. Newest
first. Add an entry at the end of every real work session so the next
one's opening move is unambiguous.

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
      3. **Bounded validation**: pick exactly ONE ProvTrail-flagged CVE
         (e.g. the Axios example from their demo), build ONE JS/TS
         template for its class, confirm it dynamically executes end to
         end before committing to building out more classes.
      4. Exit criterion matches the live-LLM item's discipline above: one
         real end-to-end case (ProvTrail flag -> dynamic confirmation)
         is success, not "all classes work." Report what doesn't work
         honestly rather than cherry-picking the class that does.

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
