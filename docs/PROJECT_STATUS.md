# Project Status

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

## Phase 4 — Open, not started

- [ ] `docs/BENCHMARK_PROTOCOL.md`'s freeze date — not yet set; catalog
      is still open to additions
- [ ] Live-LLM verification of Stage 3.7/3.8's LLM paths (currently
      stub-only in this environment — see `docs/BENCHMARK_PROTOCOL.md` §4)
- [ ] Second, independent CVE class for the free5GC reachability work
      (currently one case, CVE-2026-40248)
- [ ] Decision on whether to pursue full dynamic free5GC confirmation
      (needs a MongoDB + NRF deployment — real infrastructure work, not
      a quick add)
- [ ] Report/thesis writing — nothing in this repo constitutes report
      prose beyond the `docs/` reference material above; do not treat
      any `docs/*.md` file as report-ready without adapting the voice

## What NOT to do without deliberately deciding to

- Don't add fuzzing (AFL++/libFuzzer/coverage-guided mutation) as a
  drive-by addition — if it happens, it should be a deliberate scope
  decision with its own rationale, not scope creep from an external plan.
- Don't build a second, parallel pipeline that duplicates
  `cve_pipeline.py` + `src/reachability/`'s existing capability.
- Don't claim `llm-live` provenance for any result until a real API key
  or `claude` CLI is actually configured and used in this environment.
