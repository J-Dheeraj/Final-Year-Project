# Benchmark Protocol

Adapted from a rigor pattern (benchmark freezing, precise metric
definitions, provenance stratification) reviewed from an external plan —
**not** from that plan's fuzzing baselines or architecture, which this
project deliberately does not use (see `docs/SCOPE_AND_LIMITATIONS.md`).
Applied here to the catalog that already exists in this repo, not a new
system.

Any change to the frozen catalog after the freeze date below requires an
entry in the Change Log with a date and reason. Do not silently add or
drop entries.

## 1. Ground truth: the frozen catalog

| # | ID | Origin | Real source or reproduction |
|---|---|---|---|
| 1 | CVE-2026-42208 (litellm, SQLi) | Real, disclosed CVE | Reproduction (`target_app.py`) |
| 2 | CVE-2026-27602 (modoboa, CMDi) | Real, disclosed CVE | Reproduction |
| 3 | CVE-2026-23949 (jaraco.context, Path Traversal) | Real, disclosed CVE | Reproduction |
| 4 | CVE-2026-78683 (nltk, Deserialization) | Real, disclosed CVE | Reproduction |
| 5 | CVE-2026-54729 (dssrf, SSRF) | Real, disclosed CVE | Reproduction |
| 6 | CVE-2026-46492 (md-fileserver, XSS) | Real, disclosed CVE | Reproduction |
| 7 | CVE-2026-40246 (free5GC/udr, CWE-285) | Real, disclosed CVE | Reproduction (`free5gc_lab/`) |
| 8 | CVE-2026-40248 (free5GC/udr, CWE-285) | Real, disclosed CVE | **Real upstream source**, compile-verified against the actual repo |

Selection rule that was actually applied (not retrofitted): every entry
was independently verified against GitHub's advisory API or the GitHub
commit API before being run — not taken from search-result summaries.
See `reports/CVE_CATALOG.md`'s opening paragraph and
`docs/REACHABILITY.md`'s commit-hash citations for the verification each
entry actually got.

**Honest limitation carried forward, not smoothed over**: entries 1-7 are
reproductions built from the advisory's own description, not the named
package/repository compiled and run (`docs/SCOPE_AND_LIMITATIONS.md`,
Limitation 1). Entry 8 is the one case where the real source itself was
analyzed and patched. Any report table built from this protocol must
carry that distinction as a column, not flatten it away.

## 2. System configuration under test

One configuration, not several — this project does not run baseline
comparisons against fuzzing or static-analysis-only tools. That is a
deliberate scope decision (`docs/CRS_MAPPING.md`'s framing note), not an
omission to fill in later without discussion.

| Stage | What runs | Provenance |
|---|---|---|
| 1-2 | Advisory fetch + classification | Deterministic (API + CWE lookup / text heuristic) |
| 3 | Live probe | Real for SSRF only; static pattern-match for the other 5 classes |
| 3.5 | Exploit artifact generation | Template or LLM-generated (`_claude_available()` gates which) |
| 3.6 | Dynamic execution | Always real subprocess + real HTTP, every class |
| 3.7 | Self-improvement | Lesson-reuse (deterministic) → LLM-revision → built-in rule, in that order |
| 3.8 | Patch generation | LLM-generated, gated by two-check dynamic re-verification |
| `src/reachability/` | Reachability + patch (free5GC only) | AST-based (deterministic), rule-based patch, compile-verified |

## 3. Metrics — copy verbatim into any report table

- **DETECTED / DYNAMICALLY CONFIRMED**: `exploit_artifacts.dynamically_confirmed == true`
  in `reports/<CVE-ID>/report.json` — a real subprocess exit code from a
  real HTTP exchange (Stage 3.6), or a real compiled-harness run (Stage 3
  native-code memory safety probe). Never a static claim.
- **PLAUSIBLE patch**: `exploit_artifacts.patch_validated == true` —
  applies, the *original unmodified* exploit now fails against it, AND
  `/health` still returns 200 (`docs/SCOPE_AND_LIMITATIONS.md`,
  Limitation 3). This is the exact bar GLM's protocol calls "plausible";
  this project has never claimed anything stronger for the main pipeline.
- **CORRECT patch**: not currently measured by this pipeline. A plausible
  patch has not been checked against the *real* upstream fix's intent
  (no diff-similarity scoring, no second-reader adjudication exists here).
  If this distinction is added later, it is a new capability, not a
  relabeling of existing `patch_validated` results.
- **COMPILE-VERIFIED (free5GC only)**: `go build ./...` succeeds against
  the real, live-cloned upstream module with the patch applied
  (`src/reachability/verify_against_real_upstream.py`). Explicitly weaker
  than DETECTED or PLAUSIBLE — see Limitation 4. Never report this figure
  in the same column as dynamic confirmation results without a footnote.
- **SELF-IMPROVED**: `len(exploit_artifacts.refinement_history) > 0` —
  Stage 3.7 was invoked because the first attempt genuinely failed.

## 4. Provenance / contamination controls

Every LLM-dependent result in this catalog must record which of these it
is, per `docs/SCOPE_AND_LIMITATIONS.md` Limitation 6:

| Provenance tag | Meaning |
|---|---|
| `template` | Class-specific hand-authored template, no LLM call |
| `llm-stub` | LLM call was mocked/monkeypatched to test plumbing, not a live model |
| `llm-live` | A real model (via `claude` CLI or API) generated this, in this environment |
| `lesson-reuse` | A prior confirmed fix was replayed from `.pipeline_lessons.json`, no LLM call this run |

Current state of the catalog (accurate as of the freeze date below, not
aspirational): **no entry in this repository has `llm-live` provenance.**
This environment has neither the `claude` CLI nor an API key configured.
Every LLM-shaped result reported anywhere in this project is `llm-stub`
or `lesson-reuse`. State this explicitly in any report table — do not let
a stub result read as if a live model produced it.

## 5. Per-entry record

`reports/<CVE-ID>/report.json` already is this record — no new schema
needed. The fields that matter for this protocol:
`exploit_artifacts.{generated, executed, dynamically_confirmed,
refinement_history, patch_attempted, patch_validated}`, `analysis.{vulnerability_class, cwe}`,
`advisory.{cve_id, package_name}`. `src/reachability/`'s equivalent is
`reports/reachability/free5gc_case_study.json`.

## 6. Reporting rule

Report every entry, including the one that didn't confirm (SSRF,
`CVE-2026-54729`) and exactly why — a real network-routing limitation on
this development machine, not a pipeline defect (`reports/CVE_CATALOG.md`).
A benchmark table that quietly drops the one failure is not a benchmark,
it's a highlight reel.

## Change Log

- **[freeze pending — set the date here when you stop adding entries]**
  Catalog stands at 8 entries (6 main-pipeline CVEs + 2 free5GC CVEs)
  as of this document's creation. No entry has been removed or replaced
  since first added to `reports/CVE_CATALOG.md`.
