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

**Pre-registered for the future live-LLM classification/generation
session** (frozen here, before that session runs, so template-mode and
live-mode results are scored on the same yardstick): classification
results are scored on **both** class-level and exact-CWE-level match,
reported as separate rows — never collapse to one "accuracy" number.
This mirrors §7's 3-metric table below and must not be redefined once
live results start coming in.

**Pre-registered for the live-LLM session itself** (not just the metrics
it will produce):

- **Exit criterion**: the session succeeds if at least one CVE completes
  the full chain live-generated PoC -> dynamically confirmed ->
  patch_validated. Not "all six work" — one real, complete, `llm-live`
  result is the bar.
- **Failure handling — a real risk, confirmed in the current code, not
  hypothetical**: `generate_exploit_artifacts()` currently does
  `if not poc_code or not target_code: <fall back to template>` whenever
  a live call returns unparseable output — with no distinct signal that
  a live attempt was made and failed. Once a live adapter exists, this
  exact branch would silently relabel a failed `llm-live` attempt as
  `template`, corrupting the provenance table. Rule: **template fallback
  is not allowed to happen silently during the live-LLM session.** A
  parse failure must be recorded as an `llm-live` attempt that failed,
  not quietly downgraded to `template` — this needs an actual code
  change (a distinct failure state) before the session runs, not just a
  protocol note. Concretely: add `generation_outcome` (values
  `llm_live_success` / `llm_live_failed` / `template`) to
  `ExploitArtifacts` and surface it through `compile_report()` into the
  final report — not just an internal log line. This makes the live-
  generation failure rate itself a measured, report-visible result
  ("attempted live on N CVEs, succeeded on M") instead of an invisible
  footnote, which is exactly the kind of thing an examiner asks about.
- **Refinement, not fallback, for execution failures**: a live-generated
  PoC that compiles/parses but fails execution goes through the existing
  `refine_and_reexecute` (Stage 3.7) path as normal; only a failure that
  survives `max_iterations` counts as a failure for this exit criterion.
- **Adapter integration failure is a result, not a blocker**: if the
  Ollama/provider adapter itself fails to integrate, the session ends and
  that failure is reported plainly — not worked around by improvising a
  different backend mid-session.

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

## 7. Classification ablation (S2, LLM-independent — already run)

Stage 2 (`analyze_vulnerability`) has a genuine, already-demonstrated
dependence on advisory structure, distinct from the generation-stage
ablation in §3-4 (which is not currently testable without a live LLM —
see §4). This one requires no new infrastructure: it's a property of
`_classify_from_cwe()` vs `_classify_from_text()`, both deterministic.

**Conditions**: S2-FULL (prose + structured CWE + CVSS + references),
S2-PROSE (prose description only), S2-ID (CVE ID only — measures whether
a classifier could succeed on memorization/lookup alone, with no
advisory content at all). Metric: classification accuracy against
ground-truth CWE/class, over the 6-entry main catalog. n=6 — report
counts, not a generalization claim.

**Full 6-CVE result** (2026-09-15, run by calling `_classify_from_text()`
directly against each CVE's stored `advisory.raw_description`, and
`_classify_from_cwe()` against the ground-truth CWE already on record —
not estimated, not hand-simulated):

| CVE | Ground truth (S2-FULL) | S2-PROSE result | Class match | CWE match |
|---|---|---|---|---|
| CVE-2026-42208 (litellm) | SQL Injection / CWE-89 | **UNKNOWN / N/A** | **No** | **No** |
| CVE-2026-27602 (modoboa) | OS Command Injection / CWE-78 | OS Command Injection / CWE-78 | Yes | Yes |
| CVE-2026-23949 (jaraco.context) | Path Traversal / CWE-22 | Path Traversal / CWE-22 | Yes | Yes |
| CVE-2026-78683 (nltk) | Insecure Deserialization / CWE-502 | Insecure Deserialization / CWE-502 | Yes | Yes |
| CVE-2026-54729 (dssrf) | SSRF / CWE-918 | SSRF / CWE-918 | Yes | Yes |
| CVE-2026-46492 (md-fileserver) | XSS / CWE-80 | XSS / **CWE-79** | Yes | **No** |

**Three metrics, not one** — splitting "match" into class-level and
exact-CWE-level pre-empts the obvious examiner question ("CWE-79 and
CWE-80 are both XSS — is that really a failure?"):

| Metric | S2-PROSE | S2-FULL (structured CWE) |
|---|---|---|
| Class-level match | 5/6 | 6/6 |
| Exact-CWE match | 4/6 | 6/6 |
| Full miss (UNKNOWN) | 1/6 | 0/6 |

At the class level, prose matching is mostly fine (5/6). The real
failure mode is narrower and sharper: **a hardcoded family→representative
CWE mapping can't reproduce an analyst-assigned subtype** — prose
matching always returns CWE-79 for any "cross-site scripting" hit,
regardless of which XSS-family CWE actually applies. That's the
generalizable claim, not "keyword matching is unreliable."

**S2-ID** (CVE ID only, no advisory content at all — the functions
received nothing but the identifier, with no advisory fields populated)
was also run directly: `_classify_from_text("")` and
`_classify_from_cwe([])` both return no classification for every entry.
Precise claim: this rules out **identifier-based special-casing** in
either classifier (no hardcoded `CVE-2026-42208 -> CWE-89` shortcut
exists in the code) — it does not, and cannot, speak to model
memorization, since neither classifier is a model. S2-ID becomes
informative for memorization only once a live LLM is wired in
(`docs/PROJECT_STATUS.md`).

**Validity caveat — circularity, and a real mitigation for it**: the
ground-truth CWE used above is NVD's own structured field, so on its own
this ablation only supports "structured beats prose within NVD's data,"
not "NVD's CWE assignments are correct." Partial, real mitigation run
2026-09-15: cross-checked GitHub's independent advisory database
(`api.github.com/advisories?cve_id=<ID>`, unauthenticated REST, no
GITHUB_TOKEN needed) against NVD's CWE for all 6 entries:

| CVE | NVD CWE | GHSA CWE(s) |
|---|---|---|
| CVE-2026-42208 | CWE-89 | CWE-89 |
| CVE-2026-27602 | CWE-78 | CWE-78 |
| CVE-2026-23949 | CWE-22 | CWE-22 |
| CVE-2026-78683 | CWE-502 | CWE-502 |
| CVE-2026-54729 | CWE-918 | CWE-918 |
| CVE-2026-46492 | CWE-80 | CWE-80, CWE-87 |

CVE-2026-46492 is the one case where GHSA lists an *additional* CWE
(CWE-87) alongside the matching CWE-80, not a disagreement.

**This result supports a narrower claim than "cross-check mitigates
circularity" — state it precisely, at two levels:**

- **Pipeline-level (supported)**: the structured CWE signal is
  consistent across the two databases the ingestion stage can consult.
  The prose-vs-structured gap is not an artifact of one database's
  annotation idiosyncrasies — the pipeline gets the same signal
  regardless of source.
- **Epistemic-level (not established)**: agreement is *not* independent
  replication of the underlying vulnerability analysis. GitHub operates
  as a CNA, and advisories are routinely shared or ingested between
  databases — for CNA-authored records, NVD-GHSA agreement may hold
  partly *by construction*, not by two analysts independently arriving
  at the same conclusion. "NVD's assignments are correct" stays outside
  this study's scope, exactly as before the cross-check.

Report-ready sentence for the report's own methodology/limitations
section:

> Ground truth was taken from NVD's structured field; a cross-check
> against GitHub Security Advisories found CWE agreement for all six
> records (one record lists an additional CWE alongside NVD's),
> indicating the structured signal is consistent across both databases
> the ingestion stage consults. Because advisories are commonly shared
> or ingested between databases, agreement does not constitute
> independent replication of the underlying analysis, and the
> correctness of NVD's assignments remains outside this study's scope.

**Method provenance**, recorded so "why two different GitHub APIs?"
isn't a surprise at examination: the pipeline's own GHSA resolution
(`_resolve_ghsa_from_cve()`) uses GitHub's GraphQL API, which requires a
`GITHUB_TOKEN` this environment doesn't have configured — confirmed by
that path returning `null` for every catalog entry's `ghsa_id`. The
cross-check above used GitHub's separate REST `/advisories` endpoint
directly, which works unauthenticated for public records; it is not the
pipeline's own code path, run ad hoc for this analysis only.

**Multi-CWE scoring — pre-registered now, before the live-LLM session**:
CVE-2026-46492's GHSA record shows ground truth can be set-valued. The
frozen scoring rule: NVD's single CWE value remains the scoring ground
truth for exact-CWE match (nothing in the current catalog requires
set-valued scoring, and it was already frozen before this was noticed);
GHSA agreement is reported as a validity check, never used for scoring.
Contingency, pre-committed in case a future catalog entry's ground truth
is genuinely set-valued: exact match := prediction is a member of the
truth set, not equality against a single value.

**Downstream consequence of each failure mode**, so the finding is
concrete rather than academic: an UNKNOWN class-level miss cascades into
wrong probe selection in Stage 3 and the generic/`NotImplementedError`
template in Stage 3.5 (both are keyed on `vuln_class`); a wrong-CWE-
subtype miss does not cascade the same way — template selection is
class-keyed, not CWE-keyed, so the generated exploit is unaffected, only
the recorded `analysis.cwe` report field is wrong.

**Result and framing for the report**: 1/6 class-level failures, 2/6
exact-CWE mismatches, n=6 — report as counts, not a generalization the
sample can't support. The mechanism worth one sentence in the report:
NVD's structured field encodes an analyst's subtype judgment that a
regex can only re-derive as accurately as someone hand-encoded its
family→representative mapping; this ablation is evidence that the
pipeline's existing precedence rule (prefer structured CWE over prose,
`_classify_from_cwe()` before `_classify_from_text()`) was the right
design call, not just an arbitrary implementation choice.

**Deliberately not fixed**: the CWE-79 hardcode that causes the
CVE-2026-46492 mismatch is left as-is. Patching the classifier after
already running and reporting this ablation would turn a measurement
into a moving target. If pursued later, the fix is family-tolerant CWE
matching (accept any member of a CWE family, e.g. the real XSS family
around CWE-79 for that class) — logged as an optional future item in
`docs/PROJECT_STATUS.md`, pulling the actual child CWE sets from the
official CWE site at write-up time rather than from memory.

## Change Log

- **[freeze pending — set the date here when you stop adding entries]**
  Catalog stands at 8 entries (6 main-pipeline CVEs + 2 free5GC CVEs)
  as of this document's creation. No entry has been removed or replaced
  since first added to `reports/CVE_CATALOG.md`.
