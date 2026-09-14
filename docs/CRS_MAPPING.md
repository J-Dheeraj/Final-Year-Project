# How this pipeline maps onto AIxCC / OSS-CRS concepts

**Framing note**: this project's original pitch ("fuzzing LLMs to secure
OSS") has been deliberately dropped, confirmed OK with the professor.
Nothing in this repo does actual fuzzing (coverage-guided input mutation),
and claiming otherwise wouldn't survive a viva question. The honest,
current framing is two complementary pieces: **LLM-assisted exploit
confirmation and patch validation for known CVEs** (`cve_pipeline.py`,
the bulk of this document) plus **real reachability-filtered static
analysis on real upstream source** (`src/reachability/`, see
`docs/REACHABILITY.md`) — ported from this FYP's own earlier prototype,
reachcrs, rather than invented from scratch.

This project is a CVE-driven exploit-generation-and-validation pipeline, not a
full DARPA AIxCC-style cyber reasoning system (CRS) — it never discovers an
*unknown* bug; every run starts from an already-published CVE/GHSA ID. But its
stages line up closely enough with the AIxCC/OSS-CRS vocabulary that framing
it that way is useful, both for the FYP report and for deciding what a "next
step" toward a real CRS would look like. This document makes that mapping
explicit, and is equally explicit about where the analogy breaks down.

Background: DARPA's AI Cyber Challenge (2023–2025) produced seven open-sourced
CRSs (Atlantis/Team Atlanta — winner, Buttercup/Trail of Bits, RoboDuck/Theori,
Fuzzing Brain, Bug Buster, Artiphishell/Shellphish, Lacrosse). OSS-CRS
(OpenSSF) is a follow-on project that "liberates" those CRSs into a common
runtime so they can be pointed at real OSS-Fuzz projects instead of the
competition's synthetic challenge problems.

## Lifecycle mapping

OSS-CRS structures every CRS run into three phases: `prepare` (CRS-specific
setup), `build-target` (compile the target, usually via the OSS-Fuzz build
format), and `run` (the actual analysis campaign). This pipeline's stages
collapse onto that same three-phase shape:

| OSS-CRS phase | This pipeline | Notes |
|---|---|---|
| `prepare` | Stage 1 (Advisory Fetch) | Instead of preparing a fuzzer's corpus/config, this pulls the CVE/GHSA advisory itself — the "ground truth" a real CRS would instead have to *discover*. |
| `build-target` | Stage 3.5 (Exploit Artifact Generation) | Instead of compiling the real upstream project via an OSS-Fuzz `build.sh`, this generates a minimal Flask stand-in (`target_app.py`) that reproduces the vulnerable code pattern. This is the single biggest structural gap vs. a real CRS — see "What's not real" below. |
| `run` | Stages 2, 3, 3.6, 3.7 (Analysis, Probe, Execution, Self-improvement) | Classification (2) plus dynamic confirmation (3.6) plus the reflect-and-retry loop (3.7) together are this pipeline's version of a CRS's fuzz-triage-patch campaign loop. |

## Component mapping

| OSS-CRS / AIxCC concept | This pipeline's equivalent | Real, partial, or absent |
|---|---|---|
| `libCRS` artifact interface (submit build output, register shared dirs, exchange PoVs/patches/seeds) | `ExploitArtifacts` pydantic model + `reports/<CVE-ID>/` per-CVE directory | Partial — the artifact *shape* (PoC, target, execution log, refinement history) is real and structured, but there's no sidecar/filesystem exchange protocol between independent agents; it's all one process. |
| Resource-aware LLM proxy (LiteLLM, model aliasing, budget enforcement) | `_call_claude()` / `_claude_available()` | Absent as a budget concept — every LLM call is unmetered. `src/metrics.py` (added this session) counts calls and estimates cost after the fact; it doesn't enforce a budget during the run. |
| Fuzzing engine (AFL++/libFuzzer driving a harness) | Nothing | Absent. Stage 3 (native code)'s memory-safety probe compiles and runs a single generated harness once — it's a PoV *confirmation* step, not a fuzz *campaign*. No coverage-guided input mutation exists anywhere in this pipeline. |
| PoV (proof of vulnerability) | `dynamically_confirmed` + `execution_log` on `ExploitArtifacts` | Real — a genuine subprocess exit code from a genuine HTTP exchange or compiled-harness run, not a static claim. This is the pipeline's strongest CRS-alignment point. |
| Patch generation + `apply-patch-build`/`run-pov`/`run-test` validation | Stage 3.8 (`src/pipeline/patch.py`, added this session) | Partial/new — see "Patch generation" below. |
| Multi-agent orchestration (Fuzzing Brain, Bug Buster) | Single sequential pipeline, one CVE at a time | Absent. `cve_watcher.py` parallelizes *across* CVEs (2 workers by default) but each CVE's own pipeline run is strictly sequential, not a team of cooperating agents. |
| Reachability-filtered analysis scope (reduce what an LLM must look at) | `src/reachability/` (ported from reachcrs) | Real — AST-based call graph + BFS from entry points, 96.1% reduction (102 -> 4 functions) on a real free5GC source file, not a regex heuristic. See `docs/REACHABILITY.md`. |

## What's genuinely real (evidence, not description)

- **Dynamic confirmation (Stage 3.6/3.7)**: every `dynamically_confirmed: true`
  in `reports/*/report.json` is a real subprocess exit code from a real PoC
  run against a real (if minimal) Flask target — see `reports/CVE_CATALOG.md`
  for the worked examples, including the one case (SSRF) that honestly
  reports `false` because of a real environment limitation rather than
  papering over it.
- **Self-improvement (Stage 3.7)**: a fix learned on one CVE (CMDi/modoboa)
  was reused — not re-discovered — on an independent second run, proven via
  `source=lesson` in the report rather than `source=builtin`.

## What's not real (the honest gap vs. a CRS)

- **No discovery in the main CVE pipeline.** Every `cve_pipeline.py` run
  still starts from a CVE ID a human or feed already knows about. This is
  now *partially* offset, not closed, by `src/reachability/`: it does
  real static reachability analysis on real upstream source (see
  `docs/REACHABILITY.md`) — narrowing "what to look at" is a real,
  separate capability a CRS needs, distinct from but adjacent to full
  discovery. It still starts from a human-chosen entry point list, not
  from nothing.
- **Targets are stand-ins, not upstream code — except for the
  reachability module's free5GC case.** `target_app.py` (main pipeline)
  is still a minimal Flask app that *reproduces the vulnerability
  pattern*, not the actual upstream project compiled and run. But
  `src/reachability/` now genuinely operates on real upstream source
  (free5GC/udr, fetched verbatim, both parsed and — separately —
  compile-verified against a live clone of the real module) for one case.
  The six main-pipeline CVEs (litellm, modoboa, jaraco.context, nltk,
  dssrf, md-fileserver) are still stand-ins; this gap is closed for one
  case, not generalized.
- **No fuzzing engine, and this project no longer claims to need one** —
  see the framing note at the top of this document. Nothing here does
  coverage-guided mutation, and that's now a deliberate scope decision,
  not an unstated gap.

## Patch generation (Stage 3.8)

`src/pipeline/patch.py` adds the missing "confirm exploit → generate patch →
validate patch" loop, closing the gap the research report identified as the
project's single biggest missing CRS capability (LLMPatch/PATCH-style patch
generation, OSS-CRS's `apply-patch-build`/`run-pov`/`run-test` cycle). Given a
confirmed exploit, it asks an LLM to patch `target_app.py`'s vulnerable
handler, then validates the patch two ways before trusting it: (1) re-running
the *original* exploit against the patched target and requiring it to now
FAIL (regression: the vuln is actually closed), and (2) re-running the
target's own `/health` check to confirm the patch didn't just break the app
outright. A patch that doesn't pass both checks is discarded, not reported as
a success — same evidence-gated philosophy as Stage 3.7. See
`reports/CVE_CATALOG.md` for which of the confirmed CVEs got a validated
patch and which didn't (and why), honestly labeled per case.

## Metrics (`src/metrics.py`)

A small, real (not aspirational) metrics harness scores the existing catalog
the way AIxCC/OSS-CRS report results: bugs confirmed / bugs attempted,
PoV-confirmation rate, patch-validation rate, wall-clock time per CVE, and an
LLM-call count as a crude budget proxy (real cost tracking needs a live
provider this environment doesn't have — see `reports/METRICS.md`, generated
by running `python -m src.metrics`).

## free5GC (network-OSS target)

See `docs/FREE5GC_LAB.md` for the one concrete free5GC-adjacent lab this
session added, and an honest account of what it does and doesn't prove.

## Bottom line for the FYP framing

This is fairly and accurately described as **two complementary CRS
components**, not a full CRS in the AIxCC/OSS-CRS sense (which is
fundamentally a *discovery* system):

1. The "confirm and patch a known bug" back-half of a real CRS's loop
   (`cve_pipeline.py`) — single-CVE-at-a-time, evidence-gated exploit
   confirmation and patch validation.
2. A real, AST-based "narrow what to look at" front-half capability
   (`src/reachability/`) — reachability filtering on real upstream source,
   proven against a real, disclosed free5GC CVE with real compile
   verification against the actual project's dependency graph.

That's not a weakness to hide; it's the actual, defensible scope of what
a one-person FYP can build and verify in the time available, and it's
exactly the framing OSS-CRS itself uses when it talks about "liberating"
CRS *components* for reuse rather than requiring every user to
reimplement a whole CRS from scratch. It is also, deliberately, no longer
described as "fuzzing" — see the framing note at the top of this document.
