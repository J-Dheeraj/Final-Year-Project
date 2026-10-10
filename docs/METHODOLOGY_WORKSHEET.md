# Methodology Worksheet — COMPUTER SCIENCE / COMPUTER ENGINEERING

Filled from the project's actual methodology, audited against
`free5gc_full_deployment/FYP_Report_main_upgraded.tex` Chapter 3
("Methodology") and the project repository. Written in past
tense/passive voice as instructed.

---

## SECTION 1: PROJECT CONTEXT

### 1.1 Project Title

Agentic AI for Vulnerability Confirmation and Patch Validation in
Open-Source Software

### 1.2 Project Category

- [x] Software System / Application
- [ ] Machine Learning / AI
- [ ] Algorithm Design
- [ ] Data Analytics
- [ ] Other: ___________________________________________

*(The system was classed as Software System/Application, with a Data
Analytics component in its reachability-filtering and metrics stages
— not a standalone Data Analytics project, since no model was trained
and no statistical learning evaluation was performed.)*

---

## SECTION 2: METHODOLOGY OVERVIEW

### 2.1 Methodology Roadmap Paragraph

This project was carried out in **four** main stages. First, **the
existing CVE-driven exploit-confirmation pipeline (advisory intake,
vulnerability classification, exploit-artifact generation, dynamic
execution, self-improvement on failure, and patch generation with
regression validation) was extended and hardened against a catalogue
of six published CVEs spanning six vulnerability classes**. Next, **a
reachability-filtering engine, ported from an earlier standalone
prototype, was applied to a real, disclosed CVE in free5GC, producing
an AST-based call-graph reduction and a patch verified to compile
against the actual upstream dependency graph**. This was followed by
**the integration of ProvTrail's SARIF/AI-text export as an additional
advisory source, allowing the pipeline to be driven by statically
located JavaScript/TypeScript findings rather than only by NVD/GHSA
feed entries**. Finally, **the system was evaluated across multiple
rounds of live, locally hosted LLM verification, during which
implementation defects were identified, fixed, and re-verified, and
the pipeline's evidentiary claims were confirmed to hold under live
model generation, not only under stubbed responses**.

### 2.2 High-Level Workflow

1. Extend and harden the main exploit-confirmation pipeline against a six-CVE, six-class catalogue.
2. Port and apply the reachability-filtering engine to real, disclosed free5GC source.
3. Integrate ProvTrail's SARIF/AI-text export as a second advisory source.
4. Evaluate across successive live-model verification rounds, fixing defects surfaced by each round.

---

## SECTION 3: SYSTEM ARCHITECTURE

### 3.1 System Description

The proposed system consists of **two loosely coupled subsystems
sharing a common advisory-driven design philosophy: a main
exploit-confirmation pipeline (orchestrated by `cve_pipeline.py`, fed
by a poller watching NVD/GHSA/ProvTrail), and an independent
reachability-filtering engine (`src/reachability/`) that operates
directly on real upstream source rather than on advisory text. A
bridge module converts ProvTrail's SARIF output into pipeline-
consumable advisories, and two standalone dynamic-exploitation labs
provide locally hosted targets for live confirmation where a generic
reproduction would not suffice.**

### 3.2 Major System Components

| Component / Module | Function |
|---|---|
| `cve_pipeline.py` | Orchestrates advisory fetch, classification, artifact generation, dynamic execution, self-improvement, and patch generation/validation for a single CVE. |
| `cve_watcher.py` | Polls NVD, GHSA, and ProvTrail feeds and dispatches pipeline runs across parallel workers. |
| `provtrail_bridge.py` | Converts ProvTrail's SARIF/AI-text export into advisories the main pipeline can consume. |
| `src/reachability/` | Tree-sitter AST parsing, call-graph construction, breadth-first reachability filtering, adversarial triage, and rule-based/LLM patch generation on real upstream source. |
| `src/pipeline/patch.py` | Generates a candidate patch for a confirmed exploit and validates it via the (later corrected) acceptance criterion. |
| `src/metrics.py` | Aggregates confirmation rate, patch-acceptance rate, wall-clock time, and LLM call count. |
| `src/reachability/providers.py` | Provider abstraction layer: Claude CLI, direct Claude API gateway, OpenAI API, Codex CLI, and local Ollama backends behind one interface. |
| `free5gc_lab/`, `free5gc_full_deployment/` | Dependency-free and fuller Docker-based reproductions of the disclosed free5GC vulnerability, exploited and patched at runtime. |
| `ssrf_lab/` | A local FastAPI target providing genuine live-traffic confirmation for the SSRF vulnerability class. |
| `openemr_transfer_case/` | A Docker-based transfer case applying the same evidence-gated method to a real OpenEMR advisory in a second application domain. |

### 3.3 Architecture Diagram Check

- [x] System architecture diagram included (`figures/architecture.png`, plus interpreter-branch and model-backend supporting diagrams)
- [x] Data flow between modules explained (advisory intake → classification → artifact generation → dynamic execution → self-improvement → patch generation/validation; reachability track operates in parallel on real upstream source)

---

## SECTION 4: DATASET & DATA PREPROCESSING

### 4.1 Dataset Description

| Item | Description |
|---|---|
| Data source | NVD API v2, the GHSA feed, ProvTrail's SARIF/AI-text export; real upstream source for `free5gc/udr` (Go), `jaraco.context` (Python/PyPI), and OpenEMR (PHP) |
| Data size | Six-CVE main catalogue (one per vulnerability class) plus three real-upstream validation cases; ~86 KB / 102-function real free5GC source file; tens of models evaluated across five+ backend access methods |
| Data type | Advisory prose and structured CWE fields; source code (Go, Python, PHP); real HTTP request/response pairs; process exit codes and container logs |

### 4.2 Data Preprocessing Steps

1. Advisory text was parsed to extract the vulnerability class, affected package, and any code-diff snippet, with the advisory's own structured CWE field preferred over free-text keyword matching where present.
2. For the reachability track, the fetched Go source file was parsed with a tree-sitter grammar into an abstract syntax tree, from which function definitions and call edges were extracted into a directed call graph.
3. A stated list of real HTTP entry-point handlers was used as the seed set for breadth-first reachability traversal from that call graph.

---

## SECTION 5: ALGORITHMS / MODELS USED

### 5.1 Model / Algorithm Selection

| Model / Algorithm | Purpose |
|---|---|
| Claude CLI / pydantic-ai agent backend | Advisory analysis, exploit-artifact generation, patch generation (hosted CLI session) |
| Direct Claude API gateway (`AIxTechGatewayProvider`) | Same roles, via a bearer-token-authenticated API call rather than a CLI session |
| OpenAI API | Comparative patch-generation and bypass-probe backend across 23 model identities |
| Codex CLI | Comparative patch-generation and bypass-probe backend across 18 model identities, read-only ephemeral session |
| Ollama-served local models (`qwen2.5-coder:7b`, `:1.5b`, `mistral:7b`, and others) | Live-model verification of exploit-artifact generation and self-improvement revision at zero API cost |
| Rule-based heuristics (e.g. `find_missing_return_after_response`) | Deterministic, offline fallback patch generation requiring no LLM call |
| Tree-sitter AST parsing + breadth-first search | Reachability filtering: call-graph construction and traversal from stated entry points |

### 5.2 Key Parameters and Settings

| Parameter | Value | Reason |
|---|---|---|
| Self-improvement iteration bound | 3 | Prevents unbounded LLM cost or looping past a signature with no known fix |
| Feed poll interval | 60 minutes | Balances advisory freshness against feed rate limits |
| Parallel workers | 2 | Bounds concurrent LLM/API load while allowing cross-CVE parallelism |
| Reachability entry-point set | 4 handlers | Reflects the real, externally reachable surface of the analysed free5GC module |
| Sampling (Ollama multi-model comparison) | temperature = 0, fixed seed | Pins sampling for a reproducible, deterministic-in-intent comparison |
| Sampling (Claude CLI / Claude API / Codex CLI) | not exposed | None of these interfaces expose a temperature/seed control, an acknowledged asymmetry with the Ollama comparison |

---

## SECTION 6: IMPLEMENTATION DETAILS

### 6.1 Programming Environment

| Item | Details |
|---|---|
| Programming language | Python (pipeline orchestration, pydantic data models, reachability engine); Go (free5GC target and real upstream module); PHP (OpenEMR target) |
| Libraries / frameworks | pydantic-ai, tree-sitter, Flask, FastAPI, Go's `net/http`, PHP's `mysqli` extension |
| Hardware (CPU/GPU) | Local workstation; Ollama-served models run on locally available CPU/GPU resources, no dedicated accelerator required |

### 6.2 Implementation Procedure

1. The pre-existing exploit-confirmation pipeline was extended with real dynamic execution, replacing an earlier design where generated artifacts were written to disk but never run.
2. Self-improvement was added as a bounded retry loop consulting, in order, a persisted-lesson store, an LLM-generated revision, and a rule-based fallback.
3. Patch generation and validation was implemented next, gated on the original exploit failing against the patched target and the target's health check continuing to pass — later corrected into a four-outcome verdict after a false acceptance was found by trace-level inspection.
4. The reachability engine was ported from an earlier standalone prototype and applied to real free5GC source; the ProvTrail bridge and the free5GC/OpenEMR dynamic-exploitation labs were added as independent, loosely coupled extensions following the same dual vulnerable/patched-mode convention.

---

## SECTION 7: TESTING & VALIDATION

### 7.1 Testing Strategy

The system was tested by **executing every generated exploit artifact
as a real subprocess against a real, locally deployed target and
recording its actual exit code or HTTP response, rather than treating
generation as evidence of exploitability by itself**. Patch validation
re-ran the original exploit against the patched target and
independently checked a separate health endpoint and, for the
strongest-evidence cases, the exact expected content of a benign
request.

- [ ] Training/testing split — **not applicable**: this is not a statistical learning system being evaluated for generalisation, so no train/test split or k-fold cross-validation was used.
- [x] Validation method — repeated verification rounds across the CVE catalogue (five successive rounds for the main pipeline), with each round's failures traced to a specific, named cause before the next round was attempted.
- [x] Number of runs / folds — 5 rounds (main catalogue, Ollama); 48 runs (8-model Ollama comparison); 36 runs (6-model Claude CLI comparison); 23/18/10 model identities respectively for the later OpenAI/Codex/Claude-API comparisons; 3 runs/model for the targeted repeatability checks.

---

## SECTION 8: EVALUATION METRICS

### 8.1 Performance Metrics

| Metric | What It Measures |
|---|---|
| Confirmation rate | Proportion of catalogued CVEs whose described bug pattern was dynamically confirmed exploitable |
| Patch-acceptance rate / `patch_verdict` | Proportion of confirmed exploits for which a generated patch was accepted — the corrected four-outcome verdict (`confirmed_fix` / `regression_broke_route` / `inconclusive_crash` / `not_blocked`) supersedes the original two-check flag as the headline metric |
| Reachability reduction | Percentage reduction in functions requiring analysis after BFS filtering (96.1%, 102 reduced to 4) |
| Wall-clock time per CVE / per call | Runtime cost of a full pipeline run or a single model call, as a practicality indicator |
| LLM call count, duration, and recorded cost | Real, per-call figures read directly from each backend's own token/duration/cost fields, never estimated except where a backend genuinely provides no cost figure at all |

### 8.2 Metric Justification

These metrics were selected **to mirror the vocabulary used by DARPA's
AI Cyber Challenge and the OpenSSF's OSS-CRS project to report
cyber-reasoning-system results — bugs confirmed against bugs attempted,
proof-of-vulnerability confirmation rate, and patch-acceptance rate —
so that this project's results can be read against the same benchmark
context other agentic security-automation systems are reported
against, rather than against an ad hoc scale.**

---

## SECTION 9: LIMITATIONS & ASSUMPTIONS (METHOD-RELATED)

The methodology assumes that **a faithful reproduction of an
advisory's described bug pattern is representative evidence of that
bug class, even where the reproduction target is a minimal stand-in
rather than the actual named upstream package**. For five of the six
main-catalogue CVEs, the exploited target is a generated reproduction,
not the real installed package; a confirmed exploit therefore
demonstrates the described pattern is exploitable as reproduced, not
that the real package is exploitable as actually installed and run.
This limitation is independently closed for three cases evaluated
against real, unmodified upstream software instead of a reproduction
(`jaraco.context`, free5GC/udr, and OpenEMR), but these remain three
cases out of the full catalogue, not a systematic replacement for the
reproduction-based approach. A patch accepted by the original
two-check criterion was also found, by direct trace inspection, not to
reliably distinguish a deliberate security fix from an unrelated crash
bug in the generated patch — a genuine capability gap in the
validation harness, discovered during evaluation and corrected into a
stronger (though still not fully complete) verdict.

---

## SECTION 10: FINAL QUALITY CHECK

| Checkpoint | Yes | No |
|---|---|---|
| All algorithms and parameters are specified | [x] | [ ] |
| Implementation steps are reproducible | [x] | [ ] |
| Technical terms are used correctly | [x] | [ ] |

---

## Audit note: does Chapter 3 of the thesis already cover this worksheet?

Yes, substantively, in every section — Chapter 3 ("Methodology")
already contains content matching each worksheet section almost
one-to-one (its own opening paragraph uses nearly the same "carried
out in four main stages... First... Next... This was followed by...
Finally..." wording reproduced in Section 2.1 above). Two differences
are structural, not substantive gaps:

1. **Order and form.** The thesis is written as flowing prose
   organised into its own sections (System Architecture, Data Sources,
   Algorithms, Implementation, Testing, Evaluation Metrics,
   Limitations), not as this worksheet's numbered-section-with-
   checkboxes format. Every piece of required content is present
   somewhere in the chapter; this worksheet just re-surfaces it in the
   worksheet's own structure for a separate submission.
2. **Later work.** Section 5.1 above includes the direct Claude API
   gateway, OpenAI API, and Codex CLI backends, and Section 3.2 above
   includes the OpenEMR transfer case and `providers.py`. These were
   added to the project after most of Chapter 3's narrative was
   written; the thesis itself now cross-references them via the Scope
   section and the "Final evidence freeze" subsection (added in the
   most recent revision) rather than describing them inline
   throughout Chapter 3's prose.

No section of this worksheet surfaced a requirement the thesis
doesn't already satisfy somewhere.
