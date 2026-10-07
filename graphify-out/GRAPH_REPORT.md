# Graph Report - docs  (2026-10-07)

## Corpus Check
- 38 files · ~60,326 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 249 nodes · 290 edges · 21 communities (14 shown, 7 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 29 edges (avg confidence: 0.75)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Rejected CRS Redesign Proposal|Rejected CRS Redesign Proposal]]
- [[_COMMUNITY_OpenEMR Transfer Case Setup|OpenEMR Transfer Case Setup]]
- [[_COMMUNITY_free5GC Claude Patch Sweeps|free5GC Claude Patch Sweeps]]
- [[_COMMUNITY_Memorization & Variance Controls|Memorization & Variance Controls]]
- [[_COMMUNITY_Methodology Pitfalls Record|Methodology Pitfalls Record]]
- [[_COMMUNITY_Frozen CVE Catalog|Frozen CVE Catalog]]
- [[_COMMUNITY_XSS Oracle Bug & Classifier Fix|XSS Oracle Bug & Classifier Fix]]
- [[_COMMUNITY_OpenEMR LLM Patch Bugs|OpenEMR LLM Patch Bugs]]
- [[_COMMUNITY_Scope and Limitations|Scope and Limitations]]
- [[_COMMUNITY_Repeated Patch-Gen Evidence Ledger|Repeated Patch-Gen Evidence Ledger]]
- [[_COMMUNITY_free5GC Full-CRUD Bypass Probe|free5GC Full-CRUD Bypass Probe]]
- [[_COMMUNITY_free5GC LLM Patch Scoping|free5GC LLM Patch Scoping]]
- [[_COMMUNITY_Benchmark Metrics Definitions|Benchmark Metrics Definitions]]
- [[_COMMUNITY_Main-Catalogue Bypass Probe|Main-Catalogue Bypass Probe]]
- [[_COMMUNITY_CWE Classification Ablation|CWE Classification Ablation]]
- [[_COMMUNITY_Live Model Backend Selection|Live Model Backend Selection]]
- [[_COMMUNITY_free5GC Ollama Bypass Attempts|free5GC Ollama Bypass Attempts]]
- [[_COMMUNITY_OAuth2 Scope Exclusion|OAuth2 Scope Exclusion]]
- [[_COMMUNITY_Claude Code Comparison Protocol|Claude Code Comparison Protocol]]
- [[_COMMUNITY_Claude CLI Real-Cost Note|Claude CLI Real-Cost Note]]
- [[_COMMUNITY_Bypass Probe Sweep Script|Bypass Probe Sweep Script]]

## God Nodes (most connected - your core abstractions)
1. `Methodology Pitfalls Record` - 18 edges
2. `Defense Prep â€” Prepared Q&A` - 13 edges
3. `Frozen CVE Catalog (8 entries)` - 10 edges
4. `Results Summary Index` - 10 edges
5. `CRS Mapping (AIxCC / OSS-CRS)` - 9 edges
6. `free5GC Memorization Control Results` - 9 edges
7. `free5GC LLM-generated Patch Results (Level 2, complete)` - 8 edges
8. `free5GC Runtime Validation Plan (Phase 2)` - 8 edges
9. `OpenEMR LLM Patch-generation Results` - 8 edges
10. `OpenEMR Healthcare Transfer Case Results` - 8 edges

## Surprising Connections (you probably didn't know these)
- `NO_PAID_BACKEND import-order bug in OpenEMR patch-gen script` --semantically_similar_to--> `Methodology Pitfalls Record`  [INFERRED] [semantically similar]
  docs/OPENEMR_LLM_PATCH_RESULTS.md → docs/METHODOLOGY_PITFALLS.md
- `Rationale: Codex explicitly out of scope, gets its own separate comparison` --semantically_similar_to--> `free5GC Codex CLI Model Sweep (7 Oct 2026)`  [INFERRED] [semantically similar]
  docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md → docs/FREE5GC_CODEX_SWEEP_2026-10-07.md
- `Missing NO_PAID_BACKEND guard in reachability providers` --semantically_similar_to--> `free5GC Runtime Validation Plan (Phase 2)`  [INFERRED] [semantically similar]
  docs/FREE5GC_LLM_PATCH_SCOPE.md → docs/FREE5GC_RUNTIME_VALIDATION_PLAN.md
- `0/7-0/5 genuine bypasses; real fix held across Go and PHP` --semantically_similar_to--> `free5GC OAuth2 Enforcement Results`  [INFERRED] [semantically similar]
  docs/OPENEMR_BYPASS_PROBE_RESULTS.md → docs/FREE5GC_OAUTH2_ENFORCEMENT_RESULTS.md
- `Step 1: corrected patch validator (patch_exploit_blocked/function_preserved/verdict)` --semantically_similar_to--> `Rationale: compile-only validation is insufficient (leak still open)`  [INFERRED] [semantically similar]
  docs/SESSION_2026-09-25_MULTI_AGENT_COMPARISON.md → docs/FREE5GC_PATCH_REPEAT_RESULTS.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **free5GC evidence-tier progression: lab -> reachability compile-verify -> full deployment runtime-confirm** — free5gc_lab_doc, free5gc_llm_patch_results_doc, free5gc_full_deployment_results_doc [INFERRED 0.80]
- **Multi-backend free5GC patch/bypass sweep family (Ollama, Claude, Codex) sharing same deployment+validator** — free5gc_model_sweep_doc, free5gc_claude_sweep_doc, free5gc_codex_sweep_doc, free5gc_bypass_probe_doc, free5gc_claude_bypass_probe_doc [INFERRED 0.85]
- **Honest-gap / no-highlight-reel reporting discipline across benchmark, bypass-probe, and defense-prep docs** — benchmark_protocol_doc, catalog_bypass_probe_doc, defense_prep_doc, crs_mapping_honest_gap [INFERRED 0.75]
- **Bypass-probe classifier false-positive bug fixed across three variants** — methodpitfalls_original_classifier_bug, multirunvar_query_string_bug, multiturn_third_classifier_bug, methodpitfalls_live_double_fetch [EXTRACTED 0.90]
- **free5GC CVE-2026-40248 evidence tier progression: reachability -> compile -> runtime -> OAuth2 -> patch-repeat** — reachability_free5gc_case_study, reachability_verify_upstream, runtimeplan_result, oauth2_conclusion, patchrepeat_results [EXTRACTED 0.85]
- **OpenEMR LLM patch-generation failure-mode taxonomy** — openemr_isset_bug, openemr_or_and_bug, openemr_inverted_logic_bug, openemr_patch_doc [EXTRACTED 0.85]

## Communities (21 total, 7 thin omitted)

### Community 0 - "Rejected CRS Redesign Proposal"
Cohesion: 0.07
Nodes (33): Benchmark Protocol, Proposed aegis/detect.py + aegis/verify.py + C driver harness, Condition to revisit: bounded smoke test on known catalog bug before touching thesis chapters, Considered Directions (not adopted), execute_exploit_artifacts() (Stage 3.6) â€” single crafted input replay pattern, GLM's 'detect -> demonstrate -> repair' pure-LLM redesign proposal, Rationale for rejecting GLM proposal: unverified core assumption, internal inconsistency, logical gap, disconnected system, real cost no urgency, OSS-CRS Component Mapping Table (+25 more)

### Community 1 - "OpenEMR Transfer Case Setup"
Cohesion: 0.09
Nodes (26): Missing NO_PAID_BACKEND guard in reachability providers, Verdict: confirmed_fix for GHSA-q366-cv5v-83w8, Correction: Docker Desktop working again, recommend official Compose route, Rationale: choose GHSA-q366 as safest first target over RCE candidates, GHSA-q366-cv5v-83w8 (unauthenticated admin.php information disclosure), MariaDB bootstrap-instance readiness race bug, Rationale: minimal native PHP+MariaDB deps comparable to free5GC MongoDB substitution, PHP built-in server TCP-accept-before-ready race bug (+18 more)

### Community 2 - "free5GC Claude Patch Sweeps"
Cohesion: 0.09
Nodes (25): free5GC All-installed-Ollama Sweep (6 Oct 2026), New per-call accounting instrumentation (tokens, durations) added to Ollama sweeps, Result: 5/8 models runtime-confirmed, free5GC LLM Patch: Claude Model Sweep (paid backend), Cost checkpoint: $5.49 smoke test flagged to user before full pipeline run, free5GC LLM Patch: Extended Claude Model Sweep, claude-opus-4-8: transient go build timeout, unrelated to model, retried cleanly, Results: 4/5 confirmed_fix_all_four_handlers (+17 more)

### Community 3 - "Memorization & Variance Controls"
Cohesion: 0.12
Nodes (25): Memorization limitation (public fix commit), run_memorization_control_baseline.py (matched real-CVE arm), free5GC Memorization Control Results, HandleCreateAuthenticationStatus (synthetic-bug host function), free5GC Multi-run Variance Results, sweep.py --runs N flag, 0/6-0/7 genuine bypasses across rounds/backends, free5GC Multi-turn Bypass-probe Results (+17 more)

### Community 4 - "Methodology Pitfalls Record"
Cohesion: 0.09
Nodes (23): claude-mem plugin outage text injected into completion, No observed memorization advantage for real CVE over synthetic twin, CRLF/LF text-mode write bug corrupting synthetic case file, Pitfall 3: same classifier bug class recurred in new shape, Pitfall 1: CRLF/LF mismatch corrupting memorization-control result, Pitfall 14: Anthropic cyber safeguards refusing patch-generation prompt, Rationale: read raw request/response before trusting any boolean, Methodology Pitfalls Record (+15 more)

### Community 5 - "Frozen CVE Catalog"
Cohesion: 0.11
Nodes (20): CVE-2026-54729 (dssrf, SSRF), CVE-2026-40246 (free5GC/udr, CWE-285), CVE-2026-40248 (free5GC/udr, CWE-285), CVE-2026-23949 (jaraco.context, Path Traversal), CVE-2026-42208 (litellm, SQLi), CVE-2026-27602 (modoboa, CMDi), CVE-2026-78683 (nltk, Deserialization), Frozen CVE Catalog (8 entries) (+12 more)

### Community 6 - "XSS Oracle Bug & Classifier Fix"
Cohesion: 0.11
Nodes (19): CVE-2026-46492 (md-fileserver, XSS), Claude backend re-run (36 pairs, 0/36 corrected), _EXEC_HTML oracle regex bug (matches escaped onerror= text), False-positive bypass: gemma2:9b vs XSS CVE, _EXEC_HTML oracle regex bug, Rationale: check raw evidence before trusting aggregate pass/fail (test-oracle bug vs real bug discipline), Rationale: Codex explicitly out of scope, gets its own separate comparison, Classifier bug: byte-identical canonical path counted as false bypass, fixed with URL-decode check, ClaudeCLIProvider diagnostic-fidelity gap: discards stdout JSON on non-zero exit (+11 more)

### Community 7 - "OpenEMR LLM Patch Bugs"
Cohesion: 0.12
Nodes (17): Pitfall 5: three distinct logic bugs in LLM-generated OpenEMR patches, Pitfall 7: alarming patch-byte-identity clustering investigated, not a bug, NO_PAID_BACKEND import-order bug in OpenEMR patch-gen script, llama3.1:8b completely inverted logic leaves vulnerability fully open, Missing isset() guard causes PHP 'headers already sent' status-code bug, Swapped boolean operator (OR instead of AND) fails safe but breaks legit path, Rationale: PHP's silent warnings make lint pass a weaker signal than go build, OpenEMR LLM Patch-generation Results (+9 more)

### Community 8 - "Scope and Limitations"
Cohesion: 0.14
Nodes (15): Scope and Limitations, Rationale: fuzzing-LLM pitch dropped, confirmed OK by professor, CVE-2026-23949 (jaraco.context) real-package validation exception, Limitation 1: exploit targets are reproductions, not real package, Limitation 2: Stage 3 live probe real for SSRF only, static for 5 classes, Limitation 3: patch validation proves regression-safety, not general correctness, Limitation 5: two unmerged free5GC efforts (free5gc_lab vs reachability), Limitation 6: LLM-dependent paths verified via stub, then live (+7 more)

### Community 9 - "Repeated Patch-Gen Evidence Ledger"
Cohesion: 0.14
Nodes (14): free5GC R&D Demonstration Runbook, Expected verdict: confirmed_fix_all_four_handlers, Failed LLM patch examples: codellama:13b run2 compile fail, qwen2.5-coder:1.5b runs2-3 leak remained, run_full_deployment_harness.py demonstration script, Counts: 6/8 models runtime-confirmed, 1 partial, 1 environment-limited, Evidence Ledger: October 2026 R&D Baseline, Required final-study fields for October repeated patch-generation study, Research Questions and Acceptance Criteria table (+6 more)

### Community 10 - "free5GC Full-CRUD Bypass Probe"
Cohesion: 0.29
Nodes (7): Q&A: Does the free5GC patch actually fix the vulnerability? (Yes â€” runtime confirmed all 4 handlers), All-installed-Ollama free5GC Bypass Probe (6 Oct 2026), Rationale: single-shot probe, bounded claim not universal resistance, Results: 7 executed proposals, 0 confirmed bypasses, free5GC CVE-2026-40248 Bypass Probe Results (Ollama), Four-handler behaviour table (GET collection, GET single, PUT, DELETE) vulnerable vs patched, Materially stronger characterization than frozen FYP report: full CRUD bypass, not just delete

### Community 11 - "free5GC LLM Patch Scoping"
Cohesion: 0.29
Nodes (7): free5GC LLM Patch Scoping Doc, generate_patch() provider-agnostic extension point, Rationale: target GET-collection handler first, Level 1: LLM patch text, no runtime validation, Level 2: LLM patch, compile+runtime validated, Rationale: use Ollama first, not paid API, Known limitation: rule-based patcher under-fixes GET-collection handler

### Community 12 - "Benchmark Metrics Definitions"
Cohesion: 0.67
Nodes (3): Benchmark Metrics Definitions (DETECTED/PLAUSIBLE/CORRECT/COMPILE-VERIFIED/SELF-IMPROVED), Provenance Tags (template/llm-stub/llm-live/lesson-reuse), Scoring fields: patch_exploit_blocked / patch_function_preserved / patch_verdict

### Community 13 - "Main-Catalogue Bypass Probe"
Cohesion: 0.67
Nodes (3): Main-catalogue Bypass Probe Results, Catalog Bypass Probe Method (8 Ollama models, HTTP proposal, oracle MARKER check), Catalog Bypass Probe Results (0/48 genuine bypasses, Ollama)

## Knowledge Gaps
- **111 isolated node(s):** `Provenance Tags (template/llm-stub/llm-live/lesson-reuse)`, `S2 Classification Ablation (S2-FULL/S2-PROSE/S2-ID)`, `Rationale: run-id needed to prevent artifact overwrite across multi-run comparisons`, `Rationale: prefer structured CWE over prose classification (_classify_from_cwe before _classify_from_text)`, `CVE-2026-42208 (litellm, SQLi)` (+106 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **7 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `free5GC LLM-generated Patch Results (Level 2, complete)` connect `free5GC Claude Patch Sweeps` to `free5GC Full-CRUD Bypass Probe`, `Frozen CVE Catalog`?**
  _High betweenness centrality (0.101) - this node is a cross-community bridge._
- **Why does `free5GC LLM Patch: All-Local-Models Sweep (Ollama)` connect `free5GC Claude Patch Sweeps` to `Repeated Patch-Gen Evidence Ledger`?**
  _High betweenness centrality (0.089) - this node is a cross-community bridge._
- **Why does `free5GC Full-Deployment Extension (CVE-2026-40248, all 4 handlers)` connect `Frozen CVE Catalog` to `Repeated Patch-Gen Evidence Ledger`, `free5GC Full-CRUD Bypass Probe`, `free5GC Claude Patch Sweeps`?**
  _High betweenness centrality (0.069) - this node is a cross-community bridge._
- **What connects `Provenance Tags (template/llm-stub/llm-live/lesson-reuse)`, `S2 Classification Ablation (S2-FULL/S2-PROSE/S2-ID)`, `Rationale: run-id needed to prevent artifact overwrite across multi-run comparisons` to the rest of the system?**
  _111 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Rejected CRS Redesign Proposal` be split into smaller, more focused modules?**
  _Cohesion score 0.06628787878787878 - nodes in this community are weakly interconnected._
- **Should `OpenEMR Transfer Case Setup` be split into smaller, more focused modules?**
  _Cohesion score 0.08923076923076922 - nodes in this community are weakly interconnected._
- **Should `free5GC Claude Patch Sweeps` be split into smaller, more focused modules?**
  _Cohesion score 0.08666666666666667 - nodes in this community are weakly interconnected._