# Results & Discussion checklist audit

Audited against `free5gc_full_deployment/FYP_Report_main_upgraded.tex`,
Chapter 4 ("Results and Discussion"), as it stands after the OpenEMR
addition and pinned-commit fix (commit `0232f15`). Each item is marked
**Pass**, **Partial**, or **Gap**, with the specific text or absence
that the verdict is based on — not a restated checklist.

## Results Section

| Item | Verdict | Evidence |
|---|---|---|
| Only relevant results included (no raw data dump) | **Pass** | Every table reports an aggregated figure (confirmation rate, cost, verdict counts); raw per-call JSON is pointed to via Appendix references, not inlined. |
| Results organised logically (by experiment/research question) | **Pass** | Chapter 4 is organised by experiment in a clear progression: catalogue confirmation → patch validation → corrected validator → real-upstream cases (×3) → multi-model comparisons → reachability → classification ablation. |
| Tables and graphs are easy to read (axes labelled, legends included) | **Gap** | Every quantitative result in this chapter is a table (7 tables total: confirmation-rounds, multi-model, Claude multi-model, ablation, real-upstream, OpenEMR). **There is not a single plot, chart, or graph anywhere in the Results chapter** — only the three architecture *diagrams* (Figures 3.1–3.3), which illustrate system structure, not results. Table~4.1's own 5-round confirmation-rate progression (17%→33%→17%→67%→83%) and Table~4.5's cost-vs-screening-pass-rate relationship across 6 Claude models are both directly plottable trends currently only readable as rows of numbers. |
| Units, decimal points, and significant figures are correct | **Pass** | Consistent throughout: costs to 2 d.p. (`$1.81`), durations to 1 d.p. (`114.9`s), percentages to 1 d.p. (`96.1\%`), token counts as plain integers. No inconsistent precision spotted. |
| Results show trends, differences, and relationships, not just numbers | **Pass** | Explicit relationship claims are made and checked against the data: "cost and screening-pass rate are not monotonically related" (Haiku 4.5 cheapest + tied-best), "confirmation rate did not track parameter count" (7B beat 9B and 13B models). |
| Baseline or control results are presented for comparison | **Pass**, differently labelled | The word "baseline" appears only in a trace excerpt and one appendix reference, but the *substance* is present throughout: every real-upstream case is explicitly vulnerable-commit vs. patched-commit; the ablation's three conditions (full advisory / prose-only / identifier-only) function as a stripped-down control ladder. |
| Unexpected or negative results are clearly presented | **Pass** | Strong: the round-5 false patch acceptance, the OpenAI 401 authentication failures, `deepseek-coder-v2:16b`'s OOM failure, `qwen2.5-coder:1.5b`'s template-fallback-only confirmations, and the XSS class's 0/6 pass rate across *every* hosted Claude model are all reported as negative findings, not omitted or buried. |

## Discussion Section

| Item | Verdict | Evidence |
|---|---|---|
| Each key result is interpreted and explained | **Pass** | Section 4.2 ("Discussion") has a dedicated subsection per major result: confirmation-rate progression, why patch validation lagged, runtime/model-size findings, classification reliability, AIxCC/OSS-CRS relationship. |
| Trends, anomalies, and patterns are explained logically | **Pass** | The `codellama:13b` (1544s) vs. `deepseek-coder-v2:16b` (176.6s) runtime-vs-parameter-count anomaly is named and left honestly unexplained ("not root-caused... reported as observed rather than explained by an unverified guess") rather than papered over with a guess. |
| Discussion links results to theory, design goals, or prior literature | **Pass** | Section 4.2.4 explicitly relates the 96.1% reachability reduction to OpenAnt/FuzzingBrain's published figures, with the correct caveat that FuzzingBrain's own paper reports no comparable percentage. |
| Comparisons with baseline, expected outcomes, or simulations are made | **Pass** | AIxCC's 86%/68% aggregate is explicitly brought in as context, with an equally explicit statement of why a direct numerical comparison is invalid (different task/scale/denominator) — comparison attempted, limits of the comparison stated honestly. |
| Limitations, sources of error, or assumptions are discussed | **Pass** | Section 4.3 ("Limitations, Trade-offs, and Sources of Uncertainty") is a full subsection; Chapter 3's own Section 3.9 duplicates this at the method level. |
| Trade-offs and design compromises are acknowledged | **Pass** | The single-shot-per-CVE design, the self-improvement iteration bound of 3, and OAuth2 being disabled to reach the free5GC handlers are all named as explicit, deliberate trade-offs rather than silent gaps. |
| Practical implications of results are clearly stated | **Pass** | Section 4.4 ("Summary and Implications") draws a direct practitioner takeaway: reachability filtering as a transferable technique independent of the harder patch-generation question. |
| Critical thinking demonstrated (e.g., why results differ from theory) | **Pass**, this chapter's strongest point | The round-5 false-acceptance finding is the clearest example: the criterion's own design flaw (can't distinguish a crash from a deliberate fix) is traced by direct trace inspection, not asserted. |
| Discussion is coherent, not just bullet points or repeated numbers | **Pass** | Written entirely in connected prose; the only enumerated list in Chapter 4/5 is the final "Key Findings" summary, which is explicitly a recap, not the primary discussion vehicle. |

## Computing / Computer Science

| Item | Verdict | Evidence |
|---|---|---|
| Accuracy, precision, recall, and F1-score clearly reported | **Gap** (for the one genuine classification task) | Section 4.1.6's Stage-2 CWE classification is this project's only true classification task (6 classes, one instance each). It reports raw match/mismatch counts ("5/6 class-level, 4/6 exact-CWE") but no precision, recall, or F1. With n=6 and one example per class this is low-powered regardless, but the metrics are computable and currently absent. Everywhere else in the chapter, "accuracy" in the ML-classifier sense does not apply — confirmation rate and `patch_verdict` are the correct, already-reported analogues for a confirmation/validation task rather than a classifier. |
| Confusion matrix and error analysis included | **Partial** | No confusion matrix is presented (a 6×6 matrix would be mostly zeros given n=1/class, genuinely low information value). Error analysis itself is strong and specific in prose (the exact CVE-2026-42208 miss and the CWE-79-vs-80 mismatch are both individually traced to a named cause), just not presented as a matrix. |
| Runtime, memory, and scalability discussed | **Pass**, "scalability" implicit rather than named | Runtime is extensively covered (per-model LLM call time, per-CVE wall-clock, the codellama/deepseek anomaly). Memory is discussed concretely once and correctly (`deepseek-coder-v2:16b`'s 45 GB OOM failure, explicitly separated from model-quality). The word "scalability" itself never appears, though the parallel-workers=2 bound and the single-shot-per-model design are de facto scalability trade-offs already stated elsewhere (Chapter 3 Key Parameters table; Section 4.3). |
| Comparison to baseline algorithms or datasets | **Pass** | The rule-based heuristic patcher is compared directly against LLM-generated patches on the same free5GC handler (Section 4.1.7: rule-based patcher under-fixes, requiring only one `return` insertion vs. the real fix's two); AIxCC/OSS-CRS serves as the cross-system comparison point, with its limits stated. |

## Summary

Of 20 checklist items, **17 are a clean Pass**, 1 is **Pass-but-
differently-labelled** (baseline terminology), 1 is a genuine **Gap**
(no plots/graphs anywhere in the Results chapter — tables only), and
1 is a **Gap specific to the classification task** (precision/recall/
F1/confusion matrix not reported for Stage 2's CWE classification,
though its practical value is limited at n=6).

Both gaps are fixable without new experiments — they are presentation
gaps on data that already exists, not missing evidence:
- A plot of Table 4.1's 5-round confirmation-rate progression and
  Table 4.5's per-model cost-vs-screening-rate would directly address
  the "no graphs" gap using numbers already in the chapter.
- Precision/recall/F1 (and, if wanted, a 6×6 confusion matrix) for
  Table 4.6's classification ablation can be computed directly from
  the already-reported 5/6 and 4/6 match counts.
