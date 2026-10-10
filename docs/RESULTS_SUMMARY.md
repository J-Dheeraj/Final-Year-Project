# Results summary: free5GC/OpenEMR/catalog enhancement pass

One table per experiment from the "do everything" enhancement pass and
its subsequent Claude-backend re-run. Each row links to the doc with
full method, verification steps, and raw data - this page exists so
the headline numbers don't require reading ~20 documents to find. See
`docs/RESULTS_BY_ACCESS_METHOD.md` for the same results re-cut by
access mechanism (Claude API key / Claude Code / Claude CLI / Codex
CLI / Ollama / OpenAI API) instead of by experiment, and
`docs/FINAL_EVIDENCE_SUMMARY.md` for the one-page bounded conclusion
across all of it.

## 1. Sweep-script unification

No experimental result - consolidated 5 duplicated scripts into
`free5gc_full_deployment/sweep.py` (`--task {patch,bypass} --backend
{ollama,claude} [--models] [--runs N]`).

## 2. Memorization control: synthetic vs. real CVE

| Backend | Models | Synthetic bug | Real CVE (matched) |
|---|---|---|---|
| Ollama | 4 (small, locally available) | 1/4 compiled | 1/4 compiled |
| Claude (`claude -p`) | 6 named | 4/6 compiled (1 failure was a local-plugin artifact, not a real failure) | 5/6 compiled |
| AIxTech gateway | 10 named (6 403-denied by key) | 4/4 reachable compiled | 4/4 reachable compiled |

No memorization advantage observed for the real, potentially-trainable-on
CVE over the synthetic, provably-never-disclosed twin, in either backend.
[docs/FREE5GC_MEMORIZATION_CONTROL_RESULTS.md](FREE5GC_MEMORIZATION_CONTROL_RESULTS.md)

## 3. Multi-run variance (bypass-probe stability)

| Backend | Models x runs | Bypass confirmed |
|---|---|---|
| Ollama | 2 models x 3 runs | 0/6 |

The fix holding is not a one-run fluke, at least for this sample.
[docs/FREE5GC_MULTI_RUN_VARIANCE_RESULTS.md](FREE5GC_MULTI_RUN_VARIANCE_RESULTS.md)

## 4. Real OAuth2 enforcement

| Condition | Vulnerable build | Patched build |
|---|---|---|
| No credentials | 401 (blocked) | 401 (blocked) |
| Valid, correctly-scoped token | Exploit succeeds | Fix still holds |

OAuth2 and the code-level fix are independent, complementary layers -
OAuth2 blocks anonymous callers but gives zero protection against a
credentialed attacker once the CWE-285 bug is present.
[docs/FREE5GC_OAUTH2_ENFORCEMENT_RESULTS.md](FREE5GC_OAUTH2_ENFORCEMENT_RESULTS.md)

## 5. OpenEMR extension (patch-gen + bypass-probe)

| Backend | Patch-gen clean pass | Bypass-probe (0 = fix held) |
|---|---|---|
| Ollama (8 models) | 1/7 completed | 0/7 |
| Claude (`claude -p`, 6 models) | 5/6 | 0/5 completed |
| AIxTech gateway (10 models, 6 403-denied) | 4/4 reachable | 0/3 completed |

Ollama's patch-gen failures were genuinely varied: a missing `isset()`
guard (functionally safe, wrong status code), a swapped boolean
operator (fails safe, breaks legitimate use), and one model with
**completely inverted logic** that left the real vulnerability fully
open. [docs/OPENEMR_LLM_PATCH_RESULTS.md](OPENEMR_LLM_PATCH_RESULTS.md),
[docs/OPENEMR_BYPASS_PROBE_RESULTS.md](OPENEMR_BYPASS_PROBE_RESULTS.md)

## 6. Main 6-CVE catalogue bypass-probe

| Backend | Pairs tested | Genuine bypasses | False positives caught |
|---|---|---|---|
| Ollama | 48 (6 CVEs x 8 models) | 0 | 1 (XSS oracle regex bug) |
| Claude (`claude -p`) | 36 (6 CVEs x 6 models) | 0 | 3 (same oracle bug, self-diagnosed by the models) |
| AIxTech gateway | 60 (6 CVEs x 10 models, 36 pairs 403-denied) | 0 | 2 (same oracle bug again, both self-diagnosed) |

[docs/CATALOG_BYPASS_PROBE_RESULTS.md](CATALOG_BYPASS_PROBE_RESULTS.md)

## 7. Multi-turn adversarial probing

| Backend | Models x rounds | Genuine bypasses |
|---|---|---|
| Ollama | 8 models x up to 3 rounds | 0/7 completed |
| Claude (`claude -p`) | 6 models x up to 3 rounds | 0/6 (after fixing a third classifier false-positive variant) |
| AIxTech gateway | 10 models x up to 3 rounds (6 403-denied) | 0/4 completed, clean (classifier fix already in place) |

Seeing a rejection changed what models tried next but never toward
something that worked. [docs/FREE5GC_MULTITURN_BYPASS_PROBE_RESULTS.md](FREE5GC_MULTITURN_BYPASS_PROBE_RESULTS.md)

## 8. Patch-quality scoring (beyond pass/fail)

9 of 14 already-generated free5GC patches are byte-identical to the
real upstream fix; the other 5 (weaker Ollama models) deviate by 1-3
lines while still passing every runtime check.
[docs/PATCH_QUALITY_SCORING_RESULTS.md](PATCH_QUALITY_SCORING_RESULTS.md)

## 9. Methodology pitfalls

15 real bugs found and fixed before being reported, across this pass
and earlier sessions - including the free5GC bypass-probe classifier,
patched three times for three different disguises before being
replaced with a live-comparison check that doesn't need to guess the
next one, and a stray ambient env var that broke a brand-new gateway
provider's auth on its first live call.
[docs/METHODOLOGY_PITFALLS.md](METHODOLOGY_PITFALLS.md)

## 10. Repeated patch-generation study

The final October study ran four local models three times each against the
same real free5GC deployment. **9/12 attempts were runtime-confirmed**:
`codellama:13b` 2/3, `gemma2:9b` 3/3, `qwen2.5-coder:7b` 3/3, and
`qwen2.5-coder:1.5b` 1/3. One attempt failed compilation and two compiled
patches left the collection-GET leak open. No hosted-model calls were used.
[docs/FREE5GC_PATCH_REPEAT_RESULTS.md](FREE5GC_PATCH_REPEAT_RESULTS.md)

Raw report: `reports/reachability/free5gc_sweep_patch_ollama_october-2026-patch-repeat.json`.

## 11. All-installed-Ollama snapshot

On 6 October, all eight installed Ollama models were run once in a fresh
snapshot. **5/8 were runtime-confirmed**, two failed compilation, and one
failed before generation because of the model/runtime environment. This is a
separate snapshot from the repeated study and does not replace its 9/12
result. [docs/FREE5GC_ALL_OLLAMA_SWEEP_2026-10-06.md](FREE5GC_ALL_OLLAMA_SWEEP_2026-10-06.md)

## 12. All-installed-Ollama bypass probe

All eight installed Ollama models were also asked once to probe the patched
free5GC deployment for a request that could restore the vulnerable behaviour.
Seven proposals executed and **0/7 produced a genuine bypass**. The remaining
model failed before generation because of an Ollama runtime error, so it is
recorded as unevaluated rather than as a security success or failure.
[docs/FREE5GC_ALL_OLLAMA_BYPASS_2026-10-06.md](FREE5GC_ALL_OLLAMA_BYPASS_2026-10-06.md)

## 13. Final Codex CLI model matrix

The final Codex CLI matrix attempted 18 model IDs, including GPT-3-era,
GPT-4, GPT-5, GPT-5.6, GPT-6, and o-series names. **7/18 patches compiled and
all 7 were runtime-confirmed across the four handlers.** The bypass phase
executed 4 proposals and found **0 genuine bypasses**; the remaining attempts
were preserved as environment-limited failures. The final run recorded
186,270 input and 2,528 output tokens for patch generation, plus 104,317 input
and 974 output tokens for bypass probing.
[docs/FREE5GC_CODEX_SWEEP_2026-10-07.md](FREE5GC_CODEX_SWEEP_2026-10-07.md)

## 14. AIxTech gateway backend pass (10 named models)

The user's 10 requested model names (haiku 4.5/5.5, sonnet 4.6/5/5.5,
opus 4.6/4.7/4.8/5/5.5) were run through all 4 experiment families via
the new `--backend aixtech` option, with every pair's result - success,
genuine failure, or 403 denial - recorded individually rather than
summarized away, per-model runtime (`last_duration_s`) and real input/
output token counts (`last_usage`) captured for every call. Only 4
resolve on this gateway key (`claude-haiku-4-5-20251001`,
`claude-haiku-5-5`, `claude-sonnet-4-6`, `claude-sonnet-5`); the other 6
(`claude-sonnet-5-5`, all 5 `claude-opus-*`) are blocked by the key's
own team-scoped model allowlist (403 `team_model_access_denied` on
every single call, each still timed), recorded as the model's error in
every experiment rather than silently omitted. Of the 4 reachable
models, results were clean across the board (patch-gen gates passed,
no genuine bypasses, no memorization advantage) with one recurring
exception: the already-documented `_EXEC_HTML` oracle regex bug fired
twice on a re-run of the catalogue's XSS CVE (`claude-haiku-4-5-20251001`
and `claude-haiku-5-5`) - the same bug this project has already found
twice before and deliberately left unfixed, not a new finding. This
gateway does not report a dollar cost per call - no guessed per-token
price is substituted for model names with no verifiable published
rate; `docs/METHODOLOGY_PITFALLS.md` #15 documents an auth bug found
and fixed during this pass. Full per-model tables (all 10 rows, every
experiment) are in each experiment's own doc.

## Total measured paid-backend cost (Claude re-run pass)

**$29.53** across all 4 re-run experiments plus debug smoke tests -
see each doc's own "Update: Claude backend" section for the per-model
breakdown. The AIxTech gateway pass (section 14) is additional and
separately costed by that gateway's own account, not reported here.

## OpenAI API catalog bypass sweep (2026-10-09)

Using the project-scoped OpenAI API key, the patched targets for all six
main-catalogue CVEs were probed with 23 exposed GPT model IDs (138
model/CVE pairs). The raw report is
[`reports/reachability/catalog_bypass_probe_openai.json`](../reports/reachability/catalog_bypass_probe_openai.json), with the concise summary in
[`reports/reachability/catalog_bypass_probe_openai.md`](../reports/reachability/catalog_bypass_probe_openai.md).

| Measure | Result |
|---|---:|
| Model/CVE pairs | 138 |
| Parsed proposals | 108 |
| API/runtime errors | 30 |
| Raw oracle positives | 12 |
| Genuine bypasses after response audit | **0** |
| Total model-call runtime | **1,176.50 s** |
| Input/output tokens | **90,735 / 91,997** |
| Estimated cost for priced model IDs | **US$0.2879** |

All 12 raw positives were on the XSS target (CVE-2026-46492). The patched
renderer escaped the proposed markup; the target's existing self-check regex
matched literal `onerror=` or `javascript:` text inside escaped content. They
are therefore retained as raw oracle positives but reclassified as false
positives, consistent with the earlier Ollama and Claude audits. No genuine
bypass was confirmed. Deprecated models and API cybersecurity-policy errors
remain visible in the raw report and are not counted as model-quality failures.

## OpenAI API reruns: OpenEMR and free5GC (2026-10-10)

The OpenAI API rerun used the same local validation harnesses and the 23 model IDs exposed by the project. Per-model raw JSON preserves input/output tokens, wall-clock generation time, estimated cost, and failures.

| Experiment | Completed | Result | Runtime | Tokens (in/out) | Estimated cost |
|---|---:|---|---:|---:|---:|
| OpenEMR bypass | 23/23 | 0/23 bypasses; 20 parseable proposals | 207.30 s | 6,796 / 14,358 | US$0.0239 |
| OpenEMR patch | 23/23 | 16/23 fully working gates | 91.89 s | 5,606 / 6,419 | US$0.0206 |
| free5GC bypass | 23/23 | 0/23 bypasses; 19 parseable proposals | 166.74 s | 8,589 / 12,739 | US$0.0296 |
| free5GC patch | 23/23 | 18/23 runtime-confirmed all four handlers; 5 compile failures; 1 deprecated model | 125.77 s | 11,284 / 9,141 | US$0.0603 |

Reports: [`openemr_bypass_probe_openai.json`](../reports/reachability/openemr_bypass_probe_openai.json), [`openemr_llm_patch_openai.json`](../reports/reachability/openemr_llm_patch_openai.json), [`free5gc_sweep_bypass_openai_openai-2026-10-10-bypass.json`](../reports/reachability/free5gc_sweep_bypass_openai_openai-2026-10-10-bypass.json), and [`free5gc_sweep_patch_openai_openai-2026-10-10.json`](../reports/reachability/free5gc_sweep_patch_openai_openai-2026-10-10.json).

The combined free5GC patch report now covers all 23 model IDs. Each model required a fresh Go clone, compilation, Docker image build, and four-handler runtime check. Five generated patches failed compilation and one deprecated model failed before generation; 18 produced runtime-confirmed fixes.


Repeatability and final presentation artifacts: [`docs/FREE5GC_OPENAI_REPEATABILITY_RESULTS.md`](docs/FREE5GC_OPENAI_REPEATABILITY_RESULTS.md), [`docs/SUPERVISOR_BRIEFING.md`](docs/SUPERVISOR_BRIEFING.md), and [`docs/FINAL_DEMONSTRATION_CHECKLIST.md`](docs/FINAL_DEMONSTRATION_CHECKLIST.md).


Clean reproduction record: [REPRODUCTION_RECORD_2026-10-10.md](REPRODUCTION_RECORD_2026-10-10.md).
