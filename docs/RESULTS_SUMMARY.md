# Results summary: free5GC/OpenEMR/catalog enhancement pass

One table per experiment from the "do everything" enhancement pass and
its subsequent Claude-backend re-run. Each row links to the doc with
full method, verification steps, and raw data - this page exists so
the headline numbers don't require reading ~20 documents to find.

## 1. Sweep-script unification

No experimental result - consolidated 5 duplicated scripts into
`free5gc_full_deployment/sweep.py` (`--task {patch,bypass} --backend
{ollama,claude} [--models] [--runs N]`).

## 2. Memorization control: synthetic vs. real CVE

| Backend | Models | Synthetic bug | Real CVE (matched) |
|---|---|---|---|
| Ollama | 4 (small, locally available) | 1/4 compiled | 1/4 compiled |
| Claude | 6 named | 4/6 compiled (1 failure was a local-plugin artifact, not a real failure) | 5/6 compiled |

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
| Claude (6 models) | 5/6 | 0/5 completed |

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
| Claude | 36 (6 CVEs x 6 models) | 0 | 3 (same oracle bug, self-diagnosed by the models) |

[docs/CATALOG_BYPASS_PROBE_RESULTS.md](CATALOG_BYPASS_PROBE_RESULTS.md)

## 7. Multi-turn adversarial probing

| Backend | Models x rounds | Genuine bypasses |
|---|---|---|
| Ollama | 8 models x up to 3 rounds | 0/7 completed |
| Claude | 6 models x up to 3 rounds | 0/6 (after fixing a third classifier false-positive variant) |

Seeing a rejection changed what models tried next but never toward
something that worked. [docs/FREE5GC_MULTITURN_BYPASS_PROBE_RESULTS.md](FREE5GC_MULTITURN_BYPASS_PROBE_RESULTS.md)

## 8. Patch-quality scoring (beyond pass/fail)

9 of 14 already-generated free5GC patches are byte-identical to the
real upstream fix; the other 5 (weaker Ollama models) deviate by 1-3
lines while still passing every runtime check.
[docs/PATCH_QUALITY_SCORING_RESULTS.md](PATCH_QUALITY_SCORING_RESULTS.md)

## 9. Methodology pitfalls

14 real bugs found and fixed before being reported, across this pass
and earlier sessions - including the free5GC bypass-probe classifier,
patched three times for three different disguises before being
replaced with a live-comparison check that doesn't need to guess the
next one. [docs/METHODOLOGY_PITFALLS.md](METHODOLOGY_PITFALLS.md)

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

## Total measured paid-backend cost (Claude re-run pass)

**$29.53** across all 4 re-run experiments plus debug smoke tests -
see each doc's own "Update: Claude backend" section for the per-model
breakdown.
