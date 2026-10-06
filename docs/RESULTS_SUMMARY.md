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

## Total measured paid-backend cost (Claude re-run pass)

**$29.53** across all 4 re-run experiments plus debug smoke tests -
see each doc's own "Update: Claude backend" section for the per-model
breakdown.
