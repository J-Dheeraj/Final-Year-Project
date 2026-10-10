# free5GC prompt/cache sensitivity study (2026-10-10)

This study varies only a no-op audit marker in a semantically identical
request. It tests stability under each gateway/request protocol; it does not
claim intrinsic model determinism.

| Backend | Models | Runs | Successful calls | Unique output hashes | Input tokens | Output tokens | Measured cost |
|---|---:|---:|---:|---:|---:|---:|---:|
| AIxTech gateway | 4 | 12 | 12 | 12 | 978 | 9,586 | token-only; no dollar figure reported |
| Claude CLI | 4 | 12 | 9 | 9 successful; Opus 4.6 had 3 CLI rejections | 70 | 10,980 | US$0.6730 |

AIxTech produced different hashes for all three prompt variants for every
model, so this study found no byte-identical convergence under the markers.
Claude CLI successful calls also varied; the three Opus 4.6 calls were
retained as environment/model-access failures.

Raw reports:

- `reports/reachability/free5gc_aixtech_prompt_cache_sensitivity.json`
- `reports/reachability/free5gc_claude_prompt_cache_sensitivity.json`
