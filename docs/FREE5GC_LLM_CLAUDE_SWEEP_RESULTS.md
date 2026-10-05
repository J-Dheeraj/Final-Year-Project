# free5GC LLM patch: Claude model sweep (paid backend)

Extends `docs/FREE5GC_LLM_MODEL_SWEEP_RESULTS.md` (all 8 local Ollama
models) with real, hosted Claude models, via a new `ClaudeCLIProvider`
that shells out to the `claude` CLI's own authenticated session
(mirrors `cve_pipeline.py`'s existing `_call_claude_metered` mechanism)
rather than requiring a separate `ANTHROPIC_API_KEY`. This is a **paid
backend** - every completion call costs real money. Produced by
`free5gc_full_deployment/run_claude_model_sweep.py`.

## Results

| Model | Compiles | Applied/4 | Cost (USD) | Runtime verdict |
|---|---|---|---|---|
| `claude-haiku-4-5-20251001` | yes | 4/4 | $0.2138 | **confirmed_fix_all_four_handlers** |
| `claude-sonnet-5-5` | yes | 4/4 | $1.1334 | **confirmed_fix_all_four_handlers** |
| `claude-opus-5-5` | yes | 4/4 | $0.1644 | **confirmed_fix_all_four_handlers** |

**Total measured cost: $1.5116** (real, from the CLI's own
`total_cost_usd` field - not estimated). All three models produced the
correct fix (both `return` statements, correctly placed) and were
confirmed at the same runtime evidence tier as every other result in
this project. Full report: `reports/reachability/free5gc_llm_claude_sweep.json`.

Cost did not track capability tier in a simple way: `claude-opus-5-5`
($0.16) was cheaper than `claude-sonnet-5-5` ($1.13) on this run -
plausibly explained by `sonnet` producing a longer response with more
reasoning/commentary before converging, while `opus` answered more
directly. This is one run per model, not a reliable cost benchmark.

## A real bug found and fixed: trailing commentary corrupting the patch

The system prompt explicitly says "Output ONLY the complete corrected
function body... no commentary," but `claude-opus-5-5` ignored this
**twice**, in two different ways, on two separate attempts:

1. **First attempt**: wrapped the fix in a ` ```go ` fence, then
   appended a full explanation paragraph *after* the closing fence.
   `generate_patch()`'s old cleanup (`patched_body.strip("`")`) only
   trims backtick characters off the very ends of the string, so the
   trailing fence + prose survived untouched and got spliced directly
   into the Go source - `go build` failed with
   `syntax error: non-declaration statement outside function body`.
2. **Second attempt** (after fixing #1 by extracting only the first
   fenced block): this time there was **no fence at all** - raw code,
   followed directly by a trailing explanation paragraph containing an
   em dash. Since the fence-based fix only triggers when the response
   *starts* with a fence, this trailing prose passed through completely
   unprocessed and again broke the build
   (`invalid character U+2014 '—' in identifier`).

Both fixes left the model's actual patch logic correct in both cases -
only the leftover prose caused the compile failure. Properly fixed on
the third attempt with a fence-independent approach:
`src/reachability/patch.py`'s `generate_patch()` now locates the
response's **last unindented `}` line** (the target function's own
closing brace - every target here is exactly one complete function) and
truncates there unconditionally, discarding anything after it
regardless of whether a markdown fence was ever present. A no-op when
the response already ends cleanly.

This is a genuine, reusable robustness fix to the shared patch-cleanup
code, not something specific to Claude - any provider that tends to add
trailing commentary despite being told not to would have hit the same
failure mode. It is now in effect for every provider, not just
`ClaudeCLIProvider`.

## A transient infrastructure failure (not a code or patch bug)

The first (patched-correctly) `claude-opus-5-5` Docker build failed with
`read tcp ...: connection reset by peer` while downloading Go module
dependencies from `proxy.golang.org` - a one-off network hiccup, not
related to the generated patch (which had already compiled cleanly
moments earlier). Retried the Docker build + runtime stage only
(without calling the LLM again, since the already-compiled patch file
on disk was still valid) and it passed cleanly.

## What this does not resolve

Same limitations as every other result in this series:

- **Memorization risk not controlled for** - a hosted frontier model is,
  if anything, more likely than a small local model to have the real,
  public fix commit in its training data.
- **One run per model** - no variance/repeat-run statistics gathered,
  same caveat as the Ollama sweep.
- **Cost is a real, single-run data point, not a statistically
  meaningful benchmark** of relative pricing across tiers.

## Files

- `src/reachability/providers.py` - new `ClaudeCLIProvider` class.
- `src/reachability/patch.py` - the fence-independent trailing-content
  truncation fix (benefits every provider, not just Claude).
- `free5gc_full_deployment/udr_build/prepare_llm_patched_source.py` -
  `materialize_and_verify()` now takes an optional `provider_factory`,
  defaulting to `OllamaProvider`, so the same compile-verification logic
  works for any provider.
- `free5gc_full_deployment/run_claude_model_sweep.py` - the sweep driver.
- `reports/reachability/free5gc_llm_claude_sweep.json`/`.md` - full
  machine-readable and summary reports.
