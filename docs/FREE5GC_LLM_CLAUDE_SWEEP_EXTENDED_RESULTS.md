# free5GC LLM patch: extended Claude model sweep (user-requested names)

Extends `docs/FREE5GC_LLM_CLAUDE_SWEEP_RESULTS.md` with 5 additional
model name strings the user explicitly asked to test: `claude-sonnet-4-6`,
`claude-sonnet-5`, `claude-opus-4-6`, `claude-opus-4-7`,
`claude-opus-4-8`. Produced by
`free5gc_full_deployment/run_claude_sweep_extended.py`.

## Cost checkpoint, done before spending anything

A cheap "reply OK" smoke test of all 5 names first, to find out whether
they resolve to real models before running the full pipeline on any of
them. That smoke test alone cost **$5.49** - $0.63/$1.11/$1.04/$1.39/$1.33
per model, each showing 100K-277K `cache_creation_input_tokens`, far
more than the $0.21-$1.13 range the three models in the original sweep
needed for the *same* trivial prompt. This was flagged to the user
explicitly, given this project's own documented ~$6.88 overspend
history, before any further spend; the user reviewed it and chose to
proceed with the full pipeline for all 5 anyway.

**What that cost spike actually was**: Anthropic's prompt-cache pricing
charges a premium for the first write to a cache slot
(`cache_creation_input_tokens`) and cheap reads afterward
(`cache_read_input_tokens`) within the cache's TTL. The smoke test was
each model's *first* call in this session, paying full cache-creation
cost; the real patch-generation calls that followed cost markedly less
per model ($0.15-$0.35, see below) for a much larger prompt. The
smoke-test cost was mostly one-time warm-up overhead, not a sustained
per-call rate - worth knowing, but it did not predict the real run's
actual cost.

## Results

| Model | Compiles | Cost (USD) | Runtime verdict |
|---|---|---|---|
| `claude-sonnet-4-6` | yes | $0.1494 | **confirmed_fix_all_four_handlers** |
| `claude-sonnet-5` | **NO** - refused (see below) | $1.1130 (on the diagnostic call; see note) | not reached |
| `claude-opus-4-6` | yes | $0.2477 | **confirmed_fix_all_four_handlers** |
| `claude-opus-4-7` | yes | $0.3427 | **confirmed_fix_all_four_handlers** |
| `claude-opus-4-8` | yes | $0.3460 | **confirmed_fix_all_four_handlers** |

4 of 5 confirmed the fix. Full report:
`reports/reachability/free5gc_llm_claude_sweep_extended.json`.

### `claude-sonnet-5`: a real model, blocked by Anthropic's own cyber safeguards - and the refusal still costs money

`claude-sonnet-5` is confirmed as a real, distinct model
(`canonicalModel: "claude-sonnet-5"`, 1,000,000-token context window,
`provider: "firstParty"` in the CLI's own usage report) - not an invalid
name. But every attempt to send it this project's patch-generation
prompt (which mentions CVE/CWE/vulnerability/fix) was refused:

```
API Error: Sonnet 5's safeguards flagged this message. Our intentionally
broad safeguards allow us to deliver more capabilities faster, but can
sometimes flag legitimate cybersecurity work. Apply to the Cyber
Verification Program to reduce these interruptions.
Details: `[cyber]`
```

This is a real-time content safeguard specific to this model, not a bug
in this project's code, and not something retrying would fix - it is a
deterministic policy block tied to the prompt's subject matter, so this
result does not retry it further (retrying would just cost the same
again for the same refusal). **The refusal itself was still charged in
full** ($1.11 on the diagnostic call that captured this error message,
`cache_creation_input_tokens: 278215`) - Anthropic bills the
cache-creation cost even when the model declines to answer. The
in-sweep attempt recorded `$0 / n/a` because the run that produced the
summary table above happened not to log a cost figure from the refusal
path the harness's exception handler takes; the standalone diagnostic
call run separately (shown above) is the real, confirmed cost for this
model's refusal.

This is a genuine, reportable finding in its own right: **a model
specifically designed to assist with security work (patch generation
for a known CVE) is blocked by that same vendor's own safeguards from
doing so**, unless the account completes a separate verification
process - and the attempt to find this out is not free.

### `claude-opus-4-8`: one transient `go build` timeout, unrelated to the model

First attempt timed out during the **baseline** (unpatched) compile
check - before the LLM was ever called, so no cost was incurred. Almost
certainly a transient network hiccup fetching Go module dependencies
(the same class of issue seen earlier with a Docker build's
`connection reset by peer` in `docs/FREE5GC_LLM_CLAUDE_SWEEP_RESULTS.md`).
Retried cleanly on the second attempt with no further changes.

## What this does not resolve

Same standing limitations as every other result in this series
(memorization risk, one run per model, no statistically meaningful cost
benchmark) - see `docs/FREE5GC_LLM_CLAUDE_SWEEP_RESULTS.md`.

## Files

- `free5gc_full_deployment/run_claude_sweep_extended.py` - the sweep
  driver for this specific model-name list.
- `reports/reachability/free5gc_llm_claude_sweep_extended.json`/`.md` -
  full machine-readable and summary reports.
