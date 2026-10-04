# Scoping: running an LLM model against free5GC (Phase 3, not yet started)

Read-only scoping pass, per explicit instruction ("scope out what it
would take to run a model on free5GC"). **No implementation in this
document.** Every claim below was verified by reading the actual code
in this repo on 2026-10-05, not assumed.

## What "running a model on free5GC" currently does NOT mean

Two prior results already exist and are sometimes conflated with this:

- `free5gc_runtime_case/run_harness.py` and
  `free5gc_full_deployment/run_full_deployment_harness.py` validate the
  real upstream maintainers' own fix commit, checked out directly. No
  model is involved in producing the patch in either case.
- `src/reachability/run_free5gc_case_study.py` (the offline
  reachability/triage/patch pipeline) hardcodes
  `provider="mock"` at line 36 and `skip_testing=True`. The "patch" it
  currently produces comes from `MockProvider`'s rule-based
  `_missing_return_fix()`, not from an LLM.

So today, zero lines of free5GC-related code or docs reflect an actual
model-generated patch or model-generated exploit. This matches what was
already confirmed when the user asked "did you run all the models on
free5GC CVEs" (answer: no).

## The exact extension point that already exists

`src/reachability/patch.py`'s `generate_patch(finding, provider,
exploit_outcome=None) -> Patch` is already provider-agnostic:

- If `provider` is a `MockProvider`, it calls the rule-based
  `_mock_fix()` path (what runs today).
- For any other `Provider` (`AnthropicProvider`, `OpenAIProvider`,
  `OllamaProvider` — all three already implemented and working in
  `src/reachability/providers.py`), it builds a prompt from
  `_SYSTEM_PROMPT` + `_USER_TEMPLATE` (CWE + explanation + function body)
  and calls `provider.complete(system, user)`, then strips markdown
  fences and records `method = f"llm-{provider.name}"`.

`get_provider(name, model)` (`providers.py:267`) already resolves
`"ollama"` to a real, free, local `OllamaProvider` — no API key, no
cost — provided Ollama is installed and running locally (not currently
verified as running on this machine; would need to be checked before
any run).

**Consequence: the absolute smallest change that makes "a model" touch
free5GC is one line** — in `run_free5gc_case_study.py:36`, change
`provider="mock"` to `provider="ollama"` (or make it a CLI flag instead
of hardcoding, which is better practice but still a small change). That
alone would cause `generate_patch()` to ask a real local LLM to patch
each of the 4 flagged handlers, using the exact same triage output
already on record.

## Two different levels of "running a model," with very different cost

### Level 1 — LLM-generated patch text, no runtime validation (small)

Just the one-line/CLI-flag change above. Effort: minutes. What it buys:
a real model-authored patch string per handler, written to
`reports/reachability/free5gc_case_study.json`/`.md`, with
`patch_method = "llm-ollama"` instead of `"mock-rule-based"`.

What it does NOT buy: any confirmation that the generated patch is
correct. `run_free5gc_case_study.py` runs with `skip_testing=True` —
there is no compile step and no runtime step in this script at all
today, for either the mock or the LLM path. An LLM patch produced this
way would sit at the same evidence tier as "a diff that was never
built" — a real step backward from the free5GC work's established
standard (compile-verified, then full runtime-confirmed across all 4
handlers).

### Level 2 — LLM-generated patch, validated at the same evidence tier as the existing free5GC work (the one worth reporting)

This means taking the LLM's generated patch and running it through the
same two gates the real upstream fix already passed:

1. **Compile-verified** against the real dependency graph — the
   pattern `verify_against_real_upstream.py` already uses for the real
   fix commit (apply patch to a live clone, `go build`). For an
   LLM-generated diff this requires either (a) prompting the model to
   emit a patch in a form that can be mechanically applied (unified
   diff against the vendored source), or (b) asking it to emit the full
   replacement function body and splicing it in programmatically —
   the second is simpler and lower-risk given typical model output
   quality on partial-file edits.
2. **Runtime-confirmed** in the existing Docker-based full-deployment
   harness (`free5gc_full_deployment/`) — swap the LLM-patched UDR
   build in place of the real upstream fix commit for the
   `UDR_COMMIT=...patched` Docker build arg. This needs
   `udr_build/Dockerfile` to build from a locally patched checkout
   rather than `git checkout <commit>` — a real but modest Dockerfile
   change (clone at the vulnerable commit, apply the LLM patch on top,
   then build), reusing the already-built MongoDB + NRF + custom-UDR
   stack as-is.

Effort for Level 2: a real, scoped implementation task — on the order
of what the Level-1 free5GC DELETE-handler harness took originally
(new Dockerfile variant, a patch-application step, re-running the
existing `run_full_deployment_harness.py` four-outcome verdict logic
against the LLM-patched build instead of the real fix). Not a one-line
change, but it reuses essentially all existing harness infrastructure —
no new Docker services, no new verdict vocabulary needed.

## Recommended first target: the GET-collection handler, not DELETE

`docs/REACHABILITY.md` already documents that
`HandleApplicationDataInfluenceDataSubsToNotifyGet` (the
collection-level, query-param-based handler) is the one case where the
**rule-based patcher is known to produce only a partial fix** — the
real root cause needs two separate `return` insertions, and the
deterministic patcher only finds the first occurrence. This is the
single handler where a real LLM run is interesting rather than
redundant: a model that reasons about control flow rather than
pattern-matching text could plausibly do better than the rule-based
patcher here, and if it does, that's a genuine, reportable comparison
("rule-based patcher under-fixes this handler; an LLM patch fixes it
completely" or the converse). The other three handlers (`Delete`,
`Get`, `Put` on `.../SubscriptionId...`) already have a correct,
already-runtime-confirmed rule-based fix, so an LLM re-doing the same
single-line fix there has much less evidential value.

## Recommended provider for the first run: Ollama, not a paid API

Free, local, already implemented (`OllamaProvider`), no `NO_PAID_BACKEND`
conflict to reason about (reachability's provider system does not
currently have a `NO_PAID_BACKEND`-style guard at all — unlike
`cve_pipeline.py`'s `_call_claude_metered`, nothing in
`src/reachability/` stops `get_provider("anthropic")` or `("openai")`
from making a metered call if a key is present in the environment; this
is a real, pre-existing gap worth closing before anyone runs this
unattended, independent of the free5GC question). Starting with Ollama
sidesteps that gap entirely for a first pass and costs nothing if the
result isn't useful.

## The methodological limitation that must be stated, not hidden

free5GC's real fix commit (`86686276a7e226183ee786e3dd6714ec56c78fda`)
is public, and the CVE/GHSA advisory text describing it is also public.
Any model whose training data includes GitHub history or vulnerability
databases up to a recent-enough cutoff could in principle reproduce the
known fix from memory rather than by genuinely re-deriving it from the
supplied function body. This would need to be disclosed explicitly in
any writeup of a Level 2 result (e.g., by also testing the model against
a handler/commit pair it's less likely to have memorized, or at minimum
noting the limitation plainly) — exactly the kind of limitation this
project has consistently stated rather than hidden (OAuth2 being
disabled in the full-deployment harness, the GET handler's known
partial-fix caveat, etc.).

## Summary / decision needed

| | Level 1 (patch text only) | Level 2 (compile + runtime confirmed) |
|---|---|---|
| Code change | ~1 line (or a CLI flag) | Dockerfile + patch-application step, reusing existing harness |
| Effort | Minutes | Comparable to the original DELETE-handler harness build |
| Evidence tier produced | Below this project's own standard | Matches the existing free5GC evidence tier |
| Worth reporting alone? | No — would read as a regression in rigor | Yes |

Recommendation: skip Level 1 as an end state (fine as a quick
smoke-test, not as a result), go straight to scoping Level 2 if this is
approved, targeting the GET-collection handler first with the local
Ollama provider. Also recommend closing the missing
`NO_PAID_BACKEND`-equivalent gap in `src/reachability/providers.py`
before any paid provider is ever pointed at this pipeline, independent
of free5GC.

No implementation has started. This document is the complete scoping
deliverable requested.
