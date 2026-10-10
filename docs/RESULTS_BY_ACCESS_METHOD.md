# Results, categorized by how the model was actually reached

`docs/RESULTS_SUMMARY.md` indexes results by experiment. This page
cuts across that the other way: by the literal mechanism used to reach
the model under test. The two indexes describe the same underlying
data - this one exists because "which access path produced this
number" is a different, equally real question, and the two backends
that share a CLI binary (`claude -p`) are easy to conflate if you
don't look closely.

## 1. Run through a Claude API key (direct `anthropic` SDK, bearer token)

`AIxTechGatewayProvider` (`src/reachability/providers.py`), added
2026-10-09: calls the AI Singapore ("AIxTech") LLM gateway directly via
the `anthropic` Python SDK, authenticated with `ANTHROPIC_AUTH_TOKEN` +
`ANTHROPIC_BASE_URL` (bearer token), not `claude -p` and not a
`claude -p`-style local CLI session. This is the only category with a
real `anthropic.Anthropic().messages.create()` call in the process -
every other "Claude" category below shells out to a CLI instead.

Run across all 4 reachability experiment families, all 10 of the
user's requested model names (only 4 resolve on this gateway key):

- `docs/CATALOG_BYPASS_PROBE_RESULTS.md` ("Update: AIxTech gateway backend")
- `docs/OPENEMR_LLM_PATCH_RESULTS.md` ("Update: AIxTech gateway backend")
- `docs/OPENEMR_BYPASS_PROBE_RESULTS.md` ("Update: AIxTech gateway backend")
- `docs/FREE5GC_MEMORIZATION_CONTROL_RESULTS.md` ("Update: AIxTech gateway backend")
- `docs/FREE5GC_MULTITURN_BYPASS_PROBE_RESULTS.md` ("Update: AIxTech gateway backend")

Real per-model input/output tokens and wall-clock duration captured
for every call, including the 403-denied ones. No dollar cost - this
gateway's API response never includes one, and no per-token price was
guessed for these model names. `docs/METHODOLOGY_PITFALLS.md` #15.

## 2. Run through Claude Code (agentic backend swap in the main pipeline)

**Zero valid results exist in this category as of 2026-10-09.** This
is the one honest gap in this list: `docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md`
defines a frozen protocol to run the main `cve_pipeline.py` (not the
reachability side-experiments) with `_call_live_model()`'s backend
swapped from Ollama to the `claude` CLI - literally what `claude
--version` reports itself as (`2.1.280 (Claude Code)`). The one
execution attempt (2026-09-25) silently fell back to Ollama for every
single call, because the local `claude` CLI's OAuth session had
expired and `_call_live_model()` treats an empty Claude response as
"fall through to Ollama" with no warning logged - a real pipeline
observability gap, not yet fixed. That run's honest-but-mislabeled
Ollama data is recorded as **Round 6** in `reports/LIVE_LLM_CATALOG_RUN.md`,
under category 5 below, not here. See
`docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md`'s own status banner for the
full root-cause trace. The protocol itself remains valid and ready to
execute once the `claude` CLI is re-authenticated.

## 3. Run through Claude CLI (`claude -p`, `ClaudeCLIProvider`)

Shells out to the `claude` CLI's own authenticated session
(`claude -p <prompt> --output-format json`) - same binary as category
2, but used here as the reachability experiment scripts' model
backend, not as the main pipeline's backend. This is what every
"Update: Claude backend" section across this project's docs refers to.
Real, measured dollar cost (`total_cost_usd` from the CLI's own JSON
output) - the only category with an actual billed-dollar figure.

Results across 6 named models (haiku-4.5, sonnet-4.6, sonnet-5,
opus-4.6/4.7/4.8):

- `docs/CATALOG_BYPASS_PROBE_RESULTS.md` ("Update: Claude backend")
- `docs/OPENEMR_LLM_PATCH_RESULTS.md` ("Update: Claude backend")
- `docs/OPENEMR_BYPASS_PROBE_RESULTS.md` ("Update: Claude backend")
- `docs/FREE5GC_MEMORIZATION_CONTROL_RESULTS.md` ("Update: Claude backend")
- `docs/FREE5GC_MULTITURN_BYPASS_PROBE_RESULTS.md` ("Update: Claude backend")
- `docs/FREE5GC_CLAUDE_BYPASS_PROBE_RESULTS.md` (11 Claude models, including
  2 outright safety refusals from `claude-opus-5`/`claude-opus-5-5`)
- `docs/FREE5GC_LLM_CLAUDE_SWEEP_RESULTS.md` (first 3-model proof point)
- `docs/FREE5GC_LLM_CLAUDE_SWEEP_EXTENDED_RESULTS.md` (extended to 5 models,
  one refused by Anthropic's own real-time cyber safeguards)

Total measured cost across this category: **$29.53** (per
`docs/RESULTS_SUMMARY.md`'s closing line), plus the Claude bypass-probe
sweep's own separately-tracked spend.

## 4. Run through Codex CLI (`codex exec`, `CodexCLIProvider`)

Shells out to the authenticated Codex CLI in a read-only, ephemeral
sandbox session (`codex exec --ephemeral --sandbox read-only --json`),
using the user's ChatGPT/Codex authentication rather than an API key -
deliberately kept separate from every Claude/Anthropic category per
the user's explicit 2026-09-25 direction (`docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md`'s
own intro: *"Codex is explicitly out of scope for this protocol...
give them a separate document"*).

- `docs/FREE5GC_CODEX_SWEEP_2026-10-07.md`: 18 model IDs attempted
  (GPT-3-era through GPT-6/o-series names), **7/18 patches
  runtime-confirmed across all four handlers**, bypass phase executed
  4 proposals with **0 genuine bypasses**. Per-call duration and
  prompt/output token usage captured via the JSONL event stream.

## 5. Run through Ollama models (local, free, `OllamaProvider`)

Local open-weight models via Ollama's native `/api/chat` endpoint -
genuinely free and private, the baseline every other category is
compared against. Two distinct bodies of work share this category:

**The main pipeline's own 6-round live-model catalog run**
(`reports/LIVE_LLM_CATALOG_RUN.md`) - all 6 rounds ran on Ollama
(`qwen2.5-coder:7b` throughout), including Round 6, which was
*intended* to be the Claude Code comparison (category 2) and is
recorded here instead, honestly relabeled, because that's what it
actually measured.

**Every reachability experiment's original/baseline sweep**, predating
the Claude/Codex/AIxTech re-runs added later:

- `docs/FREE5GC_LLM_MODEL_SWEEP_RESULTS.md` (8 installed models, 6/8 confirmed)
- `docs/FREE5GC_LLM_PATCH_RESULTS.md` (first proof point, `qwen2.5-coder:7b`)
- `docs/FREE5GC_BYPASS_PROBE_RESULTS.md` (0/7 genuine bypasses)
- `docs/FREE5GC_MULTI_RUN_VARIANCE_RESULTS.md` (2 models x 3 runs, stability check)
- `docs/FREE5GC_MEMORIZATION_CONTROL_RESULTS.md` (original 4-model pass)
- `docs/FREE5GC_MULTITURN_BYPASS_PROBE_RESULTS.md` (original 8-model pass)
- `docs/OPENEMR_LLM_PATCH_RESULTS.md` (original 8-model pass, 1/7 clean)
- `docs/OPENEMR_BYPASS_PROBE_RESULTS.md` (original pass)
- `docs/CATALOG_BYPASS_PROBE_RESULTS.md` (original 8-model pass, 48 pairs)
- `docs/PATCH_QUALITY_SCORING_RESULTS.md` (scores the Ollama-generated patches)
- `docs/FREE5GC_PATCH_REPEAT_RESULTS.md` (4 models x 3 runs, 9/12 confirmed)
- `docs/FREE5GC_ALL_OLLAMA_SWEEP_2026-10-06.md` (all 8 installed models, 5/8 confirmed)
- `docs/FREE5GC_ALL_OLLAMA_BYPASS_2026-10-06.md` (all 8 installed models, 0/7)

Every call in this category is genuinely free (`cost_usd: 0.0`,
measured not estimated) and runs entirely on localhost - no network
egress beyond `127.0.0.1:11434`.

## Reading this against `docs/RESULTS_SUMMARY.md`

That page's per-experiment tables already show a Backend column
(Ollama / Claude / AIxTech gateway / Codex); this page is the same
facts, re-cut so "what actually executed the call" is the primary
axis instead of "which experiment." Use `RESULTS_SUMMARY.md` to answer
"what happened in experiment X"; use this page to answer "what has
this project actually measured through access path Y."

## 6. Run through the OpenAI API (`OpenAIProvider`)

These results used the project-scoped OpenAI API key with the OpenAI SDK,
not Codex CLI authentication, ChatGPT web access, Claude, AIxTech, or Ollama.
The provider records model identity, input/output tokens, wall-clock duration,
and estimated cost where a published rate is known. Deprecated models,
cybersecurity-policy refusals, connection failures, compile failures, and
interrupted Docker runs remain visible as their actual outcomes.

The OpenAI API results are:

- `reports/reachability/catalog_bypass_probe_openai.json`: six-CVE catalogue,
  138 model/CVE pairs; 0 genuine bypasses after auditing 12 raw XSS-oracle
  positives.
- `reports/reachability/openemr_bypass_probe_openai.json`: 23 models; 0/23
  bypasses.
- `reports/reachability/openemr_llm_patch_openai.json`: 23 models; 16/23
  fully working gates.
- `reports/reachability/free5gc_sweep_bypass_openai_openai-2026-10-10-bypass.json`:
  23 models; 0/23 bypasses against the real patched deployment.
- `reports/reachability/free5gc_sweep_patch_openai_combined_2026-10-10.json`:
  all 23 models completed across the initial, continuation, and final single-model
  runs; 18/23 full four-handler validation pipeline passes (one model-generated handler plus three deterministic materializations), five compile failures,
  and one deprecated model. The source reports remain preserved separately.

The implementation and reports were pushed in commits `4aa4964`, `af8d41e`,
and `d4ac713`.

---

See `docs/FINAL_EVIDENCE_SUMMARY.md` for the one-page bounded conclusion
drawn across all 6 categories above - headline numbers, what has and
hasn't been shown, and what remains explicitly out of scope.


Repeatability and final presentation artifacts: [`docs/FREE5GC_OPENAI_REPEATABILITY_RESULTS.md`](docs/FREE5GC_OPENAI_REPEATABILITY_RESULTS.md), [`docs/SUPERVISOR_BRIEFING.md`](docs/SUPERVISOR_BRIEFING.md), and [`docs/FINAL_DEMONSTRATION_CHECKLIST.md`](docs/FINAL_DEMONSTRATION_CHECKLIST.md).


XSS public results use the independent headless-browser replay in `reports/reachability/catalog_xss_browser_replay.json`; the legacy marker result remains available as `raw_oracle_positive`.
