
# free5GC LLM patch quality scoring: beyond pass/fail

## Why this experiment exists

`docs/SCOPE_AND_LIMITATIONS.md` names an explicit, unmeasured gap: this
project has only ever reported a binary outcome per model (compiles +
runtime-confirmed, or not) for the free5GC LLM patches, never how
CLOSE a passing patch actually is to the real upstream fix. A patch
that compiles and passes the runtime check could still look nothing
like the real fix - this experiment measures that for the first time,
over patches already generated and already compile/runtime-confirmed
in prior sessions. No new model calls; pure analysis of files already
on disk.

## Method

`src/reachability/score_patch_quality.py` extracts
`HandleApplicationDataInfluenceDataSubsToNotifyGet` from each of the 14
already-generated `api_datarepository_llm_patched*.go` files and from
the real upstream fix's own version of the same function
(`src/reachability/examples/free5gc_case_study/api_datarepository_patched.go`),
then scores: `difflib.SequenceMatcher` ratio (line-based), lines
added/removed vs. the real fix, and whether the patch uses the real
fix's own minimal shape (the real fix adds exactly one `return`
statement and changes nothing else).

## An unexpected clustering, checked before trusting the scores

9 of 14 patches scored a perfect 1.0 similarity (byte-identical to the
real fix). Whole-file MD5 hashes showed these aren't 14 independent
values but two clusters plus the default file:

- `api_datarepository_llm_patched.go` (qwen2.5-coder:7b, the original
  single-model run), `..._gemma2-9b.go`, and `..._claude-haiku-4-5-20251001.go`
  are byte-identical whole files.
- `..._claude-opus-4-6/4-7/4-8/5-5.go` and `..._claude-sonnet-4-6/5-5.go`
  (6 distinct Claude model names) are ALSO byte-identical to each
  other, in a separate cluster from the first.

Before accepting this as genuine convergence rather than a generation
bug (e.g., several model names secretly resolving to the same
underlying model, or a shared-output-path collision), checked the
already-recorded per-model cost data from the original sweeps
(`free5gc_llm_claude_sweep.json`/`_extended.json`): each of the 6
"identical" Claude models has a distinct, real recorded cost
(`$0.1494` to `$0.3460`, `claude-sonnet-5-5` separately at `$1.1334` in
the un-clustered earlier run) - different cache-creation/token patterns
per call, which is strong evidence these were genuinely separate API
calls to the respective models, not one cached response reused across
several "different" model names.

**Most likely explanation, stated as a probability judgment, not a
certainty**: the target function is short, and the task given to every
model was "add the fix, keep everything else the same" against a
function where the correct, idiomatic fix is a single `return`
statement inserted at one obvious place with the surrounding code's own
existing indentation - there is really only one sensible way to write
that. Byte-identical convergence across several models, especially
within the same vendor's closely-related model family (the Claude
cluster) and between two small code-specialized models plus one Claude
model (the other cluster), is a plausible, even expected outcome for a
task this narrow - not evidence of a measurement bug on its own.
Flagged here for anyone who wants to investigate further (e.g.
comparing raw completion text/metadata beyond cost alone), not
asserted as fully resolved.

## Results

| Model | Diff similarity to real fix | Lines added | Lines removed | Minimal fix shape |
|---|---|---|---|---|
| `qwen2.5-coder:7b` (original run) | 1.0000 | 0 | 0 | yes |
| `claude-haiku-4-5-20251001` | 1.0000 | 0 | 0 | yes |
| `gemma2:9b` | 1.0000 | 0 | 0 | yes |
| `claude-opus-4-6` | 1.0000 | 0 | 0 | yes |
| `claude-opus-4-7` | 1.0000 | 0 | 0 | yes |
| `claude-opus-4-8` | 1.0000 | 0 | 0 | yes |
| `claude-opus-5-5` | 1.0000 | 0 | 0 | yes |
| `claude-sonnet-4-6` | 1.0000 | 0 | 0 | yes |
| `claude-sonnet-5-5` | 1.0000 | 0 | 0 | yes |
| `codellama:13b` | 0.9851 | 0 | 1 | no |
| `qwen2.5-coder:1.5b` | 0.9552 | 1 | 2 | no |
| `llama3.1:8b` | 0.9412 | 2 | 2 | no |
| `qwen2.5-coder:3b` | 0.9412 | 2 | 2 | no |
| `mistral:7b` | 0.9118 | 3 | 3 | no |

## Honest interpretation

9/14 (64%) achieved a byte-perfect match to the real fix - for a bug
this narrow, "compiles and runtime-confirms" and "textually identical
to the real fix" turn out to coincide most of the time, which is a
genuinely reassuring, more specific claim than pass/fail alone
supports. The remaining 5 (all smaller/weaker Ollama models -
`codellama:13b`, `qwen2.5-coder:1.5b/3b`, `llama3.1:8b`, `mistral:7b`)
achieved the same RUNTIME outcome through small but real textual
deviations (1-3 extra added/removed lines each) - still passing every
check this project's harness runs, but via a less minimal rewrite than
the real fix. None of the 5 deviations were large rewrites; the
gradient here is "slightly less minimal," not "a different approach
entirely" - a real, if modest, quality signal pass/fail never surfaced
before this.

## Scope, stated plainly

- Diff-similarity is computed only on the ONE target function every
  model was asked to patch, not the whole file or the other 3
  rule-based-patched handlers.
- Line-based `difflib` similarity is a textual proxy, not a semantic
  one - two patches achieving the same runtime behavior through
  different code could score very differently, and vice versa (though
  for this specific bug class, textual and semantic similarity are
  closely correlated, since the fix is a single added statement).
- Multi-payload/benign-path testing "at scale" (the other half of this
  brainstormed item) was not attempted - every patch here was already
  validated against the existing 4-check `run_case()` sequence in
  prior sessions; running many MORE payload variants per patch is a
  natural, separate follow-up.

## Artifacts

- `src/reachability/score_patch_quality.py`
- `reports/reachability/patch_quality_scoring.json/.md`
