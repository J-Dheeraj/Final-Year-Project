# free5GC memorization control: can a model fix a bug it has never seen?

## Why this experiment exists

Every prior free5GC LLM-patch result
(`docs/FREE5GC_LLM_PATCH_RESULTS.md`, `docs/FREE5GC_LLM_MODEL_SWEEP_RESULTS.md`,
the Claude sweeps) carries the same stated limitation: a model that
successfully fixes CVE-2026-40248 (upstream fix commit `86686276`,
public well before this project started) might be pattern-matching a
memorized copy of that real commit rather than genuinely reasoning about
the code in front of it. Nothing in those results could tell the two
apart.

## Method

`HandleCreateAuthenticationStatus` is a real handler in the same
vendored free5GC/udr source file as the four CVE-2026-40248 handlers,
but is **not** one of them, and is written correctly in the real,
unmodified source. `src/reachability/run_memorization_control.py`
synthetically deletes the one `return` statement from its "Malformed
request syntax" validation guard, producing the exact same bug *shape*
the real CVE heuristic looks for (CWE-285: an early-exit validation
block writes an HTTP response but falls through to privileged logic
afterward) in a function that has never actually been buggy in any
public commit. Two sanity checks gate the experiment before any model is
asked anything: the real, unmodified function must NOT be flagged by
`find_missing_return_after_response` (confirming the control's baseline
is genuinely clean), and the injected copy MUST be flagged (confirming
the injection actually created the intended bug class). Both passed.

Because this vulnerable function text was created fresh by this script,
in a function that was never vulnerable in real life, no training
corpus can contain its fix - unlike the real CVE, there is no commit to
recall.

Each model was asked to patch the synthetic bug (`generate_patch()`,
unchanged from every other free5GC LLM-patch experiment), then the patch
was compile-verified by splicing it into a live clone of the real
upstream module at the real pre-fix commit (`86686276^`) - same
methodology, same tier (compile-verification, not full runtime
confirmation - this handler's data path was never wired into the Docker
full-deployment harness) as `run_free5gc_llm_patch.py`'s original result.

`src/reachability/run_memorization_control_baseline.py` re-runs the
*real* CVE handler through the identical pipeline, with the identical
models, in the same session - the matched comparison arm.

## A real bug found and fixed before any result was trusted

The first run reported 0/4 compiling fixes, including two models whose
error was "the model's patch doesn't match the injected function" even
though the model's generated diff looked correct on inspection. Traced
to a real bug in the harness: the synthetic case file was written with
Python's default text-mode translation, turning `\n` into `\r\n` on
Windows; the reachability pipeline's tree-sitter parser then read the
file back byte-for-byte with those `\r\n` sequences intact, so the
in-memory function-body text it handed to `generate_patch()` no longer
byte-matched the `\n`-only strings this script used to splice into the
real upstream clone. Fixed by writing the synthetic file with
`newline="\n"` explicitly. Re-verified empirically (not just asserted)
that the pipeline's extracted function body now matches byte-for-byte
before re-running anything against a model.

## Model availability note

The 8 Ollama models used in every prior free5GC sweep
(`deepseek-coder-v2:16b`, `codellama:13b`, `gemma2:9b`, `mistral:7b`,
`llama3.1:8b`, `qwen2.5-coder:7b/3b/1.5b`) are no longer pulled on this
machine - `ollama list` only shows `llama3.2:1b`, `llama3.2:3b`,
`qwen3:8b`, `deepseek-r1:14b`, `nomic-embed-text` as of this run,
consistent with this project's repeated disk/OOM constraints noted in
earlier sweeps. Re-pulling the original 8 (several multi-GB) was judged
not worth the time/disk cost for one control experiment. This means the
model population here is **not** the same as the earlier 8-model
sweeps - both arms of this control use the same (different, smaller)
model set, so the comparison between them is still valid; comparison
against the old 8-model numbers is not attempted.

## Results

| Model | Synthetic bug (never disclosed) | Real CVE-2026-40248 (public commit exists) |
|---|---|---|
| `llama3.2:1b` | **compiles** | fails to compile (`problemDetails` type/undefined errors) |
| `llama3.2:3b` | fails to compile (`problemDetail.Title undefined`) | **compiles** |
| `qwen3:8b` | timed out (no result either arm) | timed out (no result either arm) |
| `deepseek-r1:14b` | timed out (no result either arm) | timed out (no result either arm) |

1/4 compiling on the synthetic bug; 1/4 compiling on the real CVE - and,
among the two models that actually completed both arms, the one that
succeeded on each arm was different, not the same model succeeding on
both. The two reasoning-style models (`qwen3:8b`, `deepseek-r1:14b`)
timed out identically on both arms (this project's providers.py already
documents `think:false` not fully suppressing these models' slow
chain-of-thought generation on this hardware - a known environmental
constraint, not a new finding), so they contribute no information either
way.

## Honest interpretation

With only 2 of 4 models producing any result at all, this is a small
sample - not strong enough to make a general claim about memorization
across models. But it is a real, controlled comparison, and what it
shows is the opposite of what a strong-memorization hypothesis would
predict: neither completing model did better on the real, potentially-
memorized CVE than on the synthetic, provably-never-disclosed twin of
the same bug class. If training-data recall of commit `86686276` were
doing most of the work in this project's earlier free5GC patch results,
a consistent real-CVE advantage would be the expected signature; it
isn't present here. This is reported as a modest, appropriately-hedged
data point against the memorization explanation, not as proof it didn't
happen - a larger model sample (once more Ollama models are pulled, or
against the Claude backend) would make this a stronger result either way.

## Scope, stated plainly

- Compile-verification only, same tier as this handler family's very
  first free5GC proof point - not runtime-confirmed. Standing up this
  handler's own MongoDB-backed data path in the Docker full-deployment
  harness was judged out of scope for one control experiment.
- Small model sample (2 of 4 completed), on different hardware
  availability than every prior free5GC sweep in this project.
- A single run per model, not multiple - see the separate multi-run
  variance work for whether a single compile/fail result is stable.

## Artifacts

- `src/reachability/run_memorization_control.py` - synthetic-bug arm
- `src/reachability/run_memorization_control_baseline.py` - matched real-CVE arm
- `src/reachability/examples/memorization_control/api_datarepository_synthetic_vulnerable.go` - the injected case file
- `reports/reachability/free5gc_memorization_control.json/.md`
- `reports/reachability/free5gc_memorization_control_baseline.json/.md`
