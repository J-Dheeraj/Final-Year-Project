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

## Update: Claude backend (6 named models, both arms)

Re-run both arms (synthetic bug, real-CVE baseline) against the same 6
named Claude models used throughout this update pass.

**Synthetic bug arm**: 4/6 compiled. Investigated the 2 failures before
accepting them as model capability results: `claude-sonnet-5` failed
with the same consistent `exit 1` pattern seen throughout this update.
`claude-opus-4-7`'s failure was traced to something else entirely - its
raw diff showed an injected `<system-reminder>` block about a local
`claude-mem` plugin outage ("Provider reported the inference allowance
exhausted") prepended, unfenced, directly into the model's completion
text, corrupting the Go source (`non-declaration statement outside
function body`). Confirmed this was isolated to this one call by
checking every other model's diff for the same contamination string -
none found. Not a genuine model failure; a local environment artifact
polluting the subprocess output this specific time.

| Model | Compiles (synthetic bug) |
|---|---|
| `claude-haiku-4-5-20251001` | yes |
| `claude-sonnet-4-6` | yes |
| `claude-sonnet-5` | NO (exit 1, $0) |
| `claude-opus-4-6` | yes |
| `claude-opus-4-7` | NO (claude-mem injection artifact, not a real failure) |
| `claude-opus-4-8` | yes |

Total measured cost: $1.2046.

**Real-CVE baseline arm (matched comparison)**: 5/6 compiled -
`claude-sonnet-5` the only failure, same consistent pattern. Once the
`opus-4-7` contamination artifact is set aside (not a genuine capability
result either way), both arms show the same 5/6 success rate against
the matched model set - still no observed memorization advantage for
the real, potentially-trainable-on CVE over the synthetic, provably-
never-disclosed one, now with a larger model sample than the original
small-local-model comparison.

| Model | Compiles (real CVE) | Cost (USD) |
|---|---|---|
| `claude-haiku-4-5-20251001` | yes | $0.0552 |
| `claude-sonnet-4-6` | yes | $0.1494 |
| `claude-sonnet-5` | NO (exit 1) | $0 |
| `claude-opus-4-6` | yes | $0.2480 |
| `claude-opus-4-7` | yes | $0.3427 |
| `claude-opus-4-8` | yes | $0.3882 |

Total measured cost: $1.1835.

## Update: AIxTech gateway backend (10 named models, both arms)

Re-run both arms via `--backend aixtech` against the user's 10 requested
model names. Only 4 resolve on this gateway key
(`claude-haiku-4-5-20251001`, `claude-haiku-5-5`, `claude-sonnet-4-6`,
`claude-sonnet-5`); the other 6 (`claude-sonnet-5-5`, all 5
`claude-opus-*`) return 403 `team_model_access_denied` on both arms,
recorded as the model's error rather than silently omitted.

**Both arms: 4/4 reachable models compiled clean** - no failures, no
contamination artifacts this time. Still no observed memorization
advantage for the real CVE over the synthetic twin: the same 4 models
succeed on both arms with this backend, extending the existing
"no advantage observed" finding to a gateway-routed Claude access path
in addition to `claude -p`.

| Model | Synthetic compiles | Real-CVE compiles | Synthetic tok (in/out) | Real-CVE tok (in/out) | Synthetic dur. | Real-CVE dur. |
|---|---|---|---|---|---|---|
| `claude-haiku-4-5-20251001` | yes | yes | 664 / 484 | 639 / 462 | 3.22s | 4.01s |
| `claude-haiku-5-5` | yes | yes | 920 / 727 | 877 / 733 | 3.10s | 3.05s |
| `claude-sonnet-4-6` | yes | yes | 665 / 479 | 640 / 457 | 5.47s | 5.06s |
| `claude-sonnet-5` | yes | yes | 918 / 662 | 875 / 622 | 5.11s | 4.87s |
| `claude-sonnet-5-5` | 403 | 403 | — | — | 0.20s | 0.12s |
| `claude-opus-4-6` | 403 | 403 | — | — | 0.76s | 0.08s |
| `claude-opus-4-7` | 403 | 403 | — | — | 0.09s | 0.12s |
| `claude-opus-4-8` | 403 | 403 | — | — | 0.11s | 0.07s |
| `claude-opus-5` | 403 | 403 | — | — | 0.10s | 0.06s |
| `claude-opus-5-5` | 403 | 403 | — | — | 0.06s | 0.10s |

Token counts and duration are real, measured per call. Dollar cost is
**not reported by this gateway** (see `docs/METHODOLOGY_PITFALLS.md`
#15) - no guessed per-token price is substituted for it.

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
