# Evidence ledger: October 2026 R&D baseline

This ledger is the source-of-truth summary for the recorded free5GC local
model sweep. Counts below are derived from
`reports/reachability/free5gc_llm_model_sweep.json`, not from prose summaries.

## Research questions and acceptance criteria

| Question | Acceptance evidence |
|---|---|
| Can the system dynamically confirm known vulnerability behaviour? | A vulnerable real deployment exposes the expected four-handler behaviour and the patched deployment records a complete runtime verdict. |
| Can generated patches survive validation? | The candidate compiles against the pinned upstream source, passes all four runtime checks, and preserves the benign path. |
| How stable are results across models and runs? | Each attempt has a unique run ID, preserved source/log manifest, and a reported confirmation rate; failures remain in the denominator. |

## Recorded local-model sweep

| Model | Generation/compile | Runtime verdict | Evidence tier | Interpretation |
|---|---|---|---|---|
| `deepseek-coder-v2:16b` | Did not load | Not reached | Environment-limited | 45 GB allocation failure; no model-quality conclusion. |
| `codellama:13b` | Compiled | `confirmed_fix_all_four_handlers` | Runtime-confirmed | All four handler checks and benign path passed. |
| `gemma2:9b` | Compiled | `confirmed_fix_all_four_handlers` | Runtime-confirmed | All four handler checks and benign path passed. |
| `mistral:7b` | Compiled | `confirmed_fix_all_four_handlers` | Runtime-confirmed | All four handler checks and benign path passed. |
| `llama3.1:8b` | Compiled | `confirmed_fix_all_four_handlers` | Runtime-confirmed | All four handler checks and benign path passed. |
| `qwen2.5-coder:7b` | Compiled | `confirmed_fix_all_four_handlers` | Runtime-confirmed | All four handler checks and benign path passed. |
| `qwen2.5-coder:3b` | Compiled | `confirmed_fix_all_four_handlers` | Runtime-confirmed | All four handler checks and benign path passed. |
| `qwen2.5-coder:1.5b` | Compiled | `partial_or_inconclusive` | Compile-only plus failed runtime validation | Collection GET leak remained exploitable. |

### Counts

- 8 models listed.
- 7 models reached compilation.
- 6 models were runtime-confirmed across all four handlers.
- 1 model compiled but failed runtime validation.
- 1 model failed before generation because of an environment memory limit.

The safe claim is therefore **6/8 models in this recorded local sweep were
runtime-confirmed**, with one genuine negative result and one unevaluated
environment-limited model. Earlier documents that say 7/8 must be read as
historical wording and are being reconciled before the research freeze.

## Required final-study fields

The October repeated patch-generation study must preserve, per model and run:

- `experiment_id`, `model`, `run`, and pinned upstream commit;
- `generation_outcome` (`llm_live_success` or `llm_live_failed`);
- compile result, applied patch count, and compiler error;
- Docker build result and all four runtime verdicts;
- benign-path result;
- patch diff, generated source, logs, duration, and cost where available.

