# free5GC LLM patch: all-local-models sweep

Extends `docs/FREE5GC_LLM_PATCH_RESULTS.md`, which explicitly flagged
"single model, single run" as an unaddressed limitation. This runs
**every** Ollama model pulled on this machine - not just
`qwen2.5-coder:7b` - against the same target
(`HandleApplicationDataInfluenceDataSubsToNotifyGet`, CWE-285) and
carries each one through the same two gates: compile-verification
against a live clone of the real `free5gc/udr` upstream, then runtime
confirmation against the real Docker stack (real MongoDB, real free5GC
NRF), exactly like the single-model result. Produced by
`free5gc_full_deployment/run_model_sweep.py`.

## A real environment bug found and fixed along the way

The sweep initially failed on **every** model with `model not found`
(404), despite `ollama list` showing all 8 models present. Root cause:
this machine has two separate processes listening on port 11434 -
`ollama.exe` (the real, native Windows app, bound to `127.0.0.1:11434`,
holding the 8 target models) and `wslrelay.exe` (WSL2's port-forwarding
relay, bound to `[::1]:11434`, forwarding a *different* Ollama instance
running inside WSL2 for an unrelated project on this machine, with a
completely different model catalog). `http://localhost:11434`
(`OllamaProvider`'s default) resolves to `::1` first on this machine, so
every request was silently landing on the wrong server. Fixed by setting
`OLLAMA_BASE_URL=http://127.0.0.1:11434` explicitly for the sweep - not
a code bug, a real, pre-existing environment conflict between two
unrelated local services sharing a well-known port.

A second robustness gap was found and fixed during the first real
attempt: `mistral:7b`'s completion call exceeded `OllamaProvider`'s
240s timeout and raised an uncaught `TimeoutError`, crashing the whole
sweep script before any results were persisted. Fixed two ways: widened
`generate_patch`'s exception handling in
`prepare_llm_patched_source.materialize_and_verify()` to catch any
exception (not just `RuntimeError`) around the one network call that can
legitimately time out under CPU inference, and made the sweep write its
report **after every model** instead of only at the end, so one model's
crash can never erase already-completed results for the others.

## Results

| Model | Compiles | Applied/4 | Runtime verdict |
|---|---|---|---|
| `deepseek-coder-v2:16b` | **NO** - out-of-memory loading the model (45 GB buffer requested) | 0/4 | not reached |
| `codellama:13b` | yes | 4/4 | **confirmed_fix_all_four_handlers** |
| `gemma2:9b` | yes | 4/4 | **confirmed_fix_all_four_handlers** |
| `mistral:7b` | yes | 4/4 | **confirmed_fix_all_four_handlers** |
| `llama3.1:8b` | yes | 4/4 | **confirmed_fix_all_four_handlers** |
| `qwen2.5-coder:7b` | yes | 4/4 | **confirmed_fix_all_four_handlers** |
| `qwen2.5-coder:3b` | yes | 4/4 | **confirmed_fix_all_four_handlers** |
| `qwen2.5-coder:1.5b` | yes | 4/4 | **partial_or_inconclusive** |

Full machine-readable report:
`reports/reachability/free5gc_llm_model_sweep.json` (includes every
model's diff and per-check runtime breakdown). Per-model evidence
(`*_process.log`, container logs) in `free5gc_full_deployment/evidence/`.

### `deepseek-coder-v2:16b`: a real hardware limitation, not a code failure

```
llama-server reported out-of-memory during startup:
ggml_backend_cpu_buffer_type_alloc_buffer: failed to allocate buffer of size 45298483200
```

This model simply would not load on this machine's available RAM at its
default context size. This is an environment constraint, not evidence
about the model's patching ability - it was never actually asked to
generate anything.

### `qwen2.5-coder:1.5b`: compiles, but does NOT fix the bug - a genuine negative result

This is the one case this sweep adds that the single-model result
didn't have: a model that produces **syntactically valid Go that
compiles cleanly, but is not a correct fix**. Its generated diff:

```diff
@@ -29,4 +29,5 @@
 	}

 	s.Processor().ApplicationDataInfluenceDataSubsToNotifyGetProcedure(c, dnn, snssai, internalGroupId, supi)
+	c.JSON(http.StatusOK, "Response sent to client after validation") // Add a response to mimic the original behavior
 }
```

Instead of inserting `return` after either early-exit validation block
(the actual bug), the 1.5B model appended an unrelated, unreachable-in-
practice extra response line at the very end of the function body. It
compiles. It does nothing to close the vulnerability. The runtime
harness caught this precisely: `collection_get_leak_fixed: false` -
the collection-GET leak this handler is responsible for is still
exploitable - while the other three checks pass only because they're
fixed by the (separate, already-correct) rule-based patches applied to
the *other* three handlers, not by this model's patch at all.

**This is exactly why compile-verification alone is not sufficient
evidence**, and why this project's standard has consistently been
runtime confirmation, not just "it builds." A compile-only check would
have reported this model's patch as equally successful as the other
seven; the runtime harness shows it is not.

### Observed non-determinism (not a new finding, but directly confirmed here)

Re-running `qwen2.5-coder:7b` (already runtime-confirmed in
`docs/FREE5GC_LLM_PATCH_RESULTS.md`) produced a semantically identical
but textually different patch - the same two `return` statements in the
same places, with an extra trailing comment added by the model on this
run. Harmless here, but a concrete demonstration that a single run per
model (as both this sweep and the original result are) does not capture
run-to-run variance; a model could just as easily vary into an incorrect
patch on a different run, the way `qwen2.5-coder:1.5b` did on this one.

## What this still does not resolve

- **Memorization risk** - still not controlled for, same limitation as
  the single-model result. A model reproducing the real, public fix from
  training data rather than reasoning about the control flow remains
  indistinguishable from genuine derivation in this setup.
- **One run per model.** `qwen2.5-coder:1.5b`'s failure and
  `qwen2.5-coder:7b`'s harmless variance both show outcomes can differ
  run to run; a rigorous comparison would run each model multiple times
  and report a pass rate, not a single pass/fail.
- **`deepseek-coder-v2:16b` was never actually evaluated** - it failed
  before generating anything, due to this machine's RAM, not its
  patching ability.

## Files

- `free5gc_full_deployment/run_model_sweep.py` - the sweep driver.
- `free5gc_full_deployment/udr_build/prepare_llm_patched_source.py` -
  made reusable (`materialize_and_verify(model)`) and more robust
  (broad exception handling around the LLM call).
- `free5gc_full_deployment/udr_build/Dockerfile.llm` - added
  `ARG PATCHED_FILE` so one Dockerfile builds any model's patched source.
- `free5gc_full_deployment/udr_build/api_datarepository_llm_patched_<model>.go` -
  one materialized, compile-verified source file per model that compiled.
- `reports/reachability/free5gc_llm_model_sweep.json` /`.md` - the
  consolidated machine-readable and summary reports.
