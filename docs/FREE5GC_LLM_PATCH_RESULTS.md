# free5GC LLM-generated patch: results (Level 2, compile-verified half)

Implements the Level 2 plan from `docs/FREE5GC_LLM_PATCH_SCOPE.md`:
generate a real LLM patch for the one free5GC handler already documented
as a rule-based-patcher weak spot, and compile-verify it against a live
clone of the real upstream module. Produced by
`src/reachability/run_free5gc_llm_patch.py`.

**Status: compile-verified only.** Runtime confirmation (swapping this
patch into the Docker-based full-deployment harness) is NOT done here -
Docker Desktop is failing to start on this machine (`initializing
Inference manager: ... The system cannot find the file specified`,
2026-10-05), a real, pre-existing environment issue unrelated to this
code. That half of Level 2 remains open and is tracked, not silently
dropped.

## Setup

- **Target**: `HandleApplicationDataInfluenceDataSubsToNotifyGet`, the
  collection-level handler `docs/REACHABILITY.md` already documents as
  the one case where the deterministic rule-based patcher inserts only
  one of the two `return` statements the real root cause needs.
- **Provider**: local Ollama, model `qwen2.5-coder:7b` - free, no API
  key, no `NO_PAID_BACKEND` conflict (pulled models already on this
  machine: `deepseek-coder-v2:16b`, `codellama:13b`, `gemma2:9b`,
  `mistral:7b`, `llama3.1:8b`, `qwen2.5-coder:{7b,3b,1.5b}`).
- **Triage/verify**: left on the deterministic mock path, reusing the
  exact, already-verified finding for this handler - only the patch
  stage was handed to the LLM, per the scoping doc's design (isolates
  what changed to exactly the patch-generation step).
- **Prompt fix made first**: `src/reachability/patch.py`'s prompt
  template was hardcoded for a C target (` ```c ``` ` fence, "C
  developer" system prompt) despite free5GC being Go. Added a
  Go-specific system prompt and a `{lang}` fence selected by
  `fn.file.endswith(".go")`, so this run actually asked the model to
  write Go, not C.

## Result: the LLM patch is a strict improvement over the rule-based one on this handler

**Rule-based patch** (already on record, `reports/reachability/free5gc_case_study.md`):

```diff
@@ -17,6 +17,7 @@
 			c.Set(sbi.IN_PB_DETAILS_CTX_STR, http.StatusText(int(problemDetails.Status)))
 			c.JSON(http.StatusBadRequest, problemDetails)
 		}
+		return
 	}
```

Inserts exactly one `return`, and - looking at the actual braces - it
lands after the closing brace of the *outer* `if`, not inside the
*inner* validation block that produced the response. The second,
separate validation block a few lines down (the one `docs/REACHABILITY.md`
already flagged as needing its own `return`) is untouched.

**LLM-generated patch** (this run, `qwen2.5-coder:7b`):

```diff
@@ -16,6 +16,7 @@
 			}
 			c.Set(sbi.IN_PB_DETAILS_CTX_STR, http.StatusText(int(problemDetails.Status)))
 			c.JSON(http.StatusBadRequest, problemDetails)
+			return
 		}
 	}
 
@@ -26,6 +27,7 @@
 		}
 		c.Set(sbi.IN_PB_DETAILS_CTX_STR, http.StatusText(int(problemDetails.Status)))
 		c.JSON(http.StatusBadRequest, problemDetails)
+		return
 	}
 
 	if dnn == "" && snssai == nil && internalGroupId == "" && supi == "" {
```

Inserts a `return` immediately after **each** of the two `c.JSON(...)`
early-exit calls - correctly scoped to the validation block that
actually produced the response, and it caught **both** occurrences
rather than one. This is exactly the genuine, reportable difference the
scoping doc predicted this specific handler could produce: on a handler
with more than one occurrence of the same bug pattern, pattern-matching
the first occurrence (rule-based) is a strictly weaker fix than
reasoning about which validation block needs it (LLM).

Full diff saved at `reports/reachability/free5gc_llm_patch_get_handler.diff`.

## Compile verification against the real upstream module

Following the same method as `verify_against_real_upstream.py`: cloned
`github.com/free5gc/udr` fresh at the real pre-fix commit
(`86686276a7e226183ee786e3dd6714ec56c78fda^`), confirmed the unpatched
baseline builds, then applied four patches to the real
`internal/sbi/api_datarepository.go` - the already-verified rule-based
patch for the other 3 handlers, and this LLM-generated patch for
`HandleApplicationDataInfluenceDataSubsToNotifyGet` - and re-ran `go
build ./...`.

```
=== Baseline: real vulnerable commit, unmodified ===
  [baseline (unpatched)] go build ./... -> OK

Applied 4/4 patches: [..., ('HandleApplicationDataInfluenceDataSubsToNotifyGet', 'llm-ollama')]

=== After applying patches (LLM for the GET handler, rule-based for the other 3) to the REAL module ===
  [patched (real module, LLM-for-GET)] go build ./... -> OK

RESULT: real free5GC/udr @ 86686276a7e2 with an Ollama(qwen2.5-coder:7b)-generated
patch for HandleApplicationDataInfluenceDataSubsToNotifyGet (plus the existing
rule-based patches for the other 3 handlers) applied COMPILES
```

All 4 patches applied byte-exact (no skips), and the combined patch set
compiles cleanly against the real module's actual dependency graph - the
same evidence tier `verify_against_real_upstream.py` already established
for the all-rule-based patch set.

## What this result does NOT claim

- **No runtime confirmation.** Unlike the DELETE-handler and
  full-deployment work, this patch has not been exercised against a
  running UDR + MongoDB + NRF stack. It compiles; it has not been shown
  to actually close the vulnerability at runtime or to avoid a
  regression. That is the Docker-dependent half of Level 2, still open.
- **Memorization risk not controlled for.** `qwen2.5-coder:7b`'s
  training data may include the real fix commit or its surrounding
  GitHub history; this one run cannot distinguish "the model reasoned
  about the control flow" from "the model recalled the known fix." The
  scoping doc flagged this limitation in advance; it is not resolved by
  this result and should not be overstated when citing it.
- **Single model, single run, no cost/latency figures gathered** for
  comparison against the other free5GC-adjacent work or against the
  8-model/36-run main-pipeline comparisons (which deliberately excluded
  free5GC for structural reasons - see `docs/BENCHMARK_PROTOCOL.md`).

## Files

- `src/reachability/patch.py` - added the Go-aware prompt/fence
  (`_SYSTEM_PROMPT_GO`, `{lang}` template slot), selected automatically
  when the target file ends in `.go`.
- `src/reachability/run_free5gc_llm_patch.py` - the driver (new file).
- `reports/reachability/free5gc_llm_patch_get_handler.diff` - the raw
  LLM-generated diff.
- `docs/FREE5GC_LLM_PATCH_SCOPE.md` - the prior scoping document this
  implements.

## Next step (not done, not started)

Swap this patch into
`free5gc_full_deployment/udr_build/Dockerfile`'s build path (replace
`git checkout <patched commit>` with a checkout-at-vulnerable-commit +
apply-this-diff step) and re-run
`free5gc_full_deployment/run_full_deployment_harness.py` to get a real
four-outcome verdict for this LLM patch, once Docker Desktop is working
on this machine again.
