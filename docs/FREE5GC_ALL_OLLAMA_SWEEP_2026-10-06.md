# free5GC all-installed-Ollama sweep: 6 October 2026

This is a fresh one-run snapshot across every Ollama model installed on the
development machine. It uses the real free5GC UDR source at the pinned
vulnerable commit, compiles the generated patch against the real module, and
then runs the existing four-handler Docker validator when compilation passes.

Raw report:
`reports/reachability/free5gc_sweep_patch_ollama_october-2026-all-ollama.json`.

| Model | Patch generated | Compiled | Runtime verdict |
|---|---|---|---|
| `deepseek-coder-v2:16b` | no | no | not reached; model-generation failure |
| `codellama:13b` | yes | no | not reached; patched source failed to compile |
| `gemma2:9b` | yes | yes | `confirmed_fix_all_four_handlers` |
| `mistral:7b` | yes | yes | `confirmed_fix_all_four_handlers` |
| `llama3.1:8b` | yes | yes | `confirmed_fix_all_four_handlers` |
| `qwen2.5-coder:7b` | yes | yes | `confirmed_fix_all_four_handlers` |
| `qwen2.5-coder:3b` | yes | yes | `confirmed_fix_all_four_handlers` |
| `qwen2.5-coder:1.5b` | yes | no | not reached; patched source failed to compile |

## Result

**5/8 models were runtime-confirmed.** Five patches compiled and all five
passed the four exploit checks plus the benign-path check. Two generated
patches failed compilation, and `deepseek-coder-v2:16b` failed before a patch
could be evaluated. No hosted-model calls were used.

This is a separate single-run snapshot. The controlled repeatability result
remains the 12-run study in `docs/FREE5GC_PATCH_REPEAT_RESULTS.md`.

New Ollama sweeps now preserve per-call accounting from the native response:
wall-clock duration, prompt-evaluation input tokens, generated output tokens,
total tokens, model-load duration, prompt-evaluation duration, and generation
duration. This historical snapshot predates that instrumentation, so its raw
report does not contain these fields.
