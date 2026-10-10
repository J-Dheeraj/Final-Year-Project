# free5GC Codex CLI model sweep (7 October 2026)

## Method

The unified free5GC sweep was run through the authenticated Codex CLI using a
read-only, ephemeral session for each model. The same vulnerable commit,
Docker deployment, four-handler validator, benign-path check, and bypass
classifier used by the Ollama studies were retained. The Codex provider stores
the raw JSONL events and the `turn.completed` usage object for every call.

The requested model set was:

`gpt-6-astra`, `gpt-6.1-sol`, `gpt-6-sol`, `gpt-6-luna`, `gpt-5.6-sol`,
`gpt-5.6-terra`, `gpt-5.6-luna`, `gpt-5`, `gpt-4.1`, `gpt-4o`, `o3`, and
`o4-mini`.

## Patch-generation results

| Model | Compile | Runtime verdict | Duration (s) | Input tokens | Output tokens |
|---|---:|---|---:|---:|---:|
| `gpt-6-astra` | yes | confirmed_fix_all_four_handlers | 15.97 | 27,649 | 343 |
| `gpt-6.1-sol` | yes | confirmed_fix_all_four_handlers | 15.07 | 27,713 | 343 |
| `gpt-6-sol` | yes | confirmed_fix_all_four_handlers | 15.02 | 27,200 | 370 |
| `gpt-6-luna` | yes | confirmed_fix_all_four_handlers | 30.37 | 27,021 | 343 |
| `gpt-5.6-sol` | yes | confirmed_fix_all_four_handlers | 16.41 | 26,788 | 375 |
| `gpt-5.6-terra` | yes | confirmed_fix_all_four_handlers | 17.17 | 26,788 | 371 |
| `gpt-5.6-luna` | yes | confirmed_fix_all_four_handlers | 19.16 | 23,214 | 525 |
| `gpt-5` | no | environment-limited | 5.42 | — | — |
| `gpt-4.1` | no | environment-limited | 4.81 | — | — |
| `gpt-4o` | no | environment-limited | 4.99 | — | — |
| `o3` | no | environment-limited | 6.31 | — | — |
| `o4-mini` | no | environment-limited | 4.83 | — | — |

The seven models that completed generation all compiled and passed the
four-handler runtime validator. The five older IDs did not produce a patch;
their Codex sessions failed before a usage event was returned. They remain in
the raw report and are not counted as patch-quality failures.

## Bypass-probe results

| Model group | Proposals executed | Confirmed bypasses | Usage captured |
|---|---:|---:|---:|
| `gpt-6-astra`, `gpt-6-luna`, `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna` | 5 | 0 | yes |
| `gpt-6.1-sol`, `gpt-6-sol` | 0 | 0 | no; Codex runtime failure |
| `gpt-5`, `gpt-4.1`, `gpt-4o`, `o3`, `o4-mini` | 0 | 0 | no; Codex runtime failure |

No executed Codex proposal bypassed the patched deployment. The failed
sessions are preserved as environment-limited outcomes, so they are not
silently interpreted as successful probes or model-quality failures.

## Cost accounting

Each raw result contains `duration_s`, the available input/output token counts,
the Codex thread ID, and the billing basis. The provider now also persists the
complete raw JSONL usage events for subsequent runs. Codex CLI used ChatGPT
authentication in this run, so no direct API dollar
charge was returned. Any dollar figure should therefore be labelled as an
API-equivalent estimate using a dated pricing table, not as an observed
ChatGPT subscription charge.

Raw reports:

- `reports/reachability/free5gc_sweep_patch_codex_october-2026-codex-all-models.json`
- `reports/reachability/free5gc_sweep_bypass_codex_october-2026-codex-all-models-bypass.json`
- `reports/reachability/free5gc_sweep_bypass_codex_october-2026-codex-bypass-retry.json`

## GPT-3-era compatibility pass

An additional pass attempted six legacy IDs: `gpt-3.5-turbo`,
`gpt-3.5-turbo-0125`, `gpt-3.5-turbo-1106`, `text-davinci-003`,
`text-curie-001`, and `davinci`. All six failed before generation because the
Codex CLI skill-discovery/runtime layer terminated before returning a model
completion or usage event. They produced no patch and no bypass request, so
they are recorded as environment-limited rather than as model-quality results.

Raw GPT-3-era reports:

- `reports/reachability/free5gc_sweep_patch_codex_october-2026-codex-gpt3-models.json`
- `reports/reachability/free5gc_sweep_bypass_codex_october-2026-codex-gpt3-bypass.json`

## Final 18-model matrix

The final matrix re-ran all 18 IDs in one isolated experiment. **7/18 patches
compiled and all 7 were runtime-confirmed across the four handlers.** The
bypass phase produced 4 executable proposals and **0/4 confirmed bypasses**;
the other 14 models failed before returning a parseable proposal. The final
run recorded 186,270 input and 2,528 output tokens for patch generation, plus
104,317 input and 974 output tokens for bypass probing.

Final raw reports:

- `reports/reachability/free5gc_sweep_patch_codex_october-2026-codex-final.json`
- `reports/reachability/free5gc_sweep_bypass_codex_october-2026-codex-final-bypass.json`


> **Provenance note:** `confirmed_fix_all_four_handlers` is a full pipeline validation outcome. Four handlers are tested, but one handler change is model-generated and three are deterministic reachability materializations; it is not an independently model-generated four-handler patch rate.
