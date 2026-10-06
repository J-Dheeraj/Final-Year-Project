# free5GC repeated patch-generation study

This study measures run-to-run stability for LLM-generated patches against
the real free5GC UDR deployment. It is the final focused R&D experiment for
the October 2026 freeze.

## Frozen protocol

- Target: CVE-2026-40248, `HandleApplicationDataInfluenceDataSubsToNotifyGet`.
- Vulnerable source: the parent of upstream fix commit
  `86686276a7e226183ee786e3dd6714ec56c78fda`.
- Runtime stack: real MongoDB, real free5GC NRF, and the four-handler UDR
  harness in `free5gc_full_deployment/run_full_deployment_harness.py`.
- Each model is run three independent times.
- Every run has a unique model/run artifact directory under
  `reports/reachability/october-2026-patch-repeat/`.
- A result is a confirmed fix only when compilation, all four exploit checks,
  and the benign-path check pass.
- Compile-only, model-load, Docker, and harness failures remain separate
  outcomes and are not counted as confirmed fixes or model-quality failures
  without the corresponding evidence.

## Results

The machine-readable source is
`reports/reachability/free5gc_sweep_patch_ollama_october-2026-patch-repeat.json`.
The table below is completed after the run and must be copied from that raw
file rather than hand-counted from logs.

| Model | Confirmed runs | Compile-success runs | Runtime failures | Environment failures |
|---|---:|---:|---:|---:|
| `codellama:13b` | 2/3 | 2/3 | 0 | 1 compile failure |
| `gemma2:9b` | 3/3 | 3/3 | 0 | 0 |
| `qwen2.5-coder:7b` | 3/3 | 3/3 | 0 | 0 |
| `qwen2.5-coder:1.5b` | 1/3 | 3/3 | 2 | 0 |

Aggregate: **9/12 runs were runtime-confirmed**, 11/12 compiled, 2/12
compiled but left the collection-GET leak open, and 1/12 failed compilation.
All 12 attempts reached live generation; no template fallback or hosted
model call was used.

The `codellama:13b` compile failure was caused by explanatory text and a
markdown fence being included in the generated Go function body. The two
`qwen2.5-coder:1.5b` runtime failures compiled but appended `c.JSON` or
`c.Abort()` after the vulnerable call, leaving the collection leak open.
These failures demonstrate why compile-only validation is insufficient.

## Interpretation rule

Report per-model confirmation rates and the aggregate rate with the full
denominator. Do not rank models from this small sample. Explain each failed
run using its preserved manifest and log, distinguishing model output from
hardware, Docker, network, or harness problems.
