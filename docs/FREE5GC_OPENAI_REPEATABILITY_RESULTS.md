# free5GC OpenAI repeatability study (2026-10-10)

Four selected OpenAI models were run three times each against the same pinned vulnerable free5GC UDR source and Docker validation sequence. The repeatability runner now supports `temperature=0` and `seed=42` where accepted; models that reject those controls are retried without them and the fallback is recorded per run. Each run has a distinct artifact directory and run number.

| Model | Runs | Compiled | Full pipeline validation | Outcome pattern |
|---|---:|---:|---:|---|
| `gpt-5` | 3 | 3/3 | 2/3 | environment failure (Docker build), confirmed_fix_all_four_handlers, confirmed_fix_all_four_handlers |
| `gpt-4.1-mini` | 3 | 3/3 | 3/3 | confirmed_fix_all_four_handlers, confirmed_fix_all_four_handlers, confirmed_fix_all_four_handlers |
| `gpt-5.2` | 3 | 0/3 | 0/3 | compile failure, compile failure, compile failure |
| `gpt-5.6-luna` | 3 | 2/3 | 2/3 | confirmed_fix_all_four_handlers, confirmed_fix_all_four_handlers, compile failure |

- Total runs: **12**
- Compiled: **8/12**
- Full pipeline validation all four handlers: **7/12**
- Model-call runtime: **53.42 seconds**
- Tokens: **6,171 input / 6,046 output**
- Estimated cost: **US$0.0022**

The GPT-5 run-1 Docker failure was classified as an environment failure because Docker could not complete a TLS handshake with Docker Hub. GPT-5.2 failed compilation consistently at the same generated Go syntax location. GPT-5.6 Luna had two successful runtime validations and one compile failure. These outcomes are retained rather than collapsed into a single model score.

Raw report: `reports/reachability/free5gc_sweep_patch_openai_openai-free5gc-repeatability-2026-10-10.json`.


> **Metric interpretation:** `confirmed_fix_all_four_handlers` means the full validation pipeline passed. Four handlers are tested, but only one handler change is model-generated; three are deterministic reachability materializations. It is not a rate of independently model-generated four-handler patches.


Each successful row has `handlers_total=4`, `handlers_model_generated=1`, and `handlers_deterministically_materialized=3`; the historical verdict name is retained only for raw compatibility.
