# free5GC headline metric interpretation

The historical `confirmed_fix_all_four_handlers` field is a **full pipeline
validation outcome**. It means compilation, runtime checks for all four
handlers, and the benign-path check passed. It does not mean that a model
independently generated four handler patches.

For this harness every patch result has the following provenance:

| Field | Meaning |
|---|---|
| `handlers_total` | 4 reachable handlers were tested |
| `handlers_model_generated` | 1 handler patch was requested from the model |
| `handlers_deterministically_materialized` | 3 handler changes came from deterministic reachability rules |
| `compile_passed` | The assembled source compiled against the pinned dependency graph |
| `runtime_confirmed_all_four_handlers` | All four runtime exploit checks passed, and the benign path remained valid |
| `pipeline_validation_verdict` | The public derived verdict |

Therefore the accurate OpenAI headline is: **18/23 runs passed the full
four-handler validation pipeline**. This is not an 18/23 rate of
independently model-generated four-handler patches.

Raw JSON remains unchanged as historical evidence where possible. The derived
ledger at `reports/reachability/free5gc_derived_evidence_ledger.json` carries
the provenance fields used for interpretation.


> **Provenance note:** `confirmed_fix_all_four_handlers` is a full pipeline validation outcome. Four handlers are tested, but one handler change is model-generated and three are deterministic reachability materializations; it is not an independently model-generated four-handler patch rate.
