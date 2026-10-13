# Reproduction record (2026-10-10)

- Evidence update commit: `94689d9`
- Final freeze tag will be `fyp-rd-freeze-2026-10-10-final`
- Previous integrity freeze tag: `fyp-rd-freeze-2026-10-10-integrity-2`
- **Update, 2026-10-13**: this record is a point-in-time snapshot from
  2026-10-10; the "final freeze tag" line above is stale. Rather than
  hardcode a tag name here that will go stale again, see
  `docs/FINAL_DEMONSTRATION_CHECKLIST.md`, step 1, for the current pinned
  tag for any demo or submission, the full tag history, and what each
  superseded tag predates. (The previous update to this line, on
  2026-10-12, itself went stale within a day - this is why the checklist,
  not this record, is the single source of truth for the current tag.)
- OpenAI project: proj_QypENhihtJ0cYJq3OUqPxk5Y
- Docker server version: `29.4.3`
- Relevant local images observed: `free5gc-udr-custom:vulnerable`, `free5gc-udr-custom:patched`

## Verification commands

```text
python -m pytest -q
python -m py_compile catalog_bypass_probe.py src/reachability/providers.py free5gc_full_deployment/sweep.py browser_xss_replay.py free5gc_full_deployment/run_prompt_cache_sensitivity.py
python browser_xss_replay.py --self-test
python free5gc_full_deployment/build_evidence_ledger.py
```

These checks passed during the final evidence pass. The controlled OpenAI attempt report is `reports/reachability/free5gc_sweep_patch_openai_openai-free5gc-controlled-2026-10-10.json`; all 12 calls were rejected with HTTP 401 because the locally supplied key was invalid, so they are recorded as authentication/environment failures. The completed prompt/cache reports are listed in `docs/FREE5GC_PROMPT_CACHE_SENSITIVITY_RESULTS.md`. Credentials are loaded locally and intentionally excluded from committed files.
