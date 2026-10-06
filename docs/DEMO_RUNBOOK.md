# free5GC R&D demonstration runbook

Use the real free5GC deployment to demonstrate the evidence chain without
calling a hosted model or modifying the repository.

## Prerequisites

- Docker Desktop is running.
- The `compose/` checkout and overrides are prepared as described in
  `free5gc_full_deployment/SETUP.md`.
- `free5gc-udr-custom:vulnerable` and `free5gc-udr-custom:patched` exist.
- Python has `requests` installed.

## Demonstration

From the repository root:

```text
python free5gc_full_deployment/run_full_deployment_harness.py
```

The harness starts the vulnerable image, seeds a known subscription, and
records the collection GET leak, single-record GET leak, unauthorized PUT,
and unauthorized DELETE. It then starts the patched image and repeats the
same requests, including a legitimate GET. The expected final verdict is:

```text
overall_verdict: confirmed_fix_all_four_handlers
```

For the LLM patch result, show one preserved run from
`reports/reachability/october-2026-patch-repeat/<model>/run-<n>/manifest.json`
and its generated Go source. The corresponding failed examples are:

- `codellama:13b` run 2: generated Go failed compilation;
- `qwen2.5-coder:1.5b` runs 2 and 3: Go compiled but the collection GET leak
  remained exploitable.

## Evidence to show

- `free5gc_full_deployment/evidence/vulnerable_response.json`;
- `free5gc_full_deployment/evidence/patched_response.json`;
- `free5gc_full_deployment/evidence/verdict.json`;
- the repeated-study JSON report and per-run manifests;
- `docs/EVIDENCE_LEDGER.md` and `docs/FREE5GC_PATCH_REPEAT_RESULTS.md`.

The demonstration does not claim full-core-network coverage. OAuth2 is
disabled in this harness and remains an explicit limitation.

