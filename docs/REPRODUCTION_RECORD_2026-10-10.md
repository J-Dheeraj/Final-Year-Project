# Reproduction record (2026-10-10)

- Repository commit before final documentation changes: $sha
- OpenAI project: proj_QypENhihtJ0cYJq3OUqPxk5Y
- Docker server version: $docker
- Relevant local images observed: $images

## Verification commands

`	ext
python -m pytest -q
python -m py_compile catalog_bypass_probe.py src/reachability/providers.py free5gc_full_deployment/sweep.py
`

Both checks passed during the final evidence pass. The full free5GC OpenAI run commands and source report IDs are recorded in docs/RESULTS_BY_ACCESS_METHOD.md and the corresponding raw JSON reports. Credentials are intentionally excluded.
