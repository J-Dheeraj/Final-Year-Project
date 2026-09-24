# ProvTrail JS/TS dynamic-confirmation lab

Bounded step 3 of the ProvTrail integration item in `docs/PROJECT_STATUS.md`:
one real ProvTrail-flagged CVE, one hand-authored JS/TS class template,
confirmed dynamically through the pipeline's real execution path — not
"all classes work," per that item's own stated exit criterion.

## What this proves

`cve_pipeline.py`'s `execute_exploit_artifacts` (Stage 3.6) — the exact
function every Python CVE in this catalog already uses — can now run a
JavaScript target too. The only pipeline change was teaching it to spawn
`node` instead of the Python interpreter when the target file is `.js`
(the Python path is completely unchanged, verified by re-running an
existing CVE end-to-end after the change: still confirms, still patches,
still passes multi-payload validation, exactly as before).

## What this does NOT do (yet)

Stage 2's auto-classification and Stage 3.5's LLM-generation don't know
about JS vulnerability classes — `target_app.js`/`poc.py` here are
hand-authored, not generated. Auto-classification + auto-generation for
JS/TS classes is the next, larger step, explicitly out of scope for this
bounded validation pass (see the ProvTrail item's own gated plan).

## The CVE

[CVE-2024-48910](https://github.com/advisories/GHSA-p3vf-v8qc-cwcr)
(dompurify) — Prototype Pollution (CWE-1321), CRITICAL. Chosen over the
other two real high-confidence `VULN` entries in
`tests/fixtures/provtrail/latest-scan.ai.txt` (a Next.js HTTP-smuggling
CVE, a fastify CVE) because prototype pollution is genuinely JS-native —
no equivalent in this pipeline's existing 6 Python vulnerability classes
— and is far more tractable to build an honest minimal reproduction for
than request smuggling, which needs precise HTTP-framing manipulation.

`target_app.js` reproduces the real root cause (an unguarded recursive
merge lets `__proto__` overwrite `Object.prototype`) with a minimal
hand-written merge — not DOMPurify's actual source, same "faithful
reproduction, not the real package" scope as every other CVE in this
project (`docs/SCOPE_AND_LIMITATIONS.md` Limitation 1). Zero npm
dependencies — only Node's built-in `http`/`url` modules, so
`node target_app.js` runs with nothing but Node itself installed.

## Run it

```bash
python run_demo.py
```

Needs Node.js on PATH (`node --version`). Runs the real pipeline
function, prints `dynamically_confirmed: True` and the real
`poc.py`/`target_app.js` subprocess output on success.
