# free5GC multi-run variance: is a single-shot result stable?

## Why this experiment exists

Every prior free5GC sweep (patch-generation and bypass-probe alike) ran
each model exactly once. This project's own `docs/DEFENSE_PREP.md`
already names single-shot, no-fixed-seed runs as a live weakness ("any
one CVE's confirmed/not-confirmed result can flip between runs" - see
the main pipeline's round 1-4 catalog flips). The free5GC results never
had an equivalent check.

The new `free5gc_full_deployment/sweep.py --runs N` flag (built as part
of this session's sweep-script unification) makes this cheap to test for
the bypass-probe task specifically, since it needs no Docker image
rebuild per run - just a fresh LLM call and HTTP requests against the
already-running `free5gc-udr-custom:patched` stack.

## Method

`python sweep.py --task bypass --backend ollama --models llama3.2:1b,llama3.2:3b --runs 3`
- 2 models actually available on this machine (see
  `docs/FREE5GC_MEMORIZATION_CONTROL_RESULTS.md`'s model-availability
  note for why the original 8-model list isn't used here), 3 independent
  attempts each, same real upstream-fix build, same seeded record.

## Two real bugs found and fixed while running this

1. **Crash on a malformed model response.** `llama3.2:1b`'s third
   attempt returned `"headers": "<some string>"` instead of a JSON
   object; `proposal.get("headers") or {}` doesn't catch a non-empty
   string (it's truthy), so the string reached
   `requests.get(..., headers=headers)` and crashed deep inside
   `requests`' own header-preparation code, taking down the whole sweep.
   Fixed in `run_bypass_probe_sweep.py` by validating `isinstance(headers,
   dict)` alongside the existing method/path shape checks, converting
   the crash into the same "invalid proposal shape" non-fatal outcome
   already used for a bad method or path.

2. **A second variant of the classifier false-positive this project
   already fixed once.** After the crash fix, `llama3.2:3b` reported
   `bypass_confirmed: true` on 2 of its 3 runs. Inspecting the raw
   request/response showed both were the model asking for the EXACT
   correct, fully-authorized canonical path with a harmless, server-
   ignored query string appended (`?influenceId=subs%2Dto%2Fnotify` and
   `?influenceId=subs%20to%20notify`) - Gin's router never looks at the
   query string for this endpoint, so the server correctly served the
   normal, legitimate response. `_is_genuine_trick()` already guarded
   against a re-encoded-but-identical PATH (the bug this project caught
   and fixed in the original bypass-probe sweep); it did not strip the
   query string before comparing, so an inert `?...` suffix made the
   decoded string differ from `CANONICAL_PATH` by nothing but that
   suffix, and the check wrongly called it a genuine trick. This would
   have been reported as "first confirmed bypass in this project's
   history" had it not been checked before writing anything up. Fixed by
   comparing only `urllib.parse.urlsplit(path).path` against
   `CANONICAL_PATH`. Re-classified both affected entries from the
   already-captured raw HTTP data - no new model calls needed, same
   remediation pattern used the first time this classifier bug class was found.

## Result

| Model | Confirmation rate (bypass found) | Runs |
|---|---|---|
| `llama3.2:1b` | 0/3 | 3 |
| `llama3.2:3b` | 0/3 | 3 |

0/3 for both models, stable across all 3 independent runs each - no
run-to-run flip. This directly closes the "single-shot, could flip
between runs" caveat for the bypass-probe class of free5GC experiment:
the real fix holding is not an artifact of one lucky run per model, at
least for the 2 models and 3 runs tested here. A larger model/run count
(once more Ollama models are pulled) would strengthen this further, but
even this small sample is a genuine stability check this project didn't
have before.

## Scope, stated plainly

- Only 2 models (same availability constraint as the memorization
  control), not the full 8/11-model population used in earlier sweeps.
- Only the bypass-probe task was run with multi-run variance here - the
  patch-generation task's `--runs N` path exists in `sweep.py` but
  wasn't exercised in this session (its own Docker-image-rebuild-per-run
  cost is much higher; left for a follow-up run, not skipped silently).

## Artifacts

- `reports/reachability/free5gc_sweep_bypass_ollama.json/.md`
- The crash fix and classifier fix both live in
  `free5gc_full_deployment/run_bypass_probe_sweep.py` (shared by every
  caller: the original script, `run_claude_bypass_probe_sweep.py`, and
  the new `sweep.py`).
