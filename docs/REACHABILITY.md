# Reachability-filtered discovery (`src/reachability/`)

## Why this exists

The step-back review of this FYP's direction flagged two structural gaps
honestly documented in `docs/CRS_MAPPING.md`: (1) every CVE the main
pipeline processes is already known — nothing discovers an *unknown* bug —
and (2) every target is a hand-written stand-in (`target_app.py`), never
the real upstream project. This module addresses both at once, not by
adding fuzzing (the professor confirmed moving away from that framing is
fine), but by porting this FYP's own earlier prototype — **reachcrs**
(`C:\Users\dheer\Downloads\reachcrs`, same author, same FYP, built before
the professor redirected the base to AI-exploit-CVE) — which already does
real, AST-based reachability analysis, triage, and patch generation
against real C/C++/Go source. It was sitting unused; nothing in it needed
to be reinvented, only moved and extended.

## What was ported

`src/reachability/` is a near-verbatim copy of reachcrs's core pipeline:

| Module | Role |
|---|---|
| `reachability.py` | tree-sitter AST parsing (C/C++/Go) -> call graph -> BFS reachability from stated entry points |
| `heuristics.py` | offline, rule-based vulnerability pattern matchers (no LLM needed) |
| `triage.py` / `verify.py` | flag reachable functions, then adversarially re-check flagged ones |
| `patch.py` | generate a fix (rule-based when a heuristic matches, LLM-based otherwise via `providers.py`) |
| `testing.py` | scratch single-file compile+PoC verification (C-only — see "What's new" below) |
| `pipeline.py` / `report.py` | orchestration + JSON/Markdown report output |

Ported, not rewritten: the port was sanity-checked by reproducing
reachcrs's own numbers exactly inside AI-exploit-CVE (102 functions
parsed, 4 reachable, 96.1% reduction, all 4 real handlers flagged and
verified) — same result, new home.

## The real target: free5GC/udr, CVE-2026-40248

`examples/free5gc_case_study/api_datarepository_{vulnerable,patched}.go`
are fetched **verbatim from `github.com/free5gc/udr`**, at the commit
before and the commit of the real fix
(`86686276a7e226183ee786e3dd6714ec56c78fda`), both verified against the
GitHub API. This is a real, disclosed bug (CWE-285: a validation check
writes an HTTP 404/400 response but the handler doesn't `return`, so
request processing falls through and executes anyway) in a real,
standards-compliant 5G core network's Go source — not a stand-in written
for this project, unlike `free5gc_lab/` (the earlier session's own
reproduction of a *different*, related CVE in the same file family).

Run the offline case study (no network needed — the source is vendored):

```bash
python -m src.reachability.run_free5gc_case_study
```

Real result, this session:

- **102 functions** parsed from an **86KB real source file** (a meaningful
  parser stress test on its own).
- **4 reachable** from the 4 real HTTP entry points (`96.1% reduction`) —
  this is the actual discovery-adjacent value: a human or LLM analyzing
  this file blind would have to consider 102 functions; reachability
  narrows that to the 4 that can actually be reached from the outside.
- **4/4 flagged and verified**, all `CWE-285`, matching the real bug class.
- **Patch generated for all 4** (rule-based `find_missing_return_after_response`).

## What's new here that reachcrs's own report didn't have

reachcrs's last run against this same file (`live_llm_reports/free5gc_cve-2026-40248.json`,
in the original repo) shows `"compiler_available": false, "testing skipped"`
for every finding — not because no compiler existed, but because
`testing.py` only ever looks for a C compiler (`cc`/`gcc`/`clang`), never
`go`. This environment has a real Go toolchain (`go1.26.3`), so this
session did the deeper check reachcrs's own tester structurally couldn't:

```bash
python -m src.reachability.verify_against_real_upstream
```

This clones the **actual `free5gc/udr` repository** at the real pre-fix
commit (not a scratch copy of one file — the real module, with its real
`go.mod`/`go.sum` and full dependency graph: gin, mongo-driver, the other
free5GC internal packages), confirms it builds cleanly as a baseline,
applies the pipeline's 4 auto-generated patches directly to the real
`internal/sbi/api_datarepository.go`, and rebuilds. Real result, this
session:

```
=== Baseline: real vulnerable commit, unmodified ===
  [baseline (unpatched)] go build ./... -> OK

Applied 4/4 patches: [...]

=== After applying auto-generated patches to the REAL module ===
  [patched (real module)] go build ./... -> OK

RESULT: real free5GC/udr @ 86686276a7e2 with the pipeline's
auto-generated patches applied COMPILES
```

This is a genuinely new capability, not present in either reachcrs or
AI-exploit-CVE before this session: proof that an auto-generated patch is
compile-compatible with the **actual, real upstream project's full
dependency graph** — not just internally consistent with an isolated
copy of one file, which is all `testing.py`'s existing scratch-build model
could ever prove even for C.

## What this honestly is and isn't

- **Is**: real AST-based reachability filtering (not a regex heuristic) on
  a real ~86KB file from a real, currently-maintained 5G core network
  project; real triage/verification/patch generation; and — new this
  session — real compile verification against the actual upstream
  module's real dependency graph, not a synthetic stand-in.
- **Is not** a full dynamic PoV against the running free5GC UDR service.
  That needs a MongoDB backend, NRF registration, TLS certs, and the rest
  of a 5G core's other network functions running alongside it — running
  the actual service end-to-end was out of scope for this session, the
  same kind of honestly-stated boundary as the SSRF probe's real network
  limitation elsewhere in this repo. `go build` succeeding proves the
  patch doesn't break compilation against the real codebase; it does not
  by itself prove the patch closes the vulnerability at runtime the way
  Stage 3.6/3.8's HTTP-level dynamic confirmation does for the main CVE
  pipeline.
- **Is not** fully merged into the main `cve_pipeline.py` orchestration.
  It's a separate, standalone module with its own entry points, the same
  relationship `free5gc_lab/` and `ssrf_lab/` already have to the main
  pipeline. Wiring reachability as an actual upstream stage of the main
  pipeline (start from "here's a repo," not "here's a CVE ID") is real
  future work, not attempted here.
- **Known, inherited limitation** (documented in reachcrs's own test
  suite, `tests/test_free5gc_case_study.py` in the original repo, and
  still true here): one of the four handlers,
  `HandleApplicationDataInfluenceDataSubsToNotifyGet`, needs **two**
  separate `return` insertions in the real fix; `patch.py`'s rule-based
  generator finds only the first match per function body, so this one
  comes back partially fixed. Not silently glossed over — the real
  upstream-compile check above still shows `go build` succeeding on it
  (a partial fix doesn't break compilation), it just doesn't fully close
  the vulnerability. Fixing this needs the rule to return every match,
  not just the first — a small, scoped, honestly-deferred improvement.

## Relationship to the rest of this repo

This does NOT replace the main `cve_pipeline.py` CVE-driven workflow — it
adds a second, complementary capability the FYP's reframed pitch can
legitimately claim: **discovery-adjacent static analysis on real upstream
source**, alongside the main pipeline's **exploit confirmation and patch
validation for already-known CVEs**. See `docs/CRS_MAPPING.md` for how
both pieces now map onto the AIxCC/OSS-CRS vocabulary.
