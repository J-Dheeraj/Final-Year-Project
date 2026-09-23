# Scope and Limitations

Report-ready draft. Written to be defensible in a viva: every claim below
is stated at the precision level it can actually survive a follow-up
question at, not the precision level that sounds most impressive. Adapt
the prose to your report's voice, but do not loosen the claims.

## What this project is

Two complementary, evidence-gated capabilities for using LLMs to secure
open source software:

1. **LLM-assisted exploit confirmation and patch validation for known
   CVEs** (`cve_pipeline.py`, Stages 1-4/3.5-3.8) — given a CVE/GHSA ID,
   fetch its advisory, classify the vulnerability, generate a runnable
   proof-of-concept and a target that reproduces the described bug
   pattern, dynamically confirm the exploit actually works, iteratively
   self-improve a failed attempt, and generate + validate a patch.
2. **Reachability-filtered static analysis on real upstream source**
   (`src/reachability/`) — AST-based call-graph construction and
   breadth-first reachability from real HTTP entry points, applied to a
   real, disclosed free5GC vulnerability, with the resulting patch
   verified to compile against the actual project's real dependency
   graph.

## What this project deliberately is not

The project's original pitch ("fuzzing LLMs to secure OSS") has been
dropped. Nothing in this codebase does coverage-guided input mutation —
no AFL++, no libFuzzer, no fuzzing engine of any kind exists anywhere in
the repository. This is a scope decision, confirmed acceptable by the
supervising professor, not an unstated gap. It should be stated in the
report's own words, not left for a reader to notice on their own.

It is also not a full DARPA AIxCC-style Cyber Reasoning System: a CRS's
defining, hardest capability — finding an *unknown* bug in an unmodified
codebase — is not attempted. Every unit of work in this project starts
from either an already-published CVE ID or a stated list of entry-point
function names.

## Limitation 1: Exploit targets are reproductions, not the real package

For all six CVEs in the main catalog (`reports/CVE_CATALOG.md`), the
exploited target (`target_app.py`) is a small Flask application generated
to reproduce the *bug pattern described in the advisory text* — it is not
the actual named package (litellm, modoboa, jaraco.context, nltk, dssrf,
md-fileserver) installed, imported, or run in any form.

**What `dynamically_confirmed: True` therefore proves**: a faithful
reproduction of the advisory's described bug pattern is exploitable as
described.
**What it does not prove**: that the real, named upstream package is
exploitable when actually run. That claim is plausible (the reproduction
is built directly from the advisory's own root-cause description) but not
independently demonstrated by this pipeline. Any report language claiming
"CVE-X was exploited in package Y" should be corrected to "CVE-X's
described bug pattern was reproduced and dynamically confirmed."

This limitation does not apply to the `src/reachability/` free5GC case
study, where the source analyzed and patched is the real, cloned upstream
project — see Limitation 4 for what *is* and *is not* proven there
instead.

## Limitation 2: Stage 3's live probe is real for one class out of six

Stage 3 (`run_vuln_probe`) genuinely sends live traffic to a running
target only for SSRF, via `ssrf_lab/`. For the other five classes (SQL
injection, OS command injection, XSS, path traversal, deserialization),
Stage 3 performs static regex pattern-matching against the advisory's
code diff — no process is started, no payload is sent. Every one of
those probes' `bypass_results` entries carries `"tested": False` in the
underlying data.

This is not a defect discovered late; it is stated plainly in the
project's own `README.md` under "Honest gap, stated plainly," and it
motivated the actual source of dynamic evidence in this project: Stage
3.6 (`execute_exploit_artifacts`), which performs real subprocess
execution and real HTTP exchange for every class, not just SSRF. The
report should describe Stage 3's role accurately (classification-time
static signal) and attribute the project's dynamic-confirmation claim to
Stage 3.6, not Stage 3.

## Limitation 3: Patch validation proves regression-safety, not correctness in general

Stage 3.8 (`src/pipeline/patch.py`) validates a generated patch by
requiring two conditions simultaneously: (1) the *original, unmodified*
exploit script now fails against the patched target, and (2) the
target's `/health` endpoint still returns 200. Both are necessary because
either alone is gameable — a patch that deletes the vulnerable endpoint
entirely would satisfy (1) without being a real fix, and is caught by (2)
failing. This is a real, evidence-gated check, but it is bounded: it
proves the specific known payload no longer succeeds and the app still
starts, not that no other payload could succeed, and not that the patch
is a *good* fix by any broader software-engineering standard. It is
regression-testing against one known exploit, not formal verification.

## Limitation 4: "Compiles" is not "fixed" — the free5GC reachability work

`src/reachability/verify_against_real_upstream.py` clones the real
`github.com/free5gc/udr` repository, applies the pipeline's generated
patches directly to the real source, and confirms `go build ./...`
succeeds against the module's actual dependency graph. This is real and
meaningful: it proves compile-compatibility with the genuine upstream
project, something neither this project nor its predecessor (reachcrs)
had previously demonstrated for a Go target.

**It is not dynamic confirmation.** Compiling proves the patched code is
syntactically valid and type-checks; it says nothing about runtime
behavior. A patch that inserts a `return` in the wrong branch would still
compile and would not fix anything. Full dynamic proof would require
deploying the real free5GC UDR service (which needs a MongoDB backend and
NRF service-registration, i.e. the rest of a 5G core, not a standalone
binary) and sending it a real HTTP request — not attempted in this
project. The report should describe this result as "compile-verified
against the real project," never as "dynamically confirmed" or
"exploited," which are reserved for the main pipeline's Stage 3.6/3.8
evidence.

## Limitation 5: two free5GC efforts exist and are not unified

`free5gc_lab/` (a self-contained, dependency-free Go reproduction,
dynamically exploited and patched for CVE-2026-40246) and
`src/reachability/`'s free5GC case study (real source, compile-verified,
for the sibling CVE-2026-40248) both target the same bug family in the
same real file, and do not reference each other.

This is an honest infrastructure gap, not a deliberate architectural
separation: `free5gc_lab/` was built specifically to avoid needing
MongoDB/NRF/the rest of the 5G core stack, so it could be dynamically
exploited in seconds; the reachability work later obtained the real
source but never stood up the full service needed to dynamically test
it. Unifying the two — standing up a real free5GC deployment and pointing
a dynamic exploit at the real source instead of a hand-written
reproduction — is legitimate, well-scoped future work, and should be
named as such rather than left for a reader to notice the disconnect
unexplained.

## Limitation 6: LLM-dependent paths were proven via stub in this
   environment, then confirmed to persist without one

This development environment has neither the `claude` CLI nor an
`ANTHROPIC_API_KEY` configured. Three LLM-dependent mechanisms were
therefore verified in two stages, consistently: first via a stubbed
`_call_claude`/`_claude_available` returning a hand-written but realistic
response (proving the prompt -> parse -> apply -> re-verify plumbing
works end to end), then — for Stage 3.7 — via a completely unstubbed
real CLI run that picked up the persisted fix with zero AI backend
needed, proving the *reuse* path needs no live model even though the
*first discovery* of a fix does. The three mechanisms and their
verification status:

| Mechanism | Verified via stub | Verified live (real model generating from scratch) |
|---|---|---|
| Stage 3.7 LLM-revision (self-improvement) | Yes (Path Traversal CVE) | No |
| Stage 3.8 patch generation | Yes (SQLi CVE) | No |
| `reachcrs`/`src/reachability` LLM-based triage/patch fallback | N/A — the free5GC case study used the rule-based path (`find_missing_return_after_response`), not the LLM fallback | No |

The report should state plainly that the live-model half of paths 1 and 2
is untested in this environment, for the same reason `reachcrs`'s own
live-LLM validation needed a separate machine with a real provider
configured. This is a standing, explicit caveat, not a hidden assumption.

**Update, live-LLM Gate 1 (branch `feat/live-llm-gate1`, not yet merged):**
this environment now has a real, local live-model backend (Ollama,
`qwen2.5-coder:7b`, no API key), and a 4th, adjacent mechanism — Stage 3.5's
*initial* exploit-artifact generation (not the 3 revision/patch/triage
mechanisms in the table above) — has been verified genuinely live:
`generation_outcome=llm_live_success`, `generation_backend=ollama`,
`generation_model=qwen2.5-coder:7b`, a real CVE-tailored PoC, not a template.
The three mechanisms in the table above (Stage 3.7 revision, Stage 3.8 patch
generation, reachability's LLM fallback) are still unverified live — this
does not change any "No" in the table, it adds a 4th row's worth of
evidence for a different stage. The environment premise above ("neither the
`claude` CLI nor an API key") is now stale for this specific local-Ollama
path; it remains true that no hosted-API key is configured.

## Limitation 7: local exploitation of open-source software is legitimate authorized testing

For the avoidance of doubt in the report: dynamically exploiting a
locally-deployed, self-hosted copy of open-source software (the SSRF lab,
the free5GC lab, the generated `target_app.py` instances) is standard,
legitimate security research practice, not unauthorized access. Every
target in this project is either hand-written or a local deployment the
researcher controls, bound to `127.0.0.1`. No claim in this project
depends on, nor should be confused with, testing a system the researcher
does not own or have permission to test.

## Summary table for the report's own scope section

| Claim | Evidence level | Where |
|---|---|---|
| "The bug pattern described in CVE-X is exploitable" | Dynamic (real subprocess exit code) | Main pipeline, 5/6 confirmed CVEs |
| "Package Y itself is exploitable" | Not demonstrated | — |
| "A generated patch closes the known exploit without breaking the app" | Dynamic, two-check regression test | Stage 3.8 |
| "Reachability analysis narrows 102 real functions to 4 relevant ones" | Real, AST-based | `src/reachability/`, free5GC |
| "The generated free5GC patch compiles against the real project" | Real, compile-time | `verify_against_real_upstream.py` |
| "The generated free5GC patch fixes the bug at runtime" | Not demonstrated | — |
| "This system fuzzes to find unknown bugs" | Not attempted, not claimed | — |
