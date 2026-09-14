# free5GC lab: CVE-2026-40246 (UDR improper path validation)

The research report backing this FYP flagged "no direct use of network-stack
OSS like free5GC" as a gap. This is the one concrete step taken to close it
this session — honestly scoped, not oversold.

## The real vulnerability

[CVE-2026-40246](https://advisories.gitlab.com/pkg/golang/github.com/free5gc/udr/CVE-2026-40246)
/ [GHSA-g9cw-qwhf-24jp](https://osv.dev/vulnerability/GHSA-g9cw-qwhf-24jp),
CVSS 8.7, affects free5GC's UDR (Unified Data Repository) service, versions
≤ 1.4.2. The `DeleteInfluenceSubscription` handler checks whether the
`influenceId` path segment equals the literal string `"subs-to-notify"` and
writes an HTTP 404 when it doesn't — but never `return`s after writing that
response, so execution falls through and the subscription is deleted from
the store regardless of whether the check passed. An unauthenticated
attacker on the 5G Service Based Interface can delete **any** Traffic
Influence Subscription this way, while the API misleadingly reports 404 Not
Found either way — the kind of bug that's specifically hard to notice in
logs, since the response looks like a harmless "not found" in both the
attack and the innocent case.

This is a real, disclosed, CVSS-8.7 bug in a real 5G core network OSS
project, not a synthetic example invented for this FYP.

## What was built (`free5gc_lab/`)

- **`udr_lab.go`** — a minimal, dependency-free Go HTTP server (stdlib
  `net/http` only, Go 1.22+'s native method+wildcard routing, no external
  packages) that reproduces the exact control-flow bug: a vulnerable
  handler missing the `return`, and a patched handler with it, toggled by
  `LAB_MODE=vulnerable|patched` — same dual-mode convention `ssrf_lab`
  already uses for its own CVE.
- **`run_demo.py`** — builds the Go binary once, starts it in vulnerable
  mode, sends a `DELETE` for a real seeded subscription (`sub-002`, not
  `subs-to-notify`), and confirms it disappears despite the 404. Then
  restarts in patched mode and confirms the same attack leaves it intact.

Both were run for real to produce this output (not hand-written):

```
=== mode=vulnerable ===
  sub-002 exists before attack: True
  DELETE /.../sub-002 -> HTTP 404
  sub-002 exists after attack:  False
  VERDICT: EXPLOITED (404 returned but subscription deleted anyway)

=== mode=patched ===
  sub-002 exists before attack: True
  DELETE /.../sub-002 -> HTTP 404
  sub-002 exists after attack:  True
  VERDICT: BLOCKED
```

## A real bug this surfaced (not staged, same discipline as `CVE_CATALOG.md`)

The first version of `run_demo.py` used `go run udr_lab.go` for each mode
and called `Popen.terminate()` between them. On Windows, `go run` spawns
the compiled server as a **child** of the `go run` wrapper process;
terminating the wrapper doesn't reliably kill that child (no process-group
signal propagation). The result: the vulnerable-mode server was still
alive and bound to :8090 when the "patched" test started, so the second
`go run` never even started its own server — the demo was silently
attacking the *same already-compromised vulnerable process* twice and
reporting a false "BLOCKED" verdict for the wrong reason (the subscription
was already gone from the first attack, not protected by the patch).
Fixed by building the binary once (`go build`) and running the compiled
executable directly, so `Popen.terminate()` kills the actual server
process. Caught by checking `netstat` for a stale listener on :8090 after
the first broken run, not by assuming the output was correct.

## What this honestly is and isn't

- **Is**: a faithful, minimal reproduction of a real, disclosed, high-
  severity free5GC bug, in Go, dynamically demonstrated both exploited and
  patched, with a genuine subscription-state check (not a status-code-only
  check that a 404-either-way bug would trivially fool).
- **Is not**: the real free5GC UDR codebase compiled and run. The route
  path (`/nudr-dr/v2/subscription-data/influenceData/{influenceId}`) is a
  reasonable simplification of the real API shape, not verified against
  free5GC's actual router configuration — this lab reproduces the *handler
  logic bug*, not the full service.
- **Is not** wired into `cve_pipeline.py`'s generic Stage 3.5 template
  system, which is Python/Flask-specific. It's a standalone lab in the
  same spirit as `ssrf_lab/`, runnable on its own. Wiring a Go target into
  the pipeline's exploit-artifact-generation stage (rather than running
  it as a bespoke demo) is future work, not attempted here — the "build
  Python-shaped artifacts for a Go target" mismatch is a real design
  question, not a small addition.
- **Is not** a call-graph/reachability analysis of free5GC, unlike
  reachcrs's own BFS-from-entry-points work on other Go/C++ codebases.
  This lab targets one already-known handler, not a discovery mechanism.

## Running it

```bash
cd free5gc_lab
python run_demo.py
```

Requires a Go toolchain on PATH (`go build`/`go run`); no external Go
modules are fetched (stdlib only), so it works offline.
