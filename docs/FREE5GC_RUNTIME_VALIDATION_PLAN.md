# free5GC runtime validation plan (Phase 2)

Read-only target-selection and execution-design pass, per the
professor-approved critical-infrastructure roadmap. **No paid LLM calls
were made to produce this plan** - every fact below was verified by
reading real, currently-published `github.com/free5gc/udr` source
(a fresh, disposable shallow clone, inspected and discarded) and this
project's own already-existing, previously-verified artifacts
(`docs/REACHABILITY.md`, `docs/FREE5GC_LAB.md`,
`src/reachability/verify_against_real_upstream.py`). Nothing here is
implemented yet - this document is the first deliverable; the harness
is the second, separate step.

## Why this CVE, not a new one

The project already has a real, disclosed, independently-verified
free5GC vulnerability with real commit hashes on record
(`docs/REACHABILITY.md`, `docs/FREE5GC_LAB.md`): **CVE-2026-40246** /
**CVE-2026-40248**, both closed by the same upstream fix commit in
`internal/sbi/api_datarepository.go`. The existing work already proves
reachability (102 -> 4 functions) and compile-verification (patched
module builds against the real dependency graph) for this exact case.
Upgrading *this same case* to runtime evidence, rather than picking a
new CVE, reuses already-verified facts instead of re-deriving them, and
directly answers this project's own stated gap ("no live HTTP exploit
attempt was made against the real free5GC UDR service",
`docs/REACHABILITY.md`).

## The exact vulnerability

- **CVE**: CVE-2026-40246 (GHSA-g9cw-qwhf-24jp, CVSS 7.5, CWE-285 Improper Authorization)
- **Component**: free5GC UDR (Unified Data Repository), `github.com/free5gc/udr`
- **File**: `internal/sbi/api_datarepository.go`
- **Handler**: `HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete`
- **Fixed commit**: `86686276a7e226183ee786e3dd6714ec56c78fda` (verified against the GitHub API; same commit already cited in `docs/REACHABILITY.md`)
- **Vulnerable commit**: `86686276a7e226183ee786e3dd6714ec56c78fda^` (its direct parent)

**Verified root cause** (read directly from the real, vendored
pre-fix source, `src/reachability/examples/free5gc_case_study/api_datarepository_vulnerable.go`,
lines 1208-1219):

```go
func (s *Server) HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete(c *gin.Context) {
	influenceId := c.Param("influenceId")
	if influenceId != "subs-to-notify" {
		c.String(http.StatusNotFound, "404 page not found")
	}  // <- no `return`: execution falls through regardless

	subscriptionId := c.Params.ByName("subscriptionId")
	s.Processor().ApplicationDataInfluenceDataSubsToNotifySubscriptionIdDeleteProcedure(c, subscriptionId)
}
```

The real fix (confirmed by reading the current upstream `main` branch,
which already contains it) adds `return` immediately after the 404
write, so an invalid `influenceId` genuinely stops the request instead
of falling through to the real delete.

This handler was chosen over the sibling PUT/GET handlers (also part of
the same CWE-285 family and the same fix commit) specifically because
its exploit has an unambiguous, checkable side effect: a real document
either still exists in MongoDB afterward, or it doesn't - no response-
body parsing ambiguity.

## Real services required (verified from source, not assumed)

| Service | Required? | Why |
|---|---|---|
| **MongoDB** | **Yes, real** | `pkg/service/init.go` calls `mongoapi.SetMongoDB(...)` at startup; the DELETE handler's actual data effect (does the subscription document really disappear) is only meaningful against a real, queryable database, not a stub. |
| **NRF** | **No** | Verified in `pkg/service/init.go`, `Start()`: NRF registration failure is only logged (`logger.InitLog.Errorf("register to NRF failed: %v", err)`), not fatal - UDR continues serving its own SBI routes regardless. `nrfUri` can point at an address nothing is listening on. |
| **TLS certs** | **No** | The official sample config (`configuration.sbi.scheme: http`) supports plain HTTP; using it avoids needing free5GC's cert-generation step entirely. |
| **OAuth2 token issuance** | **No** | `internal/context/context.go`: the data-repository route group's `RouterAuthorizationCheck` middleware skips claims parsing entirely when `OAuth2Required` (config field, commonly `oauth: false` in local/lab configs) is false - to be confirmed exactly at implementation time by reading `pkg/factory/config.go`'s field name, but the code path for disabling it is real and present. |

**Net requirement: only a real MongoDB instance.** No NRF, no other
free5GC network function, no TLS/cert setup, no OAuth2 token flow.

## Config (real, from the official example)

Fetched from `github.com/free5gc/free5gc`'s own `config/udrcfg.yaml`
(the canonical reference config, not guessed):

```yaml
configuration:
  sbi:
    scheme: http
    registerIPv4: 127.0.0.4
    bindingIPv4: 127.0.0.4
    port: 8000
  dbConnectorType: mongodb
  mongodb:
    name: free5gc
    url: mongodb://localhost:27017
  nrfUri: http://127.0.0.10:8000   # unreachable placeholder is fine
```

`oauth: false` will be added/confirmed at this same top level or under
`configuration` when the harness is actually built (exact field name
to be read from `pkg/factory/config.go` at implementation time, not
guessed here).

## Endpoint and requests

- **Route** (relative to the data-repository group,
  `factory.UdrDrResUriPrefix` - exact literal value to be read at
  implementation time, expected to match the documented
  `/nudr-dr/v1/subscription-data` family already cited in
  `docs/FREE5GC_LAB.md`): `DELETE /application-data/influenceData/:influenceId/:subscriptionId`
- **Malicious request**: `DELETE .../application-data/influenceData/attacker-controlled-id/<real-subscription-id>` - an `influenceId` that is *not* the literal string `subs-to-notify`.
  - **Expected vulnerable response**: HTTP 404, body `404 page not found` - but the real subscription document is deleted from MongoDB anyway.
  - **Expected patched response**: HTTP 404, identical body - and the document still exists in MongoDB afterward (the fix's `return` stops execution before the delete call).
- **Benign/legitimate request**: `DELETE .../application-data/influenceData/subs-to-notify/<real-subscription-id>` - the correct, documented `influenceId`.
  - **Expected response on both versions**: the real delete procedure runs as intended (its own success/failure response), and the targeted document is removed - this is the *intended* behaviour of the route, not a security bypass, and must be preserved identically pre- and post-patch.
- **Inconclusive criteria**: MongoDB unreachable at test time; UDR process fails to bind its SBI port within a timeout; any response that is neither the expected 404 nor a MongoDB-driver-level error (e.g. a Go panic/stack trace) - reported as `inconclusive_crash`, mirroring the vocabulary already established in `src/pipeline/patch.py`'s corrected validator (Section 4.1.2 of the FYP report), not silently folded into "blocked" or "not blocked".

## What evidence will be saved

Per the requested bundle shape, under a new `free5gc_runtime_case/`
directory:

```
free5gc_runtime_case/
  manifest.json          # CVE, commits, component, services, verdict, timestamps
  vulnerable_commit.txt  # the exact pre-fix commit hash
  patch.diff             # real `git diff` between vulnerable and fixed commit, for this file only
  exploit_request.http   # the exact malicious DELETE request sent (method, path, headers)
  benign_request.http    # the exact legitimate DELETE request sent
  vulnerable_response.log  # real HTTP response + MongoDB document state, vulnerable commit
  patched_response.log     # real HTTP response + MongoDB document state, patched commit
  build_before.log       # `go build ./...` output, vulnerable commit (already have this pattern from verify_against_real_upstream.py)
  build_after.log        # `go build ./...` output, patched commit
  verdict.json           # patch_exploit_blocked / patch_function_preserved / patch_verdict, same vocabulary as the main pipeline
```

## No-paid-backend guarantee

This entire case needs **zero LLM calls**: the "patch" is the real
upstream maintainers' own commit (`git checkout` to the fixed commit,
or a direct `git diff`/`git apply` of the one fix commit), not an
LLM-generated one, exactly like the existing `jaraco.context` real-
upstream case (`reports/real_upstream_case/CVE-2026-23949/`). The
harness will not import or call `cve_pipeline.py`'s
`_call_live_model`/`_call_claude`/`_call_ollama` at all. As an explicit,
tested second layer of protection (not just "we didn't write code that
calls it"), `cve_pipeline.py` now has a `NO_PAID_BACKEND` environment
guard (committed `32ae137`) that makes any call to the real Claude CLI
raise immediately rather than silently proceed; the free5GC harness
script will set `NO_PAID_BACKEND=1` in its own environment before doing
anything, as a defense-in-depth measure even though it never imports
`cve_pipeline` in the first place.

## Execution plan (implementation, not started yet)

1. Clone `free5gc/udr` at the vulnerable commit into an isolated
   directory (same discipline as `verify_against_real_upstream.py`).
2. Start a real, local MongoDB (Docker Desktop needs to be running for
   this - confirmed not currently running on this machine; a native
   `mongod` binary is a fallback if Docker is unavailable).
3. Write the local config YAML above, confirm the exact `oauth`/OAuth2
   field name and the exact `UdrDrResUriPrefix` route prefix by reading
   `pkg/factory/config.go` and the router setup once more at this
   stage (both already located, not yet read to their exact literal
   values in this planning pass).
4. Seed one real subscription document directly into MongoDB (the
   collection name is read directly from
   `internal/sbi/api_datarepository.go`'s processor calls, not
   guessed).
5. Build and run the vulnerable commit's UDR binary; send the
   malicious request; confirm the document is gone; send the benign
   request against a freshly reseeded document; confirm it behaves as
   intended. Save all evidence.
6. Repeat steps 4-5 against the patched commit exactly.
7. Write `verdict.json` and the full evidence bundle.
8. Update `docs/REACHABILITY.md`/`docs/FREE5GC_LAB.md` to point at this
   new, stronger result, and note explicitly that it supersedes the
   "no live HTTP exploit attempt" caveat for this one case.

Not started: this document is the read-only design deliverable only.
