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

## Implementation attempt, 2026-09-27: blocked on Docker Desktop itself

Implementation was started per the approved instruction (harness only,
`NO_PAID_BACKEND=1`, no scope broadening). Docker Desktop's daemon was
not running (`docker ps` failed with
`failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine`).
Docker Desktop was launched (the already-installed application, not a
new install) and given time to initialize.

**It does not come up.** Its own startup log shows a real internal
failure, not a slow cold start:

```
starting services: initializing Inference manager: listening on
unix://C:\Users\dheer\AppData\Local\Docker\run\dockerInference: remove
C:\Users\dheer\AppData\Local\Docker\run\dockerInference: The file
cannot be accessed by the system. (listener: The filename, directory
name, or volume label syntax is incorrect.)
```

Docker Desktop's own "Inference manager" component (its local AI/model-
runner feature, unrelated to this project and unrelated to running a
plain MongoDB container) fails to clean up a stale socket file at
`C:\Users\dheer\AppData\Local\Docker\run\dockerInference` on this
specific machine, and this failure blocks the whole application from
reaching a working state - `docker ps` continued failing with the
identical named-pipe error for the entire wait window, confirming this
is not a transient cold-start delay.

**No native MongoDB fallback is available either** (`mongod`, `mongosh`,
`mongo` are all absent from PATH on this machine).

**Stopping here, per instruction**, rather than attempting to repair
Docker Desktop's own internal state (deleting its AppData files,
reinstalling it, etc.) - that is a machine-configuration fix unrelated
to this project's own code or research question, not a harness design
choice.

**Exact required action** (one of, needed before this specific Phase 2
case can proceed):
1. Manually delete or rename
   `C:\Users\dheer\AppData\Local\Docker\run\dockerInference` (the
   specific file/path named in Docker's own error) and retry starting
   Docker Desktop, or disable the "Docker AI"/model-runner feature in
   Docker Desktop's own settings if that avoids the Inference manager
   entirely, or repair/reinstall Docker Desktop if neither resolves it; or
2. Install a native MongoDB Community Server binary directly (no
   Docker needed at all) and point the harness's `mongodb.url` at
   `mongodb://localhost:27017` as already specified above - this avoids
   the Docker dependency entirely and is likely the faster path to
   unblock this specific case, since the harness needs nothing else
   Docker-specific (it does not need `docker-compose`, only a running
   MongoDB it can connect to).

The harness code itself (steps 1-9 of the execution plan above) is
still unimplemented, blocked on either of the two options above being
resolved first.

## Resolved, 2026-09-27: native MongoDB installed instead of repairing Docker

Per explicit direction, Docker Desktop was abandoned rather than
repaired: this experiment only ever needed a real, reachable MongoDB at
`mongodb://localhost:27017`, not Docker itself, so Docker was removed
from the dependency chain entirely rather than debugged.

**Installed MongoDB Community Server 8.3.11** via `winget install
MongoDB.Server` (package verified against its published installer
hash by winget itself before installing). It registers and starts
automatically as a Windows service (`sc query MongoDB` ->
`STATE: RUNNING`), no manual `mongod` invocation needed.

**Verified real, end-to-end, not just "service running"**:
- `netstat -ano` confirms something is genuinely listening on
  `127.0.0.1:27017`.
- A real `pymongo` client (installed via `pip install pymongo`) connected
  and ran `client.admin.command("ping")` -> `{"ok": 1.0}`, and
  `client.server_info()["version"]` -> `"8.3.11"`, confirming a real,
  responsive MongoDB server, not just an open port.

This is the engineering choice to state plainly in the eventual report:
the runtime validation harness uses a local MongoDB instance directly
rather than Docker, because the experiment's only real dependency was
UDR's own database connection - this reduces infrastructure complexity
without changing what's actually under test.

## Correction, 2026-09-27: NRF registration is a blocking infinite retry, not "logged and non-fatal"

This plan originally concluded (based on a shallow read of
`pkg/service/init.go`'s `Start()` wrapper alone) that a failed NRF
registration was only logged, not fatal, to UDR startup. Running the
harness for real disproved that: the vulnerable UDR process never bound
to port 8000 within a 30-second wait window.

Reading `Start()` more completely shows it is fully sequential:
`a.registerToNrf(a.ctx)` (blocking) -> MongoDB connect -> HTTP server
bind. And `internal/sbi/consumer/nrf_service.go`'s
`SendRegisterNFInstance` is a genuine infinite retry loop (`for
!finish { ...; time.Sleep(2*time.Second); continue }`) with no
give-up condition except success or context cancellation. Without a
reachable NRF at the configured `nrfUri` (`http://127.0.0.10:8000`),
UDR never starts its own HTTP server, so the whole runtime case is
unreachable.

**Fix: a stub NRF**, satisfying only the one call UDR needs
(`PUT .../nf-instances/{id}`, i.e. `RegisterNFInstance`) with a minimal
valid response (`nfInstanceId`/`nfType`/`nfStatus` - the only three
required, non-`omitempty` fields of `models.NrfNfManagementNfProfile`,
confirmed by reading the real vendored struct). This stub does not
perform discovery, does not track other NFs, and has no bearing on the
vulnerability under test (the data-repository DELETE handler's own
missing `return`), which is entirely independent of NRF's behaviour.

**First stub attempt (Python `http.server`) failed for a second,
unrelated reason**: free5gc's NRF client
(`github.com/free5gc/openapi`'s `innerHTTP2CleartextClient`) uses
`golang.org/x/net/http2` with `AllowHTTP: true`, dialing with prior
knowledge of HTTP/2 framing (h2c) - not plain HTTP/1.1. A Python
`http.server`-based stub can only answer HTTP/1.1, which the client
misparses as malformed HTTP/2 frames, failing with `http2: frame too
large` / connection-abort errors. This was confirmed live: the
Python stub's connections were repeatedly aborted with exactly that
client-side error.

**Working fix**: a small standalone Go binary, `stub_nrf/main.go`,
using `golang.org/x/net/http2/h2c` to serve real HTTP/2 cleartext,
answering the one `PUT` call UDR needs. `golang.org/x/net` was already
an indirect dependency of the UDR module, so no new dependency was
introduced. Built once (`go build`) into `stub_nrf.exe` and launched as
a subprocess by `run_harness.py` around each of the two `run_case()`
calls.

## Result, 2026-09-27: CVE-2026-40246 runtime-confirmed, patch runtime-validated

With the h2c stub NRF in place, both runs completed with real,
non-inconclusive verdicts:

- **Vulnerable commit** (`86686276a7e226183ee786e3dd6714ec56c78fda^`):
  the malicious `DELETE
  /nudr-dr/v2/application-data/influenceData/attacker-controlled-id/<subId>`
  request itself received `404` (the handler's own
  `influenceId != "subs-to-notify"` check fires and writes a 404 body
  in both versions), but a follow-up `GET` confirmed the subscription
  record was deleted anyway (`post_malicious_check_status: 404`) - the
  vulnerable version falls through and deletes server-side despite
  already having written the 404 response, because the original code
  has no `return` after that write.
- **Patched commit** (`86686276a7e226183ee786e3dd6714ec56c78fda`): the
  same malicious request again received `404`, but the follow-up `GET`
  confirmed the record still existed (`post_malicious_check_status:
  200`) - the added `return` stops execution before the delete runs.
- **Benign path preserved on both**: a legitimate `DELETE` using the
  correct `influenceId` ("subs-to-notify") returned `204` and the
  record was subsequently confirmed gone (`post_benign_check_status:
  404`) on both the vulnerable and patched builds - the fix does not
  break the real functionality.

This directly matches the CVE's own description (missing `return`
after a 404 write -> the delete runs regardless) and is now confirmed
against the real upstream binary at runtime, not just by static/compile
review. Full evidence bundle (`manifest.json`, `verdict.json`,
`patch.diff`, `vulnerable_response.log`, `patched_response.log`,
`vulnerable_process.log`, `patched_process.log`,
`build_vulnerable.log`, `build_patched.log`) is saved under
`free5gc_runtime_case/`.

This upgrades the free5GC case from "patch compile-verified" to
"vulnerability runtime-confirmed and patch runtime-validated" in the
FYP report.

Proceeding directly to harness implementation now.
