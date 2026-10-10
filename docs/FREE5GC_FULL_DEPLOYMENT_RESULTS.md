# free5GC full-deployment extension: CVE-2026-40248, all four CRUD handlers

Branch: `free5gc-full-deployment`. `main` and the frozen FYP report are
untouched by this work.

## Goal

The existing, report-incorporated free5GC runtime case
(`free5gc_runtime_case/`, commit `70281e5` on `main`) runtime-confirmed
one of four reachable handlers (the DELETE subscription handler) using a
minimal harness: a real MongoDB, but a hand-written stub NRF satisfying
only UDR's own startup registration call. Future Work item 2 in the
frozen report names extending this to the remaining three handlers, or a
fuller deployment, as the natural next step. This branch does both at
once: it uses the official `free5gc-compose` Docker stack (real
MongoDB, real free5GC NRF - not a stub) and tests all four reachable
handlers, not just one.

## Environment note: a caught mistake

While building the custom UDR Docker image, the vulnerable/fixed commit
hashes from the *unrelated* OpenEMR transfer-case work (done earlier in
the same session, on a different branch) were mistakenly passed as the
build arguments instead of free5GC's own commit hashes. The build failed
immediately and cleanly (`git checkout` could not find that commit in
`free5gc/udr`'s history, since it belongs to a different repository
entirely), so no incorrect image or result was ever produced. The
correct hashes (from `free5gc_runtime_case/vulnerable_commit.txt` and
`manifest.json`, already established and verified in the frozen report)
were used for the actual build. Noted here as a real caution about
working two unrelated CVE cases in one session: commit hashes look
identical in shape and are easy to transpose.

## Deployment

- **MongoDB**: real, official `mongo:4.4` image, via `free5gc-compose`'s
  own `docker-compose.yaml`, unmodified.
- **NRF**: real, official `free5gc/nrf:v4.2.3` image, unmodified except
  for one config change: `oauth: false` in `config/nrfcfg.yaml` (was
  `true`). This was necessary, not cosmetic: with OAuth2 enabled, every
  SBI request to UDR requires a valid bearer token issued by the NRF's
  own OAuth2 authorization server, which blocks reaching the vulnerable
  handler logic at all without first building a full OAuth2
  client-credentials flow - a large, orthogonal piece of work unrelated
  to the vulnerability under test. Disabling OAuth2 is a real, supported
  free5GC configuration option, not a workaround specific to this
  harness. **OAuth2 enforcement itself is therefore explicitly out of
  scope for this result** - this harness demonstrates the missing-return
  bug's exploitability once a request reaches the handler, not whether
  OAuth2 would have prevented an unauthenticated attacker from reaching
  it in an OAuth2-enabled deployment.
- **UDR**: custom-built via `udr_build/Dockerfile`, which clones the real
  `github.com/free5gc/udr` repository at a build-arg-specified commit
  and compiles it with `go build` - the same real-source discipline as
  `free5gc_runtime_case/`, just packaged as a Docker image instead of a
  bare binary, so it can run inside the official compose network and
  register with the real NRF.
- Only `db`, `free5gc-nrf`, and `free5gc-udr` are brought up. `free5gc-amf`,
  `free5gc-smf`, `free5gc-upf`, and the rest of the mesh are not started:
  they are not exercised by a data-repository HTTP handler bug, and
  `free5gc-upf` specifically requires a Linux kernel module (`GTP5G`)
  that has nothing to do with this vulnerability class.

## The four handlers, and what running them for real found

All four of the reachability engine's originally-flagged handlers share
the same root cause: a validation check writes a non-2xx response
(`c.String` or `c.JSON`) when the caller passes an invalid path segment
`influenceId`, but does not `return` afterward, so the handler's own
success-path code still executes and, in three of the four cases,
writes a *second* response body onto the same connection. Go's
`net/http` frames each `Write()` call as its own chunk when no explicit
`Content-Length` has been set, so both writes reach the client on the
same HTTP response - the second write does not get silently dropped.

| Handler | Vulnerable-build behaviour, confirmed live | Patched-build behaviour, confirmed live |
| --- | --- | --- |
| GET (collection, `.../subs-to-notify`, no query filters) | Response reads `400 Bad Request` with the real error JSON, but the raw body is followed by a JSON array of **every** influence-data subscription in the system - the empty-filter branch matches every stored record. Confirmed against a live-seeded subscription: the full subscription content was present in the 400 response's body. | `400 Bad Request`, body is only the error JSON - no appended data. |
| GET (single, wrong `influenceId`) | `404 Not Found`, but body is `404 page not found` immediately followed by the real subscription's JSON content. | `404 Not Found`, body is exactly `404 page not found` - no appended content. |
| PUT (single, wrong `influenceId`) | `404 Not Found` returned to the caller, but a follow-up read confirms the subscription **was created** - an unauthorized write, not merely an information leak: an attacker's data is stored under a request that appears to have failed. | `404 Not Found`, and a follow-up read confirms nothing was stored. |
| DELETE (single, wrong `influenceId`) | Already runtime-confirmed on `main` (commit `70281e5`): `404 Not Found` returned, but the record is deleted anyway. Re-confirmed here for consistency under the fuller deployment. | Record survives; already documented, re-confirmed here. |
| Benign path (GET, correct `influenceId`) | `200 OK` with the real, correct subscription content, on both builds - the fix does not break legitimate use. | Same. |

**This is a materially stronger characterization of CVE-2026-40248 than
what is currently in the frozen FYP report.** The report documents a
single-record unauthorized delete. The real behaviour, confirmed here
against a real deployment, is a full CRUD bypass: unauthorized read of
one record, unauthorized read of the *entire* collection, unauthorized
write, and unauthorized delete, all via the same one-line root cause
(missing `return`), all fixed by the same one-line upstream patch.

## Evidence bundle

Automated by `free5gc_full_deployment/run_full_deployment_harness.py`,
written to `free5gc_full_deployment/evidence/`:

| File | Contents |
| --- | --- |
| `RAW_FINDINGS.md` | The initial manual `curl`-based discovery, kept as the first-principles record before the harness automated it. |
| `manifest.json` | Structured record of both runs: commit hashes, deployment description, full per-run result objects for all four handlers. |
| `verdict.json` | Per-handler boolean verdicts plus `overall_verdict: "confirmed_fix_all_four_handlers"`. |
| `vulnerable_response.json`, `patched_response.json` | Full raw HTTP status/headers/body for every request in the sequence, for both builds. |
| `vulnerable_process.log`, `patched_process.log` | Raw UDR container logs, including real NRF registration confirmation. |

## What this does not establish

- OAuth2 was disabled to make the vulnerability testable at all (see
  above); this harness says nothing about whether OAuth2 enforcement
  would change the practical exploitability of this bug in a deployment
  that has it enabled.
- AMF, SMF, UPF, and the rest of the free5GC mesh were not started; this
  remains a UDR-component-level result, not a full-core-network one.
- This is still one bug class (the missing-`return` pattern) across four
  handlers in one file, not a broader audit of free5GC's other
  components.

## Status

Implementation complete, evidence captured, not yet folded into any
report. `main` is untouched. Whether to update the frozen FYP report
with this stronger characterization is a separate decision for the
report owner, given the report was deliberately frozen after multiple
rounds of review.


> **Metric interpretation:** `confirmed_fix_all_four_handlers` means the full validation pipeline passed. Four handlers are tested, but only one handler change is model-generated; three are deterministic reachability materializations. It is not a rate of independently model-generated four-handler patches.
