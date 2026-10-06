# OpenEMR healthcare transfer case: results (GHSA-q366-cv5v-83w8)

Branch: `openemr-transfer-scope`. `main` and the FYP report are
untouched by this work.

## Goal

`docs/OPENEMR_TRANSFER_CASE_PLAN.md` scoped this branch as a small,
bounded test of whether the same evidence-gated confirmation method
used for free5GC transfers to a second, unrelated domain: healthcare.
This document records the result of actually implementing and running
that harness, per the explicit instruction to implement only this one
target and stop, not expand scope.

## Target

**GHSA-q366-cv5v-83w8**: unauthenticated information disclosure in
OpenEMR's `admin.php`. No CVE number is assigned to this advisory (its
`cve_id` field is `null`, confirmed via the GitHub API during the
earlier design pass).

- **Vulnerable commit**: `b5313ea25f7928538eb793d4b4184ed4601d9afd`
- **Fixed commit**: `50f789fad45ada625fe8d0faf0c7a9c15ef52aa5` (PR #13133)
- **The fix**: an opt-in guard added at the very top of `admin.php`,
  before any other logic runs - if `OPENEMR_ADMIN_PHP_ENABLED` is not
  set to `1` (via server variable or environment variable), the script
  returns `403` with a plain-text explanation and exits immediately.
  Structurally the same class of fix as free5GC's missing `return`: an
  early-exit guard added before the sensitive code path, not a rewrite
  of the underlying logic.

## Deployment

Per the user's explicit design (a deliberate departure from this
branch's own earlier design-pass conclusion, which had proposed native
PHP + MariaDB once Docker's status was uncertain): Docker containers,
not a native install, since Docker Desktop was confirmed working again
during the free5GC full-deployment work.

- **MariaDB**: real, official `mariadb:10.11` image, with only the two
  tables `admin.php`'s own read path needs (`globals`, `version`), not
  OpenEMR's full multi-hundred-table schema - the same minimal-
  dependency-scoping principle already applied to both free5GC
  harnesses. Seeded with fake, clearly-labelled local test values only
  (`schema.sql`).
- **PHP**: a minimal image built from `php:8.2-cli` with the `mysqli`
  extension installed (`Dockerfile.php`), running PHP's own built-in
  development server (`php -S`) - no Apache, no full OpenEMR setup
  wizard, no Composer install. The real, unmodified OpenEMR checkout is
  bind-mounted into the container at runtime, so the same image serves
  both the vulnerable and patched commit by swapping the mounted
  directory and re-creating the container between runs.
- The two containers communicate over a dedicated Docker bridge network
  (`openemr-transfer-net`); the PHP container's port 8000 is published
  to `127.0.0.1:8090` for the harness to reach from the host.

## Request sequence and result

Three requests, run by `openemr_transfer_case/run_harness.py`:

| Request | Expected | Actual (this run) |
| --- | --- | --- |
| Vulnerable commit, `GET /admin.php`, no env var | `200`, metadata disclosed | `200`. Real disclosure confirmed: the rendered table shows Site ID `default`, DB Name `openemr_test`, Site Name and version pulled directly from the seeded `globals`/`version` rows. |
| Patched commit, `GET /admin.php`, no env var | `403`, metadata blocked | `403`, body exactly `admin.php is disabled by default. See the header comment in this file to enable.` - no site, database, or version data anywhere in the response. |
| Patched commit, `GET /admin.php`, `OPENEMR_ADMIN_PHP_ENABLED=1` | `200`, admin page works | `200`, identical disclosure content to the vulnerable run - confirms the fix is a default-closed gate, not a removal of the underlying admin functionality, the same "legitimate use still works" standard used throughout the free5GC work. |

**Verdict** (`evidence/verdict.json`): `confirmed_fix`, reusing the same
four-outcome verdict vocabulary (`confirmed_fix` /`not_blocked` /
`regression_broke_route` / `inconclusive_crash`) established for the
free5GC harnesses rather than inventing a new one.

## Two real implementation issues found and fixed while running this

Both are documented here because they were genuine bugs surfaced only
by running the harness for real, consistent with this project's own
established pattern (the free5GC harness's NRF-registration and h2c
discoveries are the direct precedent):

1. **A startup race in the official MariaDB image**: `mysqladmin ping`
   can succeed against an internal, password-less bootstrap instance the
   image's entrypoint runs over the Unix socket before the final,
   fully-initialized server (with the real root password committed)
   takes over, so a ping-based readiness check can report "ready"
   moments before the real root login actually works. Fixed by
   retrying the *actual* authenticated schema-load login in a loop,
   rather than trusting a separate ping.
2. **A startup race in PHP's built-in development server**: it can
   accept a TCP connection (satisfying a naive readiness check)
   fractionally before its request-handling loop is actually serving
   requests, resetting the very next request with a bare connection
   close. Fixed by separating "is the port open" (a lightweight TCP
   connect, used only for the readiness wait) from "does a real request
   succeed" (the actual evidence-gathering request, which now retries a
   few times on connection error before failing for real).

A third, cosmetic issue (two PHP "undefined array key" warnings for
`v_database`/`v_acl`, columns the minimal seed schema initially omitted)
was found in the first clean run's raw response body and fixed by adding
those two columns to `schema.sql`, seeded with the same values
`version.php` itself defines at these commits (`541`, `13`), so the
evidence is clean rather than merely "correct but noisy."

## Evidence bundle

Under `openemr_transfer_case/evidence/`:

| File | Contents |
| --- | --- |
| `manifest.json` | Structured record: advisory, commits, deployment description, full per-request result objects for all three requests. |
| `verdict.json` | The three boolean checks plus the overall `confirmed_fix` verdict. |
| `vulnerable_default_response.log`, `patched_default_response.log`, `patched_optin_response.log` | Full raw HTTP status, headers, and body for each of the three requests. |
| `container_or_process_logs/` | Raw PHP container logs for both builds. |

## What this does not establish

- This is one advisory in one file, chosen specifically because it has
  a safe, unauthenticated request/response oracle with no RCE or
  destructive payload - it is not a systematic security assessment of
  OpenEMR.
- The minimal two-table schema and bind-mounted single-file deployment
  demonstrate the vulnerability's own logic precisely, but do not
  demonstrate anything about OpenEMR's full application behaviour,
  authentication system, or the other components a production
  deployment would include.
- Per the plan this branch was scoped to, this remains a **transfer
  case** alongside free5GC, not a replacement for it: free5GC has full
  CRUD runtime confirmation across four handlers under a fuller
  deployment (see `free5gc-full-deployment`); this OpenEMR case is one
  handler, deliberately kept small to test method transfer rather than
  to match free5GC's depth.

## Status

Implementation complete, evidence captured, verdict `confirmed_fix`.
**Update, 2026-10-06**: commit `6cf91f5` (this work) is already present
on `main` (confirmed via `git branch --contains 6cf91f5`) - the "not
merged" note above is stale. Not added to the FYP report. Per explicit
instruction, this case was later extended with the same LLM
patch-generation and bypass-probe experiments already run against
free5GC - see `docs/OPENEMR_LLM_PATCH_RESULTS.md` and
`docs/OPENEMR_BYPASS_PROBE_RESULTS.md` - reversing the "stop here" note
below, which described this pass's scope only, not a permanent limit.
