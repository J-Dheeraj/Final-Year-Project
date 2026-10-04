# OpenEMR Healthcare Transfer Case Plan

## Purpose

This branch starts a small healthcare transfer case for the FYP without changing the stable free5GC report or the `main` branch. The goal is not to expand the current report immediately. The goal is to determine whether the same evidence-gated method used for free5GC can transfer to a second DARPA-relevant critical-infrastructure domain: healthcare.

OpenEMR is a good candidate because it is an actively maintained open-source electronic health record and medical practice management system, has recent public security advisories, and has an official Docker-based deployment path. That makes it a realistic healthcare system target while still being suitable for controlled local testing.

## Why OpenEMR fits the project

OpenEMR gives the project a domain transfer from telecommunications to healthcare:

- free5GC demonstrates a 5G core / telecom case.
- OpenEMR would demonstrate a healthcare / electronic health record case.
- Both are real open-source systems rather than synthetic reproductions.
- Both require dependency-aware harness design instead of a single-file proof of concept.
- The comparison can strengthen the FYP narrative: the workflow is not tied to one language, framework, or industry.

This should be treated as a transfer case only if it can stay bounded. The existing report is already content-complete; OpenEMR should not be allowed to destabilise the report unless the supervisor explicitly wants a second case study included.

## Source-backed candidate advisories

The candidates below are selected from public OpenEMR/GitHub advisory sources. They are not yet implemented or validated in this repository.

| Candidate | Advisory source | Affected / fixed version | Why it is interesting | Initial suitability |
| --- | --- | --- | --- | --- |
| OpenEMR backup command injection / RCE | GHSA-6pmc-3xm7-pm86 | `< 8.0.0.2` / `8.0.0.2` | High-impact server-side bug with a concrete patched version. It would test whether the pipeline can validate a backend security fix in a full web application. | Strong research value, but risky as a first implementation because safe local validation must avoid producing a weaponised shell/RCE demonstration. Use only with a harmless observable command or skip if that cannot be done safely. |
| Unauthenticated `admin.php` information disclosure | GHSA-q366-cv5v-83w8 | `< 8.3.0` / `8.3.0` | Simple externally reachable behaviour: unauthenticated visitor sees sensitive deployment metadata before the fix and should not after the fix. | Best first target. It is easier to validate safely, avoids destructive payloads, and can be tested with request/response evidence. |
| Arbitrary file write leading to RCE | GHSA-5vp5-4rm6-h4c9 / CVE-2026-24848 | Advisory-published OpenEMR case | High-impact file-write/RCE class with direct relevance to patch validation. | Defer. It has strong impact but likely requires file-system side effects and careful cleanup. Better as a second or third OpenEMR target after the harness is proven. |
| OOB SSRF in PDF generation | GHSA-5pc3-2crw-96rv | `<= 8.0.0.1` / `8.0.0.2` | Similar to the existing SSRF class, but in a real healthcare application and PDF-generation path. | Plausible, but requires a local callback/canary server and authenticated workflow setup. Good if the project wants a network-observable class. |
| Reflected XSS in patient portal template import | GHSA-pqfg-4hrq-q9jm / CVE-2026-40507 | `< 8.3.0` / `8.3.0` | Recent OpenEMR 8.3.0 advisory; browser-visible class. | Plausible but lower priority. Requires authenticated role setup and browser/HTML assertion design. |

Primary sources inspected:

- https://github.com/openemr/openemr/security/advisories/GHSA-6pmc-3xm7-pm86
- https://github.com/openemr/openemr/security/advisories/GHSA-q366-cv5v-83w8
- https://github.com/openemr/openemr/security/advisories/GHSA-5vp5-4rm6-h4c9
- https://github.com/openemr/openemr/security/advisories/GHSA-5pc3-2crw-96rv
- https://github.com/advisories/GHSA-pqfg-4hrq-q9jm
- https://github.com/openemr/openemr/blob/master/docker/production/docker-compose.yml
- https://www.open-emr.org/releases/

## Recommended first target

Start with GHSA-q366-cv5v-83w8: unauthenticated `admin.php` information disclosure.

Reason:

1. It is healthcare-domain specific but technically simple.
2. It avoids starting with RCE or destructive file-write behaviour.
3. It has clear pre/post evidence: unauthenticated request exposes metadata before the fix, and the patched version should not expose the same data.
4. It should be suitable for a deterministic HTTP harness, similar in spirit to the free5GC runtime harness but simpler.
5. It gives a clean reportable result even if only scoped as future work: “candidate selected because it has safe, observable pre/post behaviour.”

## Proposed evidence standard

For the selected OpenEMR target, a result should not be considered confirmed unless all of the following hold:

1. The vulnerable and patched targets are pinned to explicit versions, tags, commits, or image digests.
2. The harness starts OpenEMR and its database locally, with no public exposure.
3. The exploit check uses a harmless HTTP request and records status code plus response-body evidence.
4. The patched check confirms the sensitive behaviour is blocked or removed.
5. A benign check confirms the patched application still serves a normal login or health page.
6. All raw request/response logs, container logs, version identifiers, and harness configuration are saved.

## Expected harness dependencies

Likely dependencies:

- Docker or an equivalent container runtime.
- OpenEMR container or source checkout pinned to the vulnerable version.
- MariaDB/MySQL service.
- A deterministic setup script for admin credentials and initial site configuration.
- Python HTTP client for request/response checks.
- A no-paid-backend guard, following the free5GC pattern, so scoping and harness runs do not accidentally invoke hosted model APIs.

## Go / no-go criteria

Proceed to implementation only if all conditions below are true:

- OpenEMR can be started locally in a repeatable way within a reasonable time budget.
- The target advisory can be validated with harmless request/response evidence.
- The fixed version can be run under the same harness with minimal changes.
- The experiment can be completed without modifying the stable FYP report draft.
- The result can be summarized as a branch artifact even if it is not folded into the final report.

Stop or switch target if any of the following happen:

- Docker or the database dependency becomes the main engineering work.
- The candidate requires weaponised RCE, reverse shells, credential theft, or public callback infrastructure.
- The patched and vulnerable versions cannot be pinned cleanly.
- The harness requires extensive UI automation instead of stable HTTP-level checks.
- The work begins to pull attention away from polishing and defending the already-stable report.

## Branch policy

This work is intentionally isolated on a non-main branch. The stable report and free5GC result should remain frozen on `main` unless the supervisor explicitly asks for OpenEMR to be incorporated.

Suggested branch: `openemr-transfer-scope`.

## Next concrete step

If this branch continues, the next step is a read-only technical design pass for GHSA-q366-cv5v-83w8:

1. identify the exact vulnerable and fixed OpenEMR versions or commits;
2. identify the quickest local deployment route;
3. define the single unauthenticated request and the forbidden response markers;
4. define the benign patched-application check;
5. write an evidence-bundle schema before running anything.

No exploit implementation should be written until those five facts are known.

## Design pass, 2026-09-28: five facts above, now answered

Read-only. No harness code was written and no HTTP requests were made
against a running OpenEMR instance. Everything below was verified
against the real GitHub repository (`openemr/openemr`) via the GitHub
API, following the same "verify before use" discipline established for
the free5GC case.

### 1. Exact vulnerable and fixed commits (no CVE assigned)

- **Advisory**: GHSA-q366-cv5v-83w8, "Unauthenticated Information
  Disclosure in `admin.php` Exposes Database Names and Versions" (CWE-200,
  CWE-306; CVSS 3.1 5.3, medium). Fetched directly via
  `gh api repos/openemr/openemr/security-advisories/GHSA-q366-cv5v-83w8`.
  Its `cve_id` field is `null` - this advisory has **no CVE number**,
  only a GHSA ID; the earlier candidate table's "GHSA only" framing was
  correct and should not be paired with an invented CVE number.
- **Fixed commit**: `50f789fad45ada625fe8d0faf0c7a9c15ef52aa5` (PR #13133,
  merged 2026-07-25), commit message: "admin.php: gate behind opt-in
  `OPENEMR_ADMIN_PHP_ENABLED` env var (matches existing Docker + wiki
  guidance)."
- **Vulnerable commit**: `b5313ea25f7928538eb793d4b4184ed4601d9afd` (the
  fixed commit's direct parent).
- **Release cross-check**: the `v8_3_0` tag (commit `ebb62eb3...`) is 223
  commits ahead of and 0 commits behind the fix commit, confirming the
  fix commit is a genuine ancestor of the `8.3.0` release the advisory
  cites as the patched version.
- **The actual fix** (read directly from the commit's diff): a
  guard block added at the very top of `admin.php`, before any other
  `require_once` or logic runs:
  ```php
  if (
      filter_input(INPUT_SERVER, 'OPENEMR_ADMIN_PHP_ENABLED') !== '1'
      && (getenv('OPENEMR_ADMIN_PHP_ENABLED') ?: '') !== '1'
  ) {
      http_response_code(403);
      header('Content-Type: text/plain');
      echo "admin.php is disabled by default. See the header comment in this file to enable.\n";
      exit;
  }
  ```
  This is structurally the same class of fix as free5GC's missing
  `return` (an early-exit guard added before the sensitive code path),
  which strengthens the case that this project's evidence-gated
  methodology transfers across languages, not just across the one Go
  fix pattern it was built against.

### 2 and 3. Docker status: still broken, documented immediately

Re-tested live on 2026-09-28: relaunched Docker Desktop and re-ran
`docker ps`. Identical failure to the one recorded during the free5GC
work, same root cause, confirmed from Docker's own backend log
(`%LOCALAPPDATA%\Docker\log\host\com.docker.backend.exe.log`):
```
backend cancelling with error: starting services: initializing Inference manager:
listening on unix://<HOME>\AppData\Local\Docker\run\dockerInference:
remove <HOME>\AppData\Local\Docker\run\dockerInference: The file cannot be
accessed by the system. (listener: The filename, directory name, or volume
label syntax is incorrect.)
```
Per the same standing decision as the free5GC work, this was not
debugged further - Docker Desktop is not being repaired for this
project. The question this raises, per item 3, is whether OpenEMR's own
official Docker Compose route is worth chasing anyway. It is not: the
next section shows this specific vulnerability does not require it.

**Reassessed native-dependency footprint (lower than first scoped)**:
reading `admin.php`'s actual source at the vulnerable commit shows its
real dependency graph is much narrower than "the whole OpenEMR
application":
- It `require_once`s exactly two files, both side-effect-free and
  DB-free: `src/Common/Compatibility/Checker.php` (a pure PHP-version
  string check) and `version.php` (pure constant definitions, minimum
  PHP version required: `8.2.0`).
- It does **not** bootstrap the full framework
  (`interface/globals.php` is deliberately not required - this is the
  advisory's own stated root cause).
- It lists `sites/` for any directory containing a `sqlconf.php`, reads
  that file for `$config`/`$host`/`$login`/`$pass`/`$dbase`/`$port`, and
  if `$config` is truthy, connects via `mysqli_connect` and runs exactly
  two queries: `SELECT gl_value FROM globals WHERE gl_name =
  'openemr_name' LIMIT 1` and `SELECT * FROM version LIMIT 1` (columns
  `v_major`, `v_minor`, `v_patch`, `v_tag`, `v_realpatch`).

This means a faithful, real-source demonstration does **not** need the
full OpenEMR application, its Composer install, Apache, or its setup
wizard - only: (a) a real clone of the repo at the two commits (for
`admin.php`, `Checker.php`, `version.php`, served directly), (b) PHP's
own built-in development server (`php -S`, no Apache/Docker needed) with
the `mysqli` extension enabled, (c) a hand-written `sites/default/sqlconf.php`
pointing at a real, local MariaDB instance, and (d) a **minimal** schema
in that database - just a `globals` table and a `version` table with one
row each, not OpenEMR's full multi-hundred-table schema. This is the same
minimal-dependency-scoping principle already applied to the free5GC
harness (only UDR's own MongoDB connection was needed, not a full 5G
core), now shown to transfer to a second language and framework. PHP
8.2+ and MariaDB are both installable via `winget`, the same tool used
to install MongoDB natively for the free5GC case. **Revised conclusion**:
native PHP + MariaDB is not a "bigger lift" than the free5GC MongoDB
substitution as first assumed when this plan was scoped against Docker -
it is comparably minimal, provided the harness stays scoped to this one
file rather than attempting full-application functional testing.

### 4. Exact harmless HTTP request/response assertions

Two requests against the same running `admin.php`, distinguished only by
an environment variable, mirroring the free5GC harness's
malicious/benign pair:

- **Default-config request** (the vulnerability's own default state,
  before an operator has opted in): `GET /admin.php` with
  `OPENEMR_ADMIN_PHP_ENABLED` unset.
  - Vulnerable commit: expect HTTP `200`, `Content-Type: text/html`,
    body contains the literal string `Multi Site Administration` and a
    `<td>` cell with the configured site's database name - real
    information disclosure, exactly as the advisory's PoC describes.
  - Patched commit: expect HTTP `403`, `Content-Type: text/plain`, body
    exactly `admin.php is disabled by default. See the header comment in
    this file to enable.\n` - no site, database, or version data present
    anywhere in the response.
- **Opt-in benign request** (an operator who deliberately re-enables the
  page, per the fix's own documented instructions): `GET /admin.php`
  with `OPENEMR_ADMIN_PHP_ENABLED=1` set.
  - Vulnerable commit: identical `200` disclosure page (this commit has
    no gate at all, so enabling the env var changes nothing - recorded
    as expected, not a defect).
  - Patched commit: expect HTTP `200`, same disclosure page as the
    vulnerable commit's default response - proving the fix is a
    default-closed gate, not a removal of the underlying admin
    functionality, the same "legitimate use still works" standard
    applied to free5GC's benign delete.

### 5. Evidence-bundle schema (design only - not yet implemented)

Proposed layout, mirroring `free5gc_runtime_case/`'s existing bundle
under a new `openemr_transfer_case/` directory:

| File | Contents |
| --- | --- |
| `run_harness.py` | Starts PHP's built-in server against each commit's checkout, sends the three requests above, records results. |
| `sites/default/sqlconf.php` | The hand-written minimal site config pointing at the local MariaDB instance. |
| `schema.sql` | The two-table minimal schema (`globals`, `version`) and its one seed row each. |
| `manifest.json` | `{"advisory": "GHSA-q366-cv5v-83w8", "vulnerable_commit": "b5313ea2...", "fixed_commit": "50f789fa...", "services_used": {...}, "vulnerable_run": {...}, "patched_run": {...}}` |
| `verdict.json` | `{"advisory": "GHSA-q366-cv5v-83w8", "default_request_blocked": bool, "optin_request_preserved": bool, "verdict": "confirmed_fix" \| "not_blocked" \| "regression_broke_route" \| "inconclusive_crash"}`, reusing the free5GC case's four-outcome verdict vocabulary rather than inventing a new one. |
| `vulnerable_response.log`, `patched_response.log` | Full status/headers/body for all three requests against each commit. |
| `vulnerable_process.log`, `patched_process.log` | Raw stdout/stderr from each `php -S` process. |

This schema is written but **not yet implemented or run** - per the
instruction this design pass was scoped to, implementation is a
separate, later step.

## Correction, 2026-09-28: Docker is working again

The Docker-status finding above is now stale. Re-tested live: the
specific stale artifact causing the "Inference manager" failure
(`%LOCALAPPDATA%\Docker\run\dockerInference`, a reparse-point-flagged
file `Remove-Item` itself could not delete: "The file cannot be
accessed by the system") was cleared by restarting Docker Desktop
directly rather than through this session's own delete attempts, which
failed identically to the earlier free5GC-blocker investigation. `docker
ps` and `docker version` now succeed: Docker Desktop 4.74.0, engine
29.4.3, real running containers listed.

This changes the recommended deployment route for this case. The
official OpenEMR Docker Compose path
(`github.com/openemr/openemr/blob/master/docker/production/docker-compose.yml`)
is now usable and is the more standard, officially-supported way to run
a real OpenEMR instance - closer to how an examiner would expect this
case to be validated than a hand-built minimal PHP+MariaDB stand-in.
The native PHP (`php -S`) + MariaDB route documented above remains a
valid, lower-effort fallback if the official Docker Compose stack turns
out to be slow or fragile to stand up for just this one file's
behaviour, but Docker should be tried first now that it is available.
This is a design-doc correction only; no harness implementation has
started.
