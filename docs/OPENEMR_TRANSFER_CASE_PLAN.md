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
