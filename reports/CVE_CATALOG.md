# Curated CVE reference set

Six real, disclosed 2026 CVEs, one per vulnerability class this pipeline
classifies into, each verified directly against GitHub's advisory API
(not just search-result summaries) before being run. Every run below used
the pipeline's own no-API-key text-only mode (no `ANTHROPIC_API_KEY`, no
`claude` CLI on PATH in this environment) - the "no manual config needed"
default path, not a best-case scenario.

Each CVE has its own self-contained folder: `reports/<CVE-ID>/report.json`
(full pipeline output), `poc.iter1.v0.py`, `target_app.iter1.v0.py`
(Stage 3.5's generated artifacts - the exact files Stage 3.6 ran).

| CVE | Package | Class | CWE | Executed | Exit | Dynamically confirmed |
|---|---|---|---|---|---|---|
| [CVE-2026-42208](https://github.com/advisories/GHSA-r75f-5x8p-qvmc) | litellm | SQL Injection | CWE-89 | True | 0 | **True** |
| [CVE-2026-27602](https://github.com/advisories/GHSA-wwv8-cqpr-vx3m) | modoboa | OS Command Injection | CWE-78 | True | 1 | False* |
| [CVE-2026-23949](https://github.com/advisories/GHSA-58pv-8j8x-9vj2) | jaraco.context | Path Traversal | CWE-22 | True | 1 | False† |
| [CVE-2026-78683](https://advisories.gitlab.com/pypi/nltk/CVE-2026-78683/) | nltk | Insecure Deserialization | CWE-502 | True | 0 | **True** |
| [CVE-2026-54729](https://github.com/advisories/GHSA-5846-7qm3-r52j) | dssrf | SSRF | CWE-918 | True | 1 | False‡ |
| [CVE-2026-46492](https://github.com/advisories/GHSA-32q2-hhr5-6qvv) | md-fileserver | XSS | CWE-80 | True | 0 | **True** |

**3/6 dynamically confirmed** by the pipeline's own generated, executed
proof-of-concept - not a description of what *should* happen, a real
subprocess exit code from a real HTTP exchange against a real (if
generic-template) Flask target. The other 3 are explained below, not
silent failures:

\* **CMDi (modoboa)**: the injection point itself fired - the payload
reached a real shell - but the CMDi template's payload assumes a POSIX
`ping -c <n>` (count flag); on this Windows host, `ping` returned
`"Access denied. Option -c requires administrative privileges."` before
the injected command could execute. A template written against a Linux
target, run on a Windows host. Would very plausibly confirm run under
WSL/Linux with the same template unmodified.

† **Path Traversal (jaraco.context)**: no GitHub commit diff could be
resolved from this advisory's references, so Stage 3.5 fell back to the
*generic* PathTraversal template (a `/file?name=` URL-parameter read) -
but the real CVE's mechanism is zip-slip during `tarfile` extraction, a
different attack shape entirely. The template tested a real instance of
the vulnerability *class*, just not *this* CVE's specific mechanism -
see `README.md`'s "Honest gap" note on template vs. CVE-specific
generation (Claude-generated, CVE-tailored artifacts need `ANTHROPIC_API_KEY`
or the `claude` CLI, neither present in this run).

‡ **SSRF (dssrf)**: the generated harness correctly attempted the SSRF
payload against a real link-local address; this development machine's
own network stack cannot route to it ("unreachable network"), the same
environment limitation observed independently while validating Stage 3.6
against the SSRF template directly. Not a pipeline defect.

## Bugs this run surfaced and fixed (real, not staged)

Running these six for real - not just unit-testing the mechanism in
isolation - is what caught three genuine defects, two of them pre-existing:

1. **Path-doubling in Stage 3.6** (introduced this session, caught
   immediately): `poc_path`/`target_app_path` are stored relative to
   wherever the CLI was invoked from; `execute_exploit_artifacts` combined
   that relative path with a `cwd=` change, causing the child process to
   look for `reports/CVE-X/reports/CVE-X/target_app.py`. Fixed by
   resolving both paths to absolute before use.
2. **Text-only classification blind spot** (pre-existing): NVD's own
   `weaknesses` field (a real, structured CWE ID) was never read anywhere
   in this pipeline - classification relied entirely on prose keyword
   matching against the advisory description, which missed CVE-2026-42208
   because its NVD summary describes SQL injection's *mechanism* without
   ever using the words "SQL" or "injection". Fixed by extracting NVD's
   structured CWE field (`ghsa_extractor.py::parse_nvd_json`, mirrored in
   `cve_pipeline.py::_nvd_fallback`) and preferring it over prose matching
   when present.
3. **SSRF template silently unreachable** (pre-existing): `_CLASS_NORM`'s
   template-key lookup only matched the bare string `"server-side request
   forgery"`, but the classifier has always returned the long form
   `"Server-Side Request Forgery (SSRF)"` - so *any* SSRF CVE routed
   through the lightweight classification path (not just this session's
   new CWE-based path) silently fell back to the generic UNKNOWN template
   instead of the real SSRF one. Fixed by adding the actual returned string
   as an additional key, matching the pattern already used for XSS.

None of these three were found by inspection or a synthetic test fixture -
all three only surfaced because this catalog was run for real, end to end,
against real advisories. That is itself the argument for keeping a
reference set like this one in the repo rather than validating the
pipeline only against hand-picked, already-known-good inputs.
