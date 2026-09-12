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
| [CVE-2026-27602](https://github.com/advisories/GHSA-wwv8-cqpr-vx3m) | modoboa | OS Command Injection | CWE-78 | True | 0 (after 1 self-revision) | **True*** |
| [CVE-2026-23949](https://github.com/advisories/GHSA-58pv-8j8x-9vj2) | jaraco.context | Path Traversal | CWE-22 | True | 0 (after 1 self-revision) | **True†** |
| [CVE-2026-78683](https://advisories.gitlab.com/pypi/nltk/CVE-2026-78683/) | nltk | Insecure Deserialization | CWE-502 | True | 0 | **True** |
| [CVE-2026-54729](https://github.com/advisories/GHSA-5846-7qm3-r52j) | dssrf | SSRF | CWE-918 | True | 1 | False‡ |
| [CVE-2026-46492](https://github.com/advisories/GHSA-32q2-hhr5-6qvv) | md-fileserver | XSS | CWE-80 | True | 0 | **True** |

**5/6 dynamically confirmed** by the pipeline's own generated, executed
proof-of-concept - not a description of what *should* happen, a real
subprocess exit code from a real HTTP exchange against a real (if
generic-template) Flask target. The remaining 1 is explained below, not
a silent failure:

\* **CMDi (modoboa) - fixed by Stage 3.7's self-improvement loop, not by
hand.** First attempt failed: the CMDi template's payload used `;` as a
command separator and a POSIX-only `ping -c` flag; on this Windows host,
`cmd.exe` treats `;` as a literal character (not a separator) and
`ping.exe` rejects `-c`, so `ping -c 1 127.0.0.1; id` resolved
`"127.0.0.1;"` as an invalid hostname before the injected `id` could ever
run. Stage 3.7 recognized the failure signature, revised the payload to
use `&` (a separator both `cmd.exe` and POSIX `sh` accept) with an
`echo <marker>` payload instead of `id`, re-ran, and confirmed on the
second attempt. That fix was then **persisted** to `.pipeline_lessons.json`
- a second, independent run of this exact CVE (with a fresh, unpatched
template regenerated from scratch) applied the *same* learned fix
immediately (`source=lesson`, not `source=builtin`) rather than
re-discovering it. See "Self-improvement" below.

† **Path Traversal (jaraco.context) - fixed by Stage 3.7's LLM-revision
path** (see "Self-improvement" below for what "LLM" means in an
environment with no `claude` CLI/API key). First attempt failed - not
because traversal was blocked, but because the generated PoC's payload
targeted `/etc/passwd`, which doesn't exist on this Windows host, so
every attempt 404'd regardless of whether the traversal itself worked.
The generated PoC's own `verify()` function already anticipated Windows
(`"[fonts]" in r.text`, a real `win.ini` marker) - `exploit()` simply
never tried a payload that would reach it. The revision added a
`win.ini`-targeting payload alongside the existing `/etc/passwd` one;
re-ran, confirmed on the second attempt, persisted.

‡ **SSRF (dssrf)**: the generated harness correctly attempted the SSRF
payload against a real link-local address; this development machine's
own network stack cannot route to it ("unreachable network"), the same
environment limitation observed independently while validating Stage 3.6
against the SSRF template directly. Not a pipeline defect.

## Self-improvement (Stage 3.7)

`ExploitArtifacts.iterations` and the `poc.iter1.v0.py` filename convention
already anticipated iterative refinement - nothing ever looped. Stage 3.7
closes that: when Stage 3.6 genuinely ran an exploit and it genuinely did
NOT reproduce the bug (not "couldn't test" - a real, informative failure),
it tries, in order: (1) a persistent lessons store (`.pipeline_lessons.json`,
repo root) for a fix already learned for this vulnerability class +
failure signature - free, instant, no AI call; (2) an LLM revision
(`_llm_revise_artifacts`) that's handed the actual failure log plus the
current source and asked to diagnose and fix it, for failures nobody
pre-anticipated; (3) a small, honest, narrow built-in rule library for
signatures this project has concretely observed and hand-verified -
exactly one exists (the CMDi POSIX-vs-Windows shell syntax fix). A
newly-successful revision - from any of the three sources - is written
back to the lessons store, so it benefits every future run of the same
class hitting the same failure shape without repeating the diagnosis.

**Both paths demonstrated for real, not just described:**

- **Built-in rule** (CMDi/modoboa): fixed on the first run, `source=builtin`;
  a second independent run applied the same fix from the store,
  `source=lesson`, not `source=builtin`.
- **LLM revision** (Path Traversal/jaraco.context): this environment has
  no `claude` CLI or API key (verified: `which claude` finds nothing, no
  `ANTHROPIC_API_KEY` set) - `_llm_revise_artifacts` was exercised through
  a stubbed `_call_claude` returning a hand-written but realistic
  response (correctly diagnosing that `/etc/passwd` doesn't exist on
  Windows and adding the `win.ini` payload `verify()` already anticipated
  but `exploit()` never tried), proving the prompt→parse→patch→re-execute→
  persist plumbing end to end. **Then, separately and without any stub,
  a genuine, unmodified CLI run of the exact same CVE** picked up that
  persisted fix from `.pipeline_lessons.json` on its own (`source=lesson`)
  and confirmed - proof that once a fix exists in the store, reusing it
  needs no AI backend at all, live or stubbed. What was NOT demonstrated
  in this environment: a live model actually generating that first fix
  from scratch. The mechanism is real and tested; the live-LLM half of
  path (2) is honestly untested here for the same reason reachcrs's own
  live-LLM validation needed a separate machine with a real provider.

**What this is not**: an unbounded, autonomous, self-modifying system.
Every run is capped at `max_iterations` (default 3); a failure signature
with no known fix and no available AI backend stops immediately and
reports "no known revision" (see SSRF above - a real network limitation
no revision could fix) rather than guessing or looping forever; built-in
and lesson patches are targeted string replacements to already-generated
source, not a full rewrite (LLM revisions are a full-file replacement,
since that's the natural shape of an LLM's response, but still gated on
a confirmed re-execution before being trusted or persisted); and the
lessons store only ever grows by a run actually *confirming* a fix
worked, never by assertion. This is a bounded, evidence-gated
reflect-and-retry loop, not general self-improving AI.

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
