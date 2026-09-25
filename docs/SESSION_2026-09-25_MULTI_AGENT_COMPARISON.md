# Session record — 2026-09-25 multi-agent comparison plan

A single, consolidated record of everything attempted in this session
under the user's 5-step instruction (corrected patch validator, common
experiment protocol, run/preserve comparisons, real-upstream validation,
report update) plus a deferred OSS-CRS adapter step. Written at the
user's explicit request ("document everything done until now success,
failure, outputs, etc") after a real failure was found and corrected
mid-session — this document reports that failure in full, not just the
parts that worked. `docs/PROJECT_STATUS.md`'s session log has the same
material in chronological entry form; this document organizes the same
facts by step instead, as a single reference.

## The instruction, verbatim

> "For this phase, do these in order:
> 1. Fix patch validation. A patch must block the exploit without
>    crashing the affected route, and a legitimate request through that
>    route must still work. Make the known missing-`io` false acceptance
>    fail this check. Record separate verdicts for 'exploit blocked,'
>    'function preserved,' and 'inconclusive'; keep the old results
>    labelled under the old validator.
> 2. Define one common experiment protocol. Select the same cases for
>    your existing pipeline, Codex, and Claude Code. Fix the target
>    versions, input evidence, attempt limits, model settings, and
>    scoring rules before running them.
> 3. Run and preserve the comparisons. Save each agent's prompt, patch,
>    execution trace, test results, and cost. Assess every patch with
>    your independent validator, not the agent's own claim that it
>    succeeded.
> 4. Validate at least one case on real upstream software. Show the
>    vulnerability on a pinned vulnerable version, replay the proof
>    after a candidate fix, and test normal behaviour. Keep this result
>    separate from the simplified reproductions and from the free5GC
>    build-only result.
> 5. Update the report from the evidence. Give each results table a
>    link to its raw artifacts. Separate initial and retest counts,
>    state which objectives were met or only partially met, and explain
>    how the corrected validator changes the patch conclusions.
>
> Only after those are complete: add a small OSS-CRS source-only adapter
> for reachability findings."

Scoping decisions made along the way (all by the user, via direct
answers): Codex deferred until the Claude Code leg is done; the
CVE-2026-23949 (jaraco.context) real-upstream case chosen on the user's
own ChatGPT-sourced recommendation; all 6 main-catalogue CVEs used for
the pipeline-vs-agent comparison; Claude Code to run as a backend swap
within the existing pipeline, not a standalone agent; a fresh isolated
lessons file for the comparison; and, after the mislabeling described
below was found, to relabel the run honestly rather than silently
re-attempt it.

## Status at a glance

| Step | Status | Evidence |
|---|---|---|
| 1. Corrected patch validator | Done | `src/pipeline/patch.py`, verified against the real round-5 log |
| 2. Common experiment protocol | Done for Ollama-vs-Ollama (already existed); frozen for Claude Code; Codex leg deferred | `docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md` |
| 3. Run and preserve comparisons | Partially done, one leg failed silently and was corrected | see "Steps 2/3" below |
| 4. Real-upstream validation | Done | `real_upstream_case/CVE-2026-23949/RESULTS.md` |
| 5. Update report from evidence | Not started | -- |
| OSS-CRS source-only adapter | Not started (blocked on Step 5, per instruction) | -- |

---

## Step 1 -- Corrected patch validator: SUCCESS

**Problem being fixed**: the old `patch_validated` flag (exploit fails +
`/health` passes) could not tell a *deliberate* security rejection apart
from an *unrelated crash* in the patched route. This is exactly what
happened in round 5: `CVE-2026-78683`'s patch had a missing `io` import
that crashed the handler on every request. The crash made the exploit
"fail" and a different route (`/health`) still returned 200 -- satisfying
the old check while fixing nothing, and getting recorded as
`patch_validated: True`.

**What was built**, additively (old field untouched, three new ones
added) in `ExploitArtifacts` (`cve_pipeline.py`) and
`src/pipeline/patch.py`:

- `patch_exploit_blocked` -- did the exploit fail *without* an unhandled
  exception in the target's own log (crash-signature regex:
  `Traceback (most recent call last)|Exception on .* \[`).
- `patch_function_preserved` -- does a benign, non-malicious request to
  the *same* route still succeed (reuses the existing multi-payload
  `extra_arg` probing mechanism with a fixed benign payload).
- `patch_verdict` -- one of `confirmed_fix` / `regression_broke_route` /
  `inconclusive_crash` / `not_blocked`.

**Verification**:
- Replayed the *real, preserved* round-5 log through
  `generate_and_validate_patch` (with `execute_exploit_artifacts` mocked):
  reproduces `patch_validated=True` (the old bug still there, by design --
  old results stay under the old validator) while the new
  `patch_verdict=inconclusive_crash` correctly refuses to call it a fix.
- Synthetic clean-rejection and benign-probe logs verified the
  `confirmed_fix` and `regression_broke_route` paths.
- A pytest file (`tests/test_patch_validator.py`) was written, then hit
  this project's own pre-existing, already-documented Windows/pytest
  bug (any `cve_pipeline` import corrupts pytest's capture teardown) --
  deleted per established project precedent and replaced with a direct,
  non-pytest verification script.

**A second, real bug found later the same session** (documented under
Steps 2/3 below, since it surfaced while building that run's results
table): the health-check-failure early-return path in
`generate_and_validate_patch()` returned *before* reaching this new
verdict-computation block, leaving `patch_verdict` blank instead of
classified. Fixed by explicitly setting
`patch_exploit_blocked=False`, `patch_function_preserved=None`,
`patch_verdict="inconclusive_crash"` in that branch. Verified twice by
re-running `CVE-2026-46492` alone.

**Outcome**: Step 1's exit criterion is met. The fix is correct and
independent of which LLM backend calls it (see Steps 2/3 -- the backend
mislabeling described below does not affect this step's validity, since
it was verified by direct code reading and controlled replay, not by
trusting any live agent's output).

---

## Step 4 -- Real-upstream validation (CVE-2026-23949 / jaraco.context): SUCCESS

The strongest evidence tier this project has produced for any single
case -- a real exploit against a real, pinned, installed PyPI package,
and the real upstream maintainers' own published fix, not a generated
reproduction and not the free5GC build-only result.

**Setup**: two isolated venvs, `jaraco.context==5.3.0` (vulnerable,
advisory-confirmed) and `==6.1.0` (patched, advisory's own stated fixed
version). Read the actual installed source in both to confirm the real
root cause (`strip_first_component` splits a tar member's path on the
first `/`, keeping any `../` in the remainder) and the real fix (`6.1.0`
composes stdlib `tarfile.data_filter`, PEP 706, ahead of the same
function). Built a real malicious tarball and a real legitimate tarball,
served over local HTTP (`127.0.0.1`), and called the real, unmodified
`jaraco.context.tarball()` directly -- no mocking.

**Results** (raw log: `real_upstream_case/CVE-2026-23949/raw_log.txt`):

| Version | Test | Result |
|---|---|---|
| `5.3.0` (vulnerable) | Exploit | **EXPLOITED** -- canary file written outside the extraction dir, exit 0 |
| `5.3.0` (vulnerable) | Legitimate use | OK |
| `6.1.0` (patched) | Exploit re-probe | **BLOCKED** -- `tarfile.OutsideDestinationError`, a real stdlib safety exception, exit 1 |
| `6.1.0` (patched) | Legitimate use | OK |

**Verdict** (Step 1's vocabulary): `patch_exploit_blocked=True`,
`patch_function_preserved=True`, `patch_verdict=confirmed_fix`.

**A real bug found and fixed while building this case**: the first
exploit run against the genuinely-vulnerable version reported `[-]
FAILED` even though the traversal should have worked -- the canary-file
existence check was computed relative to the *script's own* directory
instead of the actual `target_dir` the traversal escaped from. Fixed by
computing the canary path relative to `target_dir` at call time; verified
immediately after with `[+] EXPLOITED` against the correct real path.

**What this does and does not establish**: proves CVE-2026-23949 is
exploitable in the real, named package at the advisory's stated
vulnerable version, and that the advisory's fixed version blocks it while
preserving normal use. Does not generalize to the other catalogue CVEs
(whose targets remain generated reproductions), and does not involve any
LLM-generated patch -- this validates the *evaluation methodology*, not
whether an LLM can produce a patch this good. Full writeup:
`real_upstream_case/CVE-2026-23949/RESULTS.md`.

---

## Steps 2/3 -- the Claude Code comparison attempt, and its failure

This is the part of the session that did not go as reported at first,
and is documented here in full rather than smoothed over.

### What was attempted

A frozen protocol was written first -- `docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md`
-- covering case selection (the same 6 main-catalogue CVEs), attempt
limits (one shot per CVE, Stage 3.7 bounded at 3 iterations, Stage 3.8
once per confirmed exploit), model settings (acknowledging `claude -p`
has no exposed temperature/seed control, unlike Ollama's pinned
`temperature=0, seed=42`), and scoring rules (Step 1's corrected verdict
fields as the headline metric). The pipeline's `_call_live_model()`
already prefers the `claude` CLI over Ollama whenever `_claude_available()`
returns true, so running the unmodified pipeline was intended to be a
pure backend swap -- no code change.

The run executed cleanly end-to-end: all 6 CVEs produced advisory data,
generated exploits, real execution results, refinement attempts, and
patch attempts, with plausible-looking timing. It was reported to the
user as a genuine Claude Code comparison, with a results table (4/6
confirmed, 0/6 `confirmed_fix`).

### What was actually wrong

**It never ran on Claude Code.** Every one of the 6 reports'
`generation_backend` field reads `"ollama"` / `"qwen2.5-coder:7b"`, with
real token counts (`generation_input_tokens`/`generation_output_tokens`)
and `generation_cost_usd: 0.0` -- none of which the Claude CLI backend
ever produces (`claude -p --output-format text` leaves
`cost_usd`/tokens as `None`, by that backend's own metering code, exactly
because it exposes no usage data). This is precisely the check the
protocol's own Section 6 required ("if any entry shows `ollama` instead,
that means `_claude_available()` returned false for that call... and the
entry must be flagged") -- a check that was **not performed before the
results were first reported**, and the user was told for one
conversation turn that this was a genuine Claude Code comparison.

### Root cause, verified directly

```
$ claude --version
2.1.280 (Claude Code)          # exit 0 -- no auth required

$ claude -p "Say exactly: HELLO_TEST_OK" --output-format text
Failed to authenticate: OAuth session expired and could not be refreshed
                                # exit 1
```

`_claude_available()` (`cve_pipeline.py:381`) only runs
`claude --version`, which succeeds without authentication -- so the
pipeline's startup banner correctly showed `mode=claude-cli` and gave no
indication anything was wrong. The actual generation calls use
`claude -p <prompt> --output-format text` (`cve_pipeline.py:357-378`),
which failed on *every single call* in this run with the OAuth error
above. `_call_live_model()` (`cve_pipeline.py:491-499`) treats any
empty-text Claude response as "fall through to Ollama" -- and nothing in
the pipeline logs that fallback as a warning anywhere. The run looked
entirely normal at every log line while silently substituting a 7B local
model for Claude at every single LLM call.

**This is a real, standing gap in the pipeline's own observability, not
yet fixed**: a broken primary backend degrades silently instead of
raising a visible warning. Flagged here as a finding, deliberately not
bundled with a fix in the same step, per this project's own convention
of keeping a finding and its fix as separate, auditable actions. The
`claude` CLI's own OAuth session is separate from whatever authenticates
this Claude Code desktop-app conversation itself (which was clearly
still working throughout) and needs to be re-authenticated by the user,
outside this pipeline's control.

### Remediation taken

Since the underlying data is real, honest Ollama output -- just not the
comparison it was meant to be -- nothing was discarded. It was corrected
in place:

1. The six report files were `git mv`'d from
   `reports/claude_code_catalog_run_2026-09-25/` to
   `reports/llm_catalog_run_2026-09-25_round6/`, joining the existing
   5-round Ollama series under its real name.
2. Written up as **Round 6** in `reports/LIVE_LLM_CATALOG_RUN.md`, with
   the full root-cause trace and -- for the first time in that file's
   series -- the corrected Step 1 verdict breakdown instead of just the
   old `patch_validated` flag.
3. `docs/PROJECT_STATUS.md`'s session-log entry was corrected in place
   (the original entry is kept, marked superseded, for the audit trail --
   not deleted, per the same "report failures, don't hide them"
   convention the rest of this project already follows).
4. `docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md` was annotated with a status
   note at the top rather than deleted -- the protocol itself is still
   valid and unexecuted, waiting on CLI re-authentication.
5. Both corrections were committed (`fd3d22f`) and pushed to `fyp`
   separately from the original mislabeled commit (`2b075c3`), so the
   mistake and its correction are both visible in git history rather
   than folded away.

### Round 6 results (the real data, correctly labeled as Ollama)

| CVE | Class | Confirmed | Refine attempts | Patch attempted | `patch_verdict` | Time (s) |
|---|---|---|---|---|---|---|
| CVE-2026-42208 | SQL Injection | **True** | 1 | True | `not_blocked` | 49.5 |
| CVE-2026-27602 | OS Command Injection | False | 3 | -- | -- | 74.0 |
| CVE-2026-23949 | Path Traversal | False | 3 | -- | -- | 77.7 |
| CVE-2026-78683 | Insecure Deserialization | **True** | 0 | True | `not_blocked` | 31.6 |
| CVE-2026-54729 | SSRF | **True** | 0 | True | `not_blocked` | 32.5 |
| CVE-2026-46492 | XSS | **True** | 0 | True | `inconclusive_crash` | 34.2 |
| **Total** | | **4/6** | 7 | 4/6 | **0/6 `confirmed_fix`** | **299.5** |

Full reports: `reports/llm_catalog_run_2026-09-25_round6/`.

### What Steps 2/3 still owe

- **A genuine Claude Code run has not happened yet.** The frozen protocol
  is ready; it needs the `claude` CLI re-authenticated first.
- **Codex's leg** -- explicitly deferred by the user until Claude Code's
  leg is complete, now further blocked on the above.
- **Exact per-stage prompts** were not saved as separate artifacts in any
  run so far (Step 3 asks for "each agent's prompt") -- the raw JSON
  reports capture execution trace, patch, and test results, but not the
  literal prompt text sent at each stage.
- **Cost** will always read `None` for genuine Claude CLI entries once
  that leg runs -- `claude -p --output-format text` exposes no token/cost
  data. This is a stated, protocol-acknowledged limitation, not something
  to silently work around.

---

## All commits from this session

| Commit | Summary |
|---|---|
| `78fbaf0` | Corrected patch validator (Step 1) + real-upstream CVE-2026-23949 validation (Step 4) |
| `2b075c3` | Original (mislabeled) "Claude Code catalog run" + the `patch.py` early-return verdict fix |
| `fd3d22f` | Correction: relabel the run as Ollama round 6, fix `docs/PROJECT_STATUS.md` and the protocol doc |

All pushed to `fyp` (`github.com/J-Dheeraj/Final-Year-Project`), per this
repo's remote discipline -- `origin` remains frozen and untouched.

## Full output/artifact index

| Artifact | What it is |
|---|---|
| `src/pipeline/patch.py` | Corrected validator implementation (Step 1) |
| `real_upstream_case/CVE-2026-23949/RESULTS.md` | Real-upstream validation writeup (Step 4) |
| `real_upstream_case/CVE-2026-23949/raw_log.txt` | Raw console output of all 4 real runs |
| `real_upstream_case/CVE-2026-23949/poc.py` | The real exploit/legitimate-use PoC against the installed package |
| `docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md` | Frozen, still-unexecuted Claude Code protocol |
| `reports/llm_catalog_run_2026-09-25_round6/` | Round 6 raw reports (real Ollama data, corrected label) |
| `reports/LIVE_LLM_CATALOG_RUN.md` | Full 6-round Ollama catalog writeup, including Round 6's failure trace |
| `docs/PROJECT_STATUS.md` | Chronological session log, including the original entry (superseded, kept) and its correction |

## Honest overall assessment

Two of five steps are genuinely done and hold up under independent
verification (Step 1, Step 4). Step 2/3's Ollama-vs-Ollama comparison
data already existed before this session (5 prior rounds); this
session's attempt to add a genuine Claude Code leg failed due to an
expired CLI credential outside this pipeline's control, was not caught
before being reported once, and was then corrected rather than left
standing. Step 5 (report update) and the OSS-CRS adapter have not been
started. The single most important unresolved technical finding from
this session -- beyond the two bugs already fixed -- is that
`_call_live_model()`'s silent backend fallback is a real blind spot:
nothing about this pipeline's own logging would have caught the
mislabeling without manually checking `generation_backend` against the
protocol's own written rule.
