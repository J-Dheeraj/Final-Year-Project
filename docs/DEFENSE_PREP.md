# Defense Prep — Prepared Q&A

Built from a Socratic walkthrough of this exact codebase, not written in
the abstract. Each answer below is the corrected version of an answer
that was actually given wrong once during that walkthrough — these are
the real weak spots, not hypothetical ones. Read `docs/SCOPE_AND_LIMITATIONS.md`
alongside this; these answers are its claims compressed to viva length.

## "Did you exploit litellm / modoboa / nltk / etc.?"

No. Say this precisely: **"I dynamically confirmed that the bug pattern
described in the CVE advisory is exploitable in a faithful reproduction
— I did not install or run the real named package."** `target_app.py` is
a small Flask app the pipeline writes from the advisory's own root-cause
text; the real upstream code is never imported. This is stated as
Limitation 1 in `docs/SCOPE_AND_LIMITATIONS.md`. Don't let "exploited
litellm" slip out under pressure — it's the single easiest thing to get
caught overclaiming on.

## "Is your live-probe testing real?"

For SSRF, yes — a real local lab, toggled vulnerable/patched, real HTTP
traffic. For the other five classes (SQLi, command injection, XSS, path
traversal, deserialization), Stage 3 is static regex pattern-matching
against the code diff, not live testing — stated plainly in the
project's own README under "Honest gap, stated plainly." The actual
source of dynamic evidence for every class, including those five, is
Stage 3.6 (`execute_exploit_artifacts`), which runs the generated PoC
against the generated target as real subprocesses for every vulnerability
class the pipeline handles.

## "How do you know a generated patch actually works?"

Two checks, both required: (1) the *original, unmodified* exploit script
is re-run against the patched target and must now fail, and (2) the
target's `/health` endpoint must still return 200. Either check alone is
gameable — a patch that deletes the vulnerable endpoint entirely would
pass check 1 without being a real fix, and is caught by check 2 failing.
Both together prove regression-safety against one known exploit, not
general correctness — say "plausible patch," not "correct patch"; this
project doesn't currently measure semantic correctness against the real
upstream fix.

## "Why are your two free5GC efforts (the lab and the reachability case study) not the same thing?"

Because of a real infrastructure gap, not a design choice: the real
free5GC UDR service needs a MongoDB backend and NRF service registration
to run — it isn't a standalone binary. `free5gc_lab/` was built as a
self-contained, dependency-free reproduction specifically so it could be
dynamically exploited and patched in seconds with no infrastructure. The
reachability work later obtained the real upstream source and proved
real compile-compatibility against it, but never stood up the full
service needed to dynamically test the real code. Say this directly if
asked — don't imply the two are unified when they aren't.

## "Does the free5GC patch actually fix the vulnerability?"

Unknown, and say so. `go build ./...` succeeding on the real, cloned
free5GC module proves the patch is syntactically valid and compiles
against the real project's actual dependency graph — genuinely new
evidence neither this project nor its predecessor had before. It does
**not** prove the patch is correct at runtime; compiling only proves the
code type-checks, not that the specific vulnerable code path was
actually closed. Full proof would need the real service running (see
above) and a real HTTP exploit attempt against it, which wasn't done.

## "Isn't testing exploits against real software illegal?"

No — say this confidently, don't hedge. Every target exploited in this
project is either hand-written or a locally-deployed copy of open-source
software the researcher controls, bound to `127.0.0.1`. This is standard,
legitimate security research practice — the same thing a CVE researcher
does to verify a bug before disclosure. Nothing in this project touches
a system the researcher doesn't own or have permission to test.

## "Why isn't this a real Cyber Reasoning System (CRS)?"

Because a CRS's defining, hardest job — finding an *unknown* bug in an
unmodified codebase — isn't attempted here. Every unit of work starts
from either an already-published CVE ID or a stated entry-point list. Be
ready to name the two pieces this project *does* do and place them
honestly: (1) exploit confirmation and patch validation for known CVEs,
and (2) reachability-filtered static analysis narrowing what to look at
in real source, which is discovery-*adjacent* (narrowing scope) but not
discovery itself.

## "You also have a bug bounty / discovery tool (claude-bug-bounty) — why isn't that part of this project?"

Deliberately kept separate, not an oversight. `claude-bug-bounty` is a
real, actively-maintained discovery tool (recon, live scanning for 26+
web vuln classes plus smart-contract bugs, a validation gate, then
platform-specific report generation for HackerOne/Bugcrowd/etc.) — it
hunts for *unknown* bugs in live targets. That is precisely the CRS-style
capability the previous answer says this project does not attempt.
Merging it in would blur the exact line the "fuzzing" reframing (below)
was built to make precise: this project confirms and patches *known*
CVEs; it does not discover unknown ones. Two honestly-scoped tools -
discovery in one repo, confirmation in this one - is a stronger,
more defensible position than one tool quietly claiming both. If
pressed on whether they could be combined: yes, architecturally
(`claude-bug-bounty`'s findings could in principle feed this pipeline's
Stage 1 the same way ProvTrail's static findings already do), but that
was never attempted and isn't claimed here.

## "Why did you drop fuzzing from the project title/pitch?"

Because nothing in the pipeline does coverage-guided input mutation —
claiming "fuzzing" would be indefensible the moment anyone asked to see
the fuzzer. The professor confirmed this reframing is acceptable. The
honest, current framing — LLM-assisted exploit confirmation and patch
validation for known CVEs, plus reachability-filtered analysis on real
source — is in `docs/CRS_MAPPING.md`'s framing note. If asked "so you
considered fuzzing and decided against it, or never had it?" — the
honest answer is the latter: it was in the project's original one-line
pitch, never in the implementation, and the pitch was corrected to match
reality rather than the implementation being built out to match the pitch.

## "What's the weakest evidence in this whole project?"

Have an honest answer ready rather than getting caught by the question.
**This changed on 2026-09-23** — the old answer below ("LLM paths are
only stub-tested") is now out of date and would be an overclaim in the
other direction if repeated unchanged. Current candidates, ranked: the
free5GC compile verification still only proves compile-compatibility,
not runtime correctness (unchanged, see the free5GC question above);
five of six main-pipeline vulnerability classes still rely on static
pattern-matching in Stage 3 rather than live testing (though Stage 3.6
covers all six with real dynamic execution regardless); and the
live-model catalog runs are still single-shot per CVE with no fixed
seed/temperature=0, so any one CVE's confirmed/not-confirmed result can
flip between runs (see round 1 vs. round 2's SQLi flip, and round 3 vs.
round 4's OS-CMDi/Deserialization/SSRF/XSS flips, all in
`reports/LIVE_LLM_CATALOG_RUN.md`) — a single round's number is not a
stable measurement, only the *union* across rounds ("has this class ever
confirmed") is currently defensible.

(Historical, kept for context: before 2026-09-23, self-improvement's and
patch generation's LLM paths were only stub-tested in this environment
— no live API key/CLI. That gap is closed; see the next question.)

## "Are Stage 3.7 (self-improvement) and Stage 3.8 (patch generation) actually verified live now?"

Yes, as of commit `e344966` (2026-09-23) and the round-3/round-4 catalog
runs that followed it. Before that commit, `src/pipeline/self_improve.py`
called `_call_claude`/`_claude_available` directly instead of the
provider-agnostic `_call_live_model`/`_live_model_available` helper
Stage 3.5/3.8 already used — under this machine's actual conditions (no
`claude` CLI, local Ollama only), that meant Stage 3.7 silently never ran
at all, not "ran via stub." Fixed by mirroring the exact pattern already
proven for Stage 3.5/3.8. Round 4 (`reports/LIVE_LLM_CATALOG_RUN.md`)
shows the result: `CVE-2026-27602` confirmed via a genuine
from-scratch Stage 3.7 revision (`source=llm`, `revision_backend=ollama`
in the raw report, not a reused lesson), and `CVE-2026-78683` got its
Stage 3.8 patch validated for the first time across all four rounds — a
real `500`/`ValueError` from re-running the *original, unmodified*
exploit against the patched target. Both are independently reproducible:
`git show e344966`, and the raw JSON reports under
`reports/llm_catalog_run_2026-09-23_round4/`.

## "You found bugs in your own pipeline while producing these results — what were they, and how do you know they're fixed?"

Two, both found by reading round 3's raw `execution_log` output closely
rather than trusting the summary numbers, and both documented in
`reports/LIVE_LLM_CATALOG_RUN.md` *before* being fixed (commit `6f932b4`
documents them; `b05b45d` fixes them — deliberately two separate,
auditable commits, not one commit that quietly corrects a number already
reported). (1) `_extract_marker` didn't strip a stray leading/trailing
`` ``` `` markdown fence from the model's response, so 4 of 5 round-3
failures crashed with a literal `SyntaxError` on the rewritten
`target_app.py`'s first line — not a reasoning failure, a parsing gap.
(2) `execute_exploit_artifacts` left `exit_code`/`dynamically_confirmed`
stale (carried over from the previous run) when the target crashed
before its health check, so a crash could misleadingly read as "ran and
cleanly failed" in `refinement_history`. Verified fixed three ways, not
just asserted: a standalone unit test against the exact failure shape
(now parses as valid Python), a standalone test that runs a healthy
target then swaps in a crashing one on the same artifacts object (now
correctly resets to `None`/`False` instead of staying stale), and a full
catalog re-run (round 4) checked programmatically for the crash signature
— `grep`/`Select-String` for `SyntaxError` across all 6 round-4 reports
returns zero matches, independently reproducible in a terminal with:
```
git show b05b45d
```
and the per-CVE loop documented in `reports/LIVE_LLM_CATALOG_RUN.md`'s
round 4 section.

## "What's your single strongest piece of dynamic evidence?"

`CVE-2026-78683` (Insecure Deserialization) in round 4:
live-generated exploit (Stage 3.5, `qwen2.5-coder:7b` via Ollama, no
template) → dynamically confirmed on the first try, zero refinement
needed (`poc.py` exit 0, `[+] EXPLOITED`) → live-generated patch (Stage
3.8) → the *same, unmodified* exploit script re-run against the patched
target now genuinely fails (`poc.py` exit 1, `[-] FAILED`, the target
raises `ValueError: Deserialization only allowed for safe classes` and
returns HTTP 500) → `/health` still returns 200, so the patch didn't just
break the app. Every step is a real subprocess exit code or a real HTTP
response, not a description of what should happen, and every step is in
`reports/llm_catalog_run_2026-09-23_round4/CVE-2026-78683.json`. This is
the first time in the project's history all of generation, dynamic
confirmation, AND patch validation succeeded for the same CVE in the
same run — cite this one first if asked for a concrete example.
