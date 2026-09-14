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
Candidates, ranked: self-improvement's and patch generation's LLM paths
are only stub-tested in this environment (no live API key/CLI — see
`docs/BENCHMARK_PROTOCOL.md` §4, every LLM-shaped result here is
`llm-stub` or `lesson-reuse`, never `llm-live`); the free5GC compile
verification proves compile-compatibility, not runtime correctness; and
five of six main-pipeline vulnerability classes rely on static
pattern-matching in Stage 3 rather than live testing (though Stage 3.6
covers all six with real dynamic execution regardless).
