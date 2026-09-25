> **VOID — conference submission abandoned (2026-09-25).** This paper is
> no longer being submitted to the free5GC World Forum or any venue. The
> deliverable is now the full FYP report + viva + demo. The free5GC
> reachability work described below is still real and reusable in the
> report; the verified-vs-fabricated table further down is the useful
> part. Everything about HotCRP, deadlines, and "action needed before
> submitting" is dead — ignore it. Kept, not deleted, only as a record of
> what was independently verified.

# Notes on this draft — read before submitting anything

## What's real vs. what needs your input

Every technical claim, number, and CVE/GHSA/commit-hash citation in
`main.tex` is drawn directly from this repo's actual, verified work:

| Claim in the paper | Source in this repo |
|---|---|
| 102 functions parsed, 4 reachable, 96.1% reduction | `src/reachability/run_free5gc_case_study.py` output, `docs/REACHABILITY.md` |
| CVE-2026-40248, GHSA-jgq2-qv8v-5cmj, CVSS 7.5, CWE-285 | Fetched directly from `api.github.com/advisories/GHSA-jgq2-qv8v-5cmj` this session — not from a secondary summary |
| CVE-2026-40246, GHSA-g9cw-qwhf-24jp, CVSS 7.5 | Fetched directly from `api.github.com/advisories/GHSA-g9cw-qwhf-24jp` this session (corrects an earlier, wrong 8.7 figure that was in `docs/FREE5GC_LAB.md` from an unverified secondary source) |
| Fix commit `86686276a7e226183ee786e3dd6714ec56c78fda` | `src/reachability/verify_against_real_upstream.py`, verified against the real cloned repo |
| Patch applied to real upstream, `go build ./...` succeeds | `src/reachability/verify_against_real_upstream.py`, re-run end-to-end from a fresh clone before this session's commit `e03926d` |
| Partial-fix limitation (1 of 4 handlers needs 2 returns) | Inherited from `reachcrs`'s own test suite (`tests/test_free5gc_case_study.py`), still true in the ported version here |

**Citations — now verified, with one correction made along the way:**
all three bibliography entries (OpenAnt, AIxCC, OSS-CRS) were checked
directly against their primary sources (arXiv abstract pages, DARPA's
own site) via live fetch, not reconstructed from memory. Full author
lists and exact titles are now in `main.tex`. One real issue this
surfaced and fixed: the draft originally cited OpenAnt only in passing
as "related work," but this project's reachability engine explicitly
follows OpenAnt's decomposition methodology (per the original code's
own docstring) — under-attributing that would have been a real problem
in a submission, not a style nit. The Introduction, Approach, and
Related Work sections now say so explicitly. Still worth a final
independent check by you before submitting (arXiv IDs and DOIs can
change; confirm they still resolve).

**Compiled and verified — real, not assumed.** TeX Live 2026
(`scheme-basic` + `collection-latexextra` + `collection-fontsrecommended`
+ `acmart`) was installed in this environment and `main.tex` was
compiled end to end with `pdflatex`. Real result: **3 pages**, clean
compile, `main.pdf` committed alongside this file as evidence. Two real
issues the compile itself surfaced and that are now fixed:
`printacmref=false` was wrong — the class flags ACM reference format as
mandatory for papers over one page, now `true`; and four inline
`\texttt{}` tokens (long package/file paths) overflowed the narrow
two-column width, fixed with `\sloppy` plus one targeted `\allowbreak`.

**CCS concepts — done, real, not fabricated.** Generated directly from
ACM's own interactive tool at `dl.acm.org/ccs` (used live via browser,
not guessed): **Security and privacy → Software and application
security → Software security engineering** (concept ID
`10002978.10003022.10003023`) and **Security and privacy → Systems
security → Vulnerability management** (concept ID
`10002978.10003006.10011634`), both marked High relevance. The
`\begin{CCSXML}...\end{CCSXML}` + `\ccsdesc{}` block is now in
`main.tex` above `\keywords{}`. Recompiled twice after adding it: the
"CCS concepts are mandatory" warning is gone, page count holds at 3.

**What still needs your action before submitting:**

1. **Author name, affiliation, email** — name/affiliation are filled
   in; email is still the placeholder `[email@institution.edu]` in
   `main.tex`. Recompile after filling it in — real values may shift
   the page count slightly, so re-check it's still $\le$ 4 pages.
2. **HotCRP submission** — `https://free5gc-2026.hotcrp.com/`, PDF
   only, not anonymized (this CFP is not double-blind).

## What this paper deliberately does NOT claim

Matches this repo's own `docs/SCOPE_AND_LIMITATIONS.md` discipline —
don't loosen these in revision:

- Not dynamic/runtime confirmation of the vulnerability against the
  live UDR service (would need MongoDB + NRF deployment — stated as
  future work, not attempted).
- Not a claim that this generalizes beyond this one CVE family / this
  one free5GC file.
- Not vulnerability discovery — CVE-2026-40248 was already known and
  disclosed before this work started.

## If you want to strengthen it before the deadline

In priority order, cheapest-to-most-effort:
1. Verify the four citations (see above) — must happen regardless.
2. Add a short reproducibility statement pointing at the repo (once you
   decide what, if anything, of the repo becomes public alongside the
   paper — this needs its own decision, see `docs/PROJECT_STATUS.md`'s
   LICENSE item, which is still pending your university's IP policy
   check).
3. If time allows before Sept 28: the live-LLM session's `generation_outcome`
   result (if it lands in time) could extend this paper's scope to
   also report LLM-generated (not just rule-based) patches for this
   same case — but do not let paper-deadline pressure rush that session's
   own preconditions (`docs/BENCHMARK_PROTOCOL.md`, `docs/PROJECT_STATUS.md`).
   A solid short paper on what's already verified beats a rushed one
   with an unverified new claim in it.
