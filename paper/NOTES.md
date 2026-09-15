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

**What is NOT verified and needs your action before submitting:**

1. **All four `%% TODO` citations in `main.tex`.** I reconstructed these
   from an earlier research document pasted into this project's
   conversation, not from a fresh, independent check this session. Do
   not trust arXiv IDs, author lists, or venues from this draft —
   pull each one up yourself (arXiv, Google Scholar, or the DARPA page
   directly) and confirm it exists and says what the paper claims it
   says. A fabricated or wrong citation in a real ACM submission is a
   serious problem, not a formatting nit.
2. **Author name, affiliation, email** — placeholders in `main.tex`,
   fill in before compiling for real.
3. **Compile it.** No LaTeX toolchain is available in the environment
   this draft was written in, so `main.tex` has not been test-compiled.
   Paste it into Overleaf's ACM `sigconf` template (search "ACM
   Conference Proceedings" in Overleaf's template gallery) or compile
   locally with a full TeX Live/MiKTeX install that includes the
   `acmart` package. Check the page count fits the short-paper limit
   (4 pages including references) — the current draft is written to
   roughly that length but hasn't been measured against real compiled
   output.
4. **CCS concepts / keywords formatting.** The CFP mentions CCS concept
   codes are required; `\keywords{}` is filled in but proper CCS
   concept codes (`\begin{CCSXML}...\end{CCSXML}` block, standard in
   `acmart`) are not yet added — look up the right codes at
   `dl.acm.org/ccs` for security/networking topics and add them.
5. **HotCRP submission** — `https://free5gc-2026.hotcrp.com/`, PDF
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
