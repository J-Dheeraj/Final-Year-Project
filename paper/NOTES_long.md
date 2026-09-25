> **VOID — conference submission abandoned (2026-09-25).** Neither the
> short nor the long paper is being submitted anywhere. The deliverable is
> now the full FYP report + viva + demo. The technical content and the
> verified-numbers list below stay useful as source material for the
> report's free5GC chapter; the HotCRP/deadline/"action needed before
> submitting" parts are dead. Kept as a verification record, not a plan.

# Notes on the LONG-paper draft (`main_long.tex`) — read before submitting

This is the long-track variant of `main.tex` for the 2nd free5GC World Forum.
Long track: **up to 12 pages for review, 9 camera-ready** (bibliography + a
well-marked appendix excluded). ACM `sigconf`, not double-blind. Same Sept 28,
2026 deadline, same HotCRP site as the short paper.

## Compile status (real, not assumed)

Compiled end-to-end with `pdflatex` (same TeX Live / `acmart` setup as
`main.tex`). Real result: **6 pages**, clean compile, 0 errors, all citations
and cross-references resolved, all 7 figures included. `_build/main_long.pdf` is
the artifact. 6 pages sits inside the long-track range and well under both caps.

## What is verified

- **Every technical number** (102 functions, 4 reachable, 96.1%, four handlers,
  3 full / 1 partial patch, baseline+patched `go build ./...` OK) is drawn from
  the repo's real case study: `docs/REACHABILITY.md`, `src/reachability/*`, and
  `src/reachability/verify_against_real_upstream.py`. No number was invented for
  the long version.
- **Both CVEs** (CVE-2026-40248 / GHSA-jgq2-qv8v-5cmj and CVE-2026-40246 /
  GHSA-g9cw-qwhf-24jp, both CWE-285, CVSS 7.5) are the same missing-`return`
  family fixed by the same commit `86686276...`. The long draft frames the study
  as covering that *family* rather than one CVE — accurate, because the single
  reachability run over `api_datarepository.go` covers all four handlers the fix
  touches. It does **not** claim two independent evaluations.
- **Citations checked against primary sources this session:** OpenAnt
  (arXiv:2606.19149), OSS-CRS (arXiv:2603.08566), FuzzingBrain (arXiv:2509.07225,
  real AIxCC 4th-place finalist paper — newly added), Kuznetsov et al. 2019
  (UKRCON, DOI 10.1109/UKRCON.2019.8879997 — venue name corrected from the docx),
  Almazyad et al. 2024 (AICCSA). AIxCC and free5GC as in the short paper.

## What still needs YOUR action before submitting

1. **Proofread the prose.** This draft was rebuilt in LaTeX from the clean
   `main.tex` plus your docx's added sections — it does NOT carry the docx's
   paraphrase errors (reversed contribution, "crank out", "influenced", etc.),
   but read it once end-to-end in your own voice.
2. **Verify the 7 figures.** `figures/fig1.png`..`fig7.png` were extracted
   verbatim from your `.docx` and reused with your original captions. Confirm
   each is the intended, legible final figure at column width (the control-flow,
   workflow, call-graph, verification, reduction, patch-outcome, and
   evidence-boundary figures, in that order).
3. **Email / page recheck.** Email is already filled; recompile after any edit
   and confirm it still lands $\le$ 12 review pages.
4. **HotCRP:** https://free5gc-2026.hotcrp.com/ — PDF, not anonymized, pick the
   long-paper track.

## What this draft deliberately does NOT claim (do not loosen)

Same discipline as `docs/SCOPE_AND_LIMITATIONS.md` and the short paper's NOTES:

- Not runtime/dynamic confirmation against the live UDR (needs MongoDB + NRF —
  stated as the top future-work item).
- Not generalisation beyond this one file / one vulnerability family.
- Not discovery — both CVEs were disclosed before this work.
- One handler is only partially corrected; this is stated, not hidden.

## Honest strategic note

At 6 pages the draft is long-track-*valid* but on the short end, because the
underlying evidence is the same single file / single family as the short paper —
presented in more depth, not with new results. This is a legitimately honest
long paper, not a padded one. To make it a genuinely *strong* long paper, the
real levers (both real work, deferred) are: (a) runtime confirmation against a
live free5GC UDR deployment, or (b) a genuinely independent second target
(another free5GC component / CVE class). Neither should be rushed before Sept 28.
If you cannot add one of those in time, the crisp short paper (`main.tex`)
remains the safer acceptance bet — both tracks get identical ACM DL treatment.
