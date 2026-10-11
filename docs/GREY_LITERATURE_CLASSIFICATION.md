## Grey literature classification

Classifies all 20 references in `free5gc_full_deployment/FYP_Report_main_upgraded.tex`'s
bibliography along two independent axes: **channel** (grey literature --- not
controlled by a commercial or peer-review publisher --- vs. formally published) and
**content type** (Primary / Secondary / Tertiary, per the standard literature-review
taxonomy). These are deliberately kept separate because they answer different
questions: channel asks "did this go through editorial/peer review before release,"
content type asks "is this original work, or an analysis of other people's original
work." A source can be grey *and* primary at once (most of this bibliography is), and
that combination is not itself a weakness --- it is named explicitly below, together
with what was done to compensate for it.

## Classification table

| Key | Channel | Content type | Why |
|---|---|---|---|
| `weiss-khayet` | Grey (personal blog) | Primary | First-hand account of the author's own original CVE-exploitation experiment |
| `openai-incident` | Grey (corporate blog) | Primary | First-hand incident account from the company directly involved |
| `anthropic-agents` | Grey (corporate blog) | Primary | First-hand description of the vendor's own agent-building practice |
| `aixcc` | Grey (government report/press release) | Primary | Original results from the competition's own organiser |
| `atlantis` | Grey (arXiv preprint) | Primary | Original system description from its own developers |
| `osscrs` | Grey (project website) | Primary | First-hand description of the project's own scope by its own maintainers |
| `free5gc` | Grey (institutional press release) | Primary | First-hand governance announcement from the body making the change |
| `sarif` | Grey (standards-body specification) | Primary | Original, authoritative definition of the format by the body that owns it |
| `openant` | Grey (arXiv preprint) | Primary | Original system and evaluation from its own developers |
| `fuzzingbrain` | Grey (arXiv preprint + repo) | Primary | Original system description, independently checkable against its own open-source repo |
| `ollama` | Grey (product website) | Primary | Official, first-hand source identifying the tool itself |
| `vulnrepaireval` | Grey (arXiv preprint) | Primary | Original benchmark and evaluation |
| `pvbench` | Grey (arXiv preprint) | Primary | Original benchmark and evaluation |
| `pocgym` | Grey (arXiv preprint) | Primary | Original system and evaluation |
| `fangkang` | Grey (arXiv preprint) | Primary | Original experiment and results |
| `qiplausibility` | **Not grey** (ISSTA 2015, peer-reviewed) | **Secondary** | Analyses and critiques three *other* existing systems (GenProg, RSRepair, AE) rather than presenting a new one |
| `sokaixcc` | **Not grey** (USENIX Security 2026, peer-reviewed) | **Secondary** | A "Systematization of Knowledge" --- by definition a synthesis and analysis of the AIxCC competition and its finalist CRSs, not a new system of its own |
| `fangkangzeroday` | Grey (arXiv preprint) | Primary | Original experiment and results |
| `cvegenie` | Grey (arXiv preprint) | Primary | Original system and evaluation |
| `incompletefixeskernel` | Grey (arXiv preprint) | Primary | Original empirical study of the Linux kernel's own commit history |

**18 of 20 references are grey literature; 2 are formally published** (`qiplausibility`,
`sokaixcc` --- the same two sources already identified as the only peer-reviewed
entries in `docs/SOURCE_EVALUATION_CRAAP.md`). This is the same finding from a
different angle, not a coincidence: "grey" (channel) and "not peer-reviewed"
(CRAAP's Authority dimension) are measuring overlapping things here, because this
bibliography has no formally published venue between "arXiv preprint" and "accepted,
peer-reviewed conference paper" --- no journal articles, no books, no theses.

**No tertiary sources** (encyclopedias, textbooks, directories, bibliographies) are
cited anywhere in the bibliography. This is appropriate for a technical literature
review making specific, falsifiable empirical claims --- a tertiary source would be
the wrong tool for any of the claims this bibliography is used to support --- and is
recorded here as a deliberate absence, not an oversight.

**A content-type pattern worth naming**: both of the two non-grey, peer-reviewed
sources are **Secondary literature** --- each is an analysis of other primary
work (three classical repair systems for `qiplausibility`; the AIxCC competition and
its finalists for `sokaixcc`) rather than a primary contribution of a new system or
experiment. Every grey-literature source in the bibliography, by contrast, is Primary
--- a first-hand report of original work by the people who did it. This is the
structurally expected pattern for a fast-moving, pre-peer-review field: the formally
published literature that exists is literature *about* the field (systematic
reviews, SoKs), while the field's actual frontier results are still sitting in grey
literature because peer review has not caught up to them.

## Why grey literature is used here, and what was done about it

The field this thesis's Lit Review covers --- LLM agents for offensive/defensive
software security --- is moving faster than the peer-review cycle: several of the
sources cited (`pvbench`, `incompletefixeskernel`, `sokaixcc` itself) post-date the
project's own earliest work this session and would not exist in any peer-reviewed form
in time to be cited at all if peer-reviewed sources were the only ones admitted. This
matches exactly the stated case for using grey literature in a review: it can be "even
more current and up-to-date than published academic papers," and excluding it here
would not make the Lit Review more rigorous, it would make it describe a 2023-era
field instead of the one this thesis is actually situated in.

The stated risk of grey literature is that it has not been through the review process
that would normally catch an error before publication, which is exactly why the
guidance stresses cross-checking grey sources against other information before relying
on them. This thesis's own literature-review process already did this, independently
of being handed this specific framework:

- **`docs/SOURCE_EVALUATION_CRAAP.md` is itself a cross-checking exercise** applied to
  every grey source in this bibliography, and it already caught one real error this
  way: an initial characterisation of `pocgym`'s own headline figure was wrong (mixed
  up with a different paper found in the same search), and was only caught because the
  paper's own primary text was read directly rather than trusted from a secondary
  description.
- **Three grey sources making specific, checkable claims** (`atlantis`, `openant`,
  `fuzzingbrain`) were independently re-verified against their own primary text or, for
  `fuzzingbrain`, cross-checked against its own open-source repository as a second,
  independent artifact --- not just the paper's own prose. All three held up exactly
  as cited.
- **Where a single grey source carried an empirical claim this project leans on**
  (`aixcc`'s DARPA press release, a textbook example of a "government report" in the
  grey-literature examples above), it was deliberately paired with a formally
  published, peer-reviewed secondary source making the same point (`sokaixcc`) rather
  than left to stand alone --- the single clearest case in this bibliography of
  grey-literature cross-checking against a more authoritative source, done before this
  specific framework was introduced to this review.

## What this does not claim

This classification does not claim every grey source here is equally reliable ---
`docs/SOURCE_EVALUATION_CRAAP.md`'s Authority and Accuracy ratings already draw that
distinction (a personal Substack post and a USENIX-accepted SoK are both grey, but
"is it grey" is the wrong question to ask about either of them in isolation; what
matters is whether each is used in a way proportionate to what it actually
establishes, which the CRAAP document audits directly). This document answers a
narrower, complementary question --- how much of this Lit Review rests on literature
that has not yet been through formal peer review, and why that is a defensible,
deliberate choice for this specific field rather than a citation-practice gap --- and
should be read alongside the CRAAP document, not as a replacement for it.
