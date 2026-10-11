# Source evaluation (CRAAP framework)

Applied to all 20 references in `free5gc_full_deployment/FYP_Report_main_upgraded.tex`'s
bibliography, using the CRAAP framework (Currency, Relevance, Authority, Accuracy,
Purpose; California State University, Chico, Meriam Library). Each source gets a
per-dimension rating (**Strong** / **Adequate** / **Weak**) and a one-line reason, not
a restated definition of the dimension.

**A note on how "Accuracy" was assessed here.** For the 9 sources added in this
session's literature-review passes (`vulnrepaireval` through `incompletefixeskernel`
below), Accuracy reflects a live re-read of the source's own abstract/full text this
session, including two cases where that re-read caught and corrected a wrong figure
before it reached the thesis (see `pocgym` below). For the 11 sources already in the
thesis before this session, Accuracy reflects the citation's own stated venue and
metadata, not a fresh independent re-verification of its figures performed in this
pass --- that distinction is flagged explicitly per entry rather than glossed over.

## Summary table

| Key | Type | Currency | Relevance | Authority | Accuracy | Purpose |
|---|---|---|---|---|---|---|
| `openai-incident` | Corporate blog post | Adequate | Strong | Adequate | Adequate | Weak |
| `anthropic-agents` | Corporate engineering blog | Adequate | Strong | Strong | Adequate | Weak |
| `weiss-khayet` | Personal Substack post | Adequate | Strong | Weak | Weak | Weak |
| `aixcc` | Government press release | Weak | Strong | Strong | Adequate | Weak |
| `atlantis` | arXiv preprint | Strong | Strong | Adequate | Strong | Strong |
| `osscrs` | Project website | Adequate | Strong | Adequate | Strong | Weak |
| `free5gc` | Foundation press release | Weak | Adequate | Adequate | Strong | Weak |
| `sarif` | Formal standard (OASIS) | Weak | Adequate | Strong | Strong | Strong |
| `openant` | arXiv preprint | Strong | Strong | Adequate | Strong | Strong |
| `fuzzingbrain` | arXiv preprint + repo | Strong | Strong | Adequate | Strong | Strong |
| `ollama` | Product website | Adequate | Adequate | Adequate | Strong | Weak |
| `vulnrepaireval` | arXiv preprint | Strong | Strong | Adequate | Strong | Strong |
| `pvbench` | arXiv preprint | Strong | Strong | Adequate | Strong | Strong |
| `pocgym` | arXiv preprint | Strong | Strong | Adequate | Strong | Strong |
| `fangkang` | arXiv preprint | Adequate | Strong | Strong | Strong | Strong |
| `qiplausibility` | Peer-reviewed (ISSTA 2015) | Weak | Strong | Strong | Strong | Strong |
| `sokaixcc` | Peer-reviewed (USENIX Sec. 2026) | Strong | Strong | Strong | Strong | Strong |
| `fangkangzeroday` | arXiv preprint | Adequate | Strong | Strong | Strong | Strong |
| `cvegenie` | arXiv preprint | Strong | Strong | Adequate | Strong | Strong |
| `incompletefixeskernel` | arXiv preprint | Strong | Strong | Adequate | Strong | Strong |

Pattern visible in the table before the per-source detail: every **Weak** rating in
the Authority and Accuracy columns falls on one of the three non-research sources
(`weiss-khayet`, and secondarily the two press releases/blog posts); every arXiv
preprint not yet confirmed peer-reviewed lands at **Adequate**, not Strong, on
Authority specifically because arXiv preprints are not peer-reviewed at the point of
posting --- a real, stated limitation, not an oversight. Every source scoring
**Weak** on Purpose is marketing, promotional, or personal-opinion writing rather than
a research contribution; this is used deliberately below to separate "this source
supports a factual/motivational claim" from "this source supports an empirical
finding," which is exactly how each one is actually used in the thesis.

## Pre-existing sources (in the thesis before this session)

### `weiss-khayet` --- "Can AI weaponize new CVEs in under 15 minutes?" (Substack, 2025)

- **Currency**: Adequate. Aug. 2025, recent enough for the fast-moving agentic-security
  field, but this is the thesis's single most load-bearing citation for its own
  motivating premise and it rests on the weakest source in the bibliography.
- **Relevance**: Strong. Directly on point --- the thesis's own prototype is explicitly
  built on this pipeline.
- **Authority**: Weak. A personal Substack post, not a peer-reviewed paper, an
  institutional report, or even a corporate engineering blog. No stated institutional
  affiliation or review process.
- **Accuracy**: Weak. No independent replication is cited; the "under fifteen minutes"
  claim is the author's own self-report, with no raw data, methodology appendix, or
  third-party verification available alongside it, as far as this evaluation could
  determine.
- **Purpose**: Weak. A personal blog post's primary purpose is to demonstrate a
  capability and attract attention to the author's work, not to establish a reviewed
  empirical finding.
- **Verdict**: The thesis already does the right mitigating thing here --- it uses this
  source only as motivation/basis-for-extension ("their pipeline formed the direct
  basis for AI-exploit-CVE"), never as evidence for an empirical claim this project
  itself relies on, and this session added two actual peer-adjacent, better-evidenced
  sources (`fangkang`, `fangkangzeroday`) right next to it making the same point with
  real numbers. The weak source is still cited for attribution of lineage, which is
  legitimate; it is just not pulling the evidentiary weight here, and should not be.

### `openai-incident` --- "The Hugging Face incident and the road ahead" (OpenAI blog, 2026)

- **Currency**: Adequate (Aug. 2026).
- **Relevance**: Strong --- used specifically to open the "AI can hack" framing the
  Introduction reacts to, which is exactly what it is.
- **Authority**: Adequate. A corporate blog post from the model vendor itself, not an
  independent third party; reasonable authority on "what happened" (first-party
  incident account) but not disinterested authority on how that incident should be
  interpreted.
- **Accuracy**: Adequate. First-party incident accounts are generally accurate about
  the bare facts of what occurred, less reliable on framing/severity, which OpenAI has
  a vested interest in managing.
- **Purpose**: Weak. A vendor's own post about an incident involving its own product
  has an inherent motive to shape the narrative; cited here appropriately as "this is
  the framing this project pushes back against," not as neutral evidence.
- **Verdict**: Appropriate use for a motivating/framing citation; would not be
  appropriate if used as evidence for a technical claim, and it is not used that way.

### `anthropic-agents` --- "Building effective AI agents" (Anthropic Engineering, 2024)

- **Currency**: Adequate (Dec. 2024; the field has moved since, but the definition of
  "agent" used doesn't depend on anything that has since changed).
- **Relevance**: Strong --- used for a single definitional sentence (what counts as an
  "agent" in this literature), which is exactly the kind of claim a vendor engineering
  blog is well-suited to support.
- **Authority**: Strong for this specific purpose. Anthropic is a primary, credible
  source on how the term "agent" is used in its own and the broader industry's current
  practice, even though it is not a peer-reviewed academic source.
- **Accuracy**: Adequate --- a definitional claim, not an empirical one, so there is
  little to independently verify beyond "is this a fair restatement," which it is.
- **Purpose**: Weak by CRAAP's strict reading (a vendor engineering blog's purpose
  includes promoting the vendor's own products), but this is close to irrelevant for a
  purely definitional citation.
- **Verdict**: Good fit for its narrow, definitional purpose; would be a poor sole
  source for an empirical claim, and is not used as one.

### `aixcc` --- "AIxCC Final Competition Results" (DARPA press release, 2025)

- **Currency**: Weak. A press release is a snapshot, not a living record, and this
  session's own literature pass found exactly the gap this predicts: the headline
  86%/68% figures had no independent, reviewed analysis behind them in the
  bibliography until `sokaixcc` was added alongside it.
- **Relevance**: Strong --- the headline AIxCC figures the thesis repeatedly compares
  itself against come directly from here.
- **Authority**: Strong. DARPA is the competition's own organiser and the authoritative
  primary source for the competition's own results.
- **Accuracy**: Adequate. Primary-source numbers from the organiser are generally
  reliable for the bare figures, but a press release is not held to the same standard
  of detailed methodological disclosure as a peer-reviewed paper, and this project has
  no independent way to audit how "discovered" or "patched" were operationally defined
  in the underlying competition scoring.
- **Purpose**: Weak. A government agency's own press release about its own flagship
  competition has an institutional interest in presenting favourable headline numbers.
- **Verdict**: This was the single weakest-supported empirical claim in the
  bibliography before this session's `sokaixcc` addition; it is now corroborated by a
  peer-reviewed, third-party systematic analysis of the same competition, cited
  alongside it rather than replacing it (the thesis still correctly cites DARPA as the
  primary source for its own numbers).

### `atlantis` --- ATLANTIS AIxCC winning-system paper (arXiv, 2025)

- **Currency**: Strong (Sep. 2025, describing a system that competed in 2025).
- **Relevance**: Strong --- the thesis names ATLANTIS as AIxCC's winning system and
  cites this directly for that claim.
- **Authority**: Adequate. Multiple-author arXiv preprint from the system's own
  developers; not independently confirmed peer-reviewed as part of this evaluation,
  and a paper describing one's own competition-winning system has an inherent
  self-promotional interest, though the bare factual claims (what the system combined,
  that it won) are independently checkable against the AIxCC results themselves.
- **Accuracy**: Strong --- re-verified directly this session against the paper's own
  abstract: confirms the AIxCC-final win (DEF CON 33, Aug. 2025) and the LLM +
  program-analysis (symbolic execution, directed fuzzing, static analysis) combination
  the thesis describes.
- **Purpose**: Strong for a technical system-description paper from its own authors,
  which is a normal and appropriate way to document a novel system's architecture.
- **Verdict**: Reasonable technical citation; the self-description risk is mitigated by
  the claim being a simple factual one (what the system is composed of) rather than a
  disputed performance claim.

### `osscrs` --- OSS-CRS project website

- **Currency**: Adequate --- a live project site, presumably kept current by its
  maintainers, but with no publication date to anchor it.
- **Relevance**: Strong --- used for exactly what it is (describing what the OSS-CRS
  project does).
- **Authority**: Adequate. An OpenSSF-hosted project site is a reasonably authoritative
  primary source for describing its own project's scope and purpose.
- **Accuracy**: Strong for a purely descriptive, non-empirical claim about what a
  project does; there is little room for the kind of accuracy error that would matter
  for an empirical figure.
- **Purpose**: Weak by CRAAP's strict standard (a project site's purpose includes
  promoting the project), but again close to irrelevant for a purely descriptive
  citation.
- **Verdict**: Appropriate for its role; would be inappropriate as the sole source for
  a disputed performance claim, and is not used that way.

### `free5gc` --- Linux Foundation press release on free5GC's move under the Foundation

- **Currency**: Weak, structurally (a press release dated to a single announcement
  event, not a living record) but the fact it supports --- free5GC's status and
  governance --- does not meaningfully change over time in a way that would
  invalidate the citation.
- **Relevance**: Adequate --- used for background/context on free5GC's standing as a
  real, governed open-source project, which is exactly its content.
- **Authority**: Adequate. The Linux Foundation is an authoritative source for its own
  governance announcements.
- **Accuracy**: Strong for the kind of claim it supports (an institutional fact about
  project governance), low risk of inaccuracy.
- **Purpose**: Weak by CRAAP's strict standard (a press release's purpose includes
  promoting the announcement), again largely immaterial for this specific,
  non-empirical use.
- **Verdict**: Fine for its narrow descriptive purpose.

### `sarif` --- SARIF v2.1.0 specification (OASIS, 2020)

- **Currency**: Weak by date (2020) but this is a formal, versioned technical
  standard, not a finding that ages the way an empirical result does; version 2.1.0 is
  still the current version referenced by tooling that uses SARIF today, so this is
  not actually a currency problem in practice.
- **Relevance**: Adequate --- used to name the interchange format bridging ProvTrail's
  static findings and this project's own pipeline, a minor but legitimate use.
- **Authority**: Strong. OASIS is the formal standards body responsible for SARIF;
  this is the canonical primary source.
- **Accuracy**: Strong --- a formal specification document is as authoritative as a
  source can be for defining its own format.
- **Purpose**: Strong --- a technical standard's purpose is to define the standard,
  with no promotional or persuasive angle to discount.
- **Verdict**: Exemplary citation for what it is; no concerns.

### `openant` --- OpenAnt (arXiv, 2026)

- **Currency**: Strong (2026, describing current work).
- **Relevance**: Strong --- central comparison point for this thesis's own
  reachability-filtering approach, discussed at length and used as a direct
  methodological contrast throughout Chapter 2.
- **Authority**: Adequate. Two-author arXiv preprint; not independently confirmed
  peer-reviewed in this evaluation pass.
- **Accuracy**: Strong --- the "up to 97%" figure and the OpenSSL/WordPress/Flowise
  evaluation targets were re-verified this session against independent secondary
  coverage (including the authors' own company blog) describing the same paper; the
  thesis's own discussion additionally and correctly hedges this as a self-reported
  "up to" figure rather than independently re-measured by this project.
- **Purpose**: Strong --- a technical research paper describing a novel system,
  appropriate authorial purpose.
- **Verdict**: Well-used; the thesis's own hedging language already compensates for
  the Authority gap rather than overstating what an unreviewed preprint establishes.

### `fuzzingbrain` --- "All You Need Is A Fuzzing Brain" (arXiv + competition repo, 2025)

- **Currency**: Strong.
- **Relevance**: Strong --- used repeatedly as a direct comparison point for both
  reachability filtering and, notably, patch-validation rigour (its compile+regression
  criterion), which is one of the thesis's more substantive literature comparisons.
- **Authority**: Adequate (unreviewed arXiv preprint) but meaningfully strengthened by
  the paired, independently-checkable competition repository link, which lets a
  reader verify the system's actual published validation criteria rather than only
  trusting the paper's own description of them.
- **Accuracy**: Strong --- the dual citation (paper + repo) is exactly the right
  pattern for an unreviewed preprint making a claim about a system's actual behaviour:
  the repo is independently checkable evidence, not just the authors' own prose. This
  session additionally re-verified the two specific claims the thesis makes against
  the paper's own full text directly: the three-part patch-acceptance criterion
  (compiles without error, eliminates all known POVs, and passes a regression
  `TestSuite`) matches the thesis's "compile successfully and pass a supplied
  regression-test suite" description, and the dedicated "SARIF Assessment Mode"
  section confirms the thesis's claim about an externally-supplied-findings mode
  verbatim ("validates externally provided vulnerability reports, typically from
  static analysis tools or issue trackers").
- **Purpose**: Strong --- genuine technical documentation of a competition system.
- **Verdict**: One of the better-supported citations in the bibliography precisely
  because of the repo pairing; a model for how an otherwise-Adequate-Authority source
  can be used responsibly.

### `ollama` --- Ollama product website

- **Currency**: Adequate --- a live, maintained product site.
- **Relevance**: Adequate --- used only to identify what Ollama is, a minor
  infrastructural citation.
- **Authority**: Adequate --- the product's own official site is the correct primary
  source for identifying it.
- **Accuracy**: Strong for this narrow use (there is nothing to get wrong about "this
  is Ollama's website").
- **Purpose**: Weak by CRAAP's strict standard (a product site's purpose includes
  promoting the product), immaterial here.
- **Verdict**: Fine; this is the correct category of citation for identifying a tool
  used in the methodology, not a claim requiring independent verification.

## Sources added this session (independently re-verified at the time of addition)

These 9 sources share a pattern worth stating once rather than seven times: all are
arXiv preprints except `qiplausibility` (ISSTA 2015, peer-reviewed) and `sokaixcc`
(USENIX Security 2026, peer-reviewed, distinguished-paper runner-up), so Authority
lands at **Adequate** for most of them on the same peer-review basis as `openant` and
`fuzzingbrain` above --- this is a real, stated limitation of a literature review
drawing heavily on a fast-moving field where peer review lags publication by months to
years, not an inconsistency specific to these sources. Where it was possible to check
Accuracy against the primary source directly this session (all nine), that check was
done, and in two cases it mattered:

- **`pocgym` is the clearest case where this evaluation process caught a real error.**
  An initial characterisation of this paper (71.5% of PoCs invalid) was mixed up with a
  different paper found in the same search pass. Re-reading PoC-Gym's own arXiv
  abstract directly caught the error before it reached the thesis and produced the
  correct figure actually used (65 of 116 candidates, i.e. 44% false-positive rate).
  This is recorded here as a demonstration of why the Accuracy check in this framework
  is not a formality: a title-level or secondary-source-level read would have put a
  wrong number into the thesis.
- **`qiplausibility`'s classical, pre-LLM finding was deliberately sought out** rather
  than relying only on recent arXiv preprints making the same validation-rigour point,
  specifically to raise the Currency/Authority balance of that part of the Lit Review:
  a 2015 ISSTA paper is weaker on Currency than a 2026 preprint but far stronger on
  Authority (peer-reviewed venue vs. none), and was added for exactly that trade-off.

### `vulnrepaireval`, `pvbench`, `pocgym`, `cvegenie`, `incompletefixeskernel` --- recent arXiv preprints (2025--2026)

- **Currency**: Strong --- all within the last 6--18 months of the thesis's own
  writing, appropriate for a field moving this fast.
- **Relevance**: Strong --- each was selected specifically because it quantifies a
  claim the thesis already makes qualitatively (validation-rigour gap, exploit-
  reproduction cost/scale, incomplete-fix root causes), not added for general topical
  adjacency.
- **Authority**: Adequate --- unreviewed arXiv preprints at time of citation; multi-
  author, identifiable institutional affiliations, but no peer review to date as far
  as this evaluation could confirm.
- **Accuracy**: Strong --- each was read directly (abstract or full text) this
  session rather than cited from a secondary summary, and the specific figures used in
  the thesis were checked against that direct read.
- **Purpose**: Strong --- genuine empirical research papers with no promotional
  content detected.

### `fangkang`, `fangkangzeroday` --- Fang, Kang et al.'s one-day and zero-day exploitation papers (arXiv, 2024)

- **Currency**: Adequate --- 2024, the oldest of this session's additions, but still
  the foundational and most-cited pair of papers in exactly this sub-field, so their
  age is a feature (establishing precedent) rather than a weakness here.
- **Relevance**: Strong --- the single most direct precedent for the thesis's own
  core premise (an agent can exploit a known CVE from its advisory text alone).
- **Authority**: Strong relative to the other arXiv preprints in this bibliography:
  these are among the most widely cited and discussed papers in this specific
  sub-field, which is itself a form of community-validated authority distinct from
  formal peer review, and was corroborated by this session's own web search returning
  substantial independent press and technical commentary on both papers.
- **Accuracy**: Strong --- read directly this session; the headline figures used in
  the thesis (87% vs. 0%/7%; 4.3x improvement) were taken from the papers' own
  abstracts, not a secondary characterisation.
- **Purpose**: Strong --- genuine, widely-discussed empirical research with an
  explicitly stated dual-use safety framing in both papers, not promotional content.

### `sokaixcc` --- SoK: DARPA's AI Cyber Challenge (USENIX Security 2026)

- **Currency**: Strong.
- **Relevance**: Strong --- added specifically to upgrade the evidentiary basis for
  the `aixcc` press-release figures already cited elsewhere.
- **Authority**: Strong --- the only source in this bibliography confirmed, during
  this session's own verification, to be a peer-reviewed, accepted conference paper
  (USENIX Security 2026) that was also a distinguished-paper-award runner-up, making
  it arguably the single highest-authority source in the entire bibliography.
- **Accuracy**: Strong on venue/status (confirmed via the paper's own arXiv listing
  and USENIX's own program page during this session); the specific internal findings
  beyond the headline competition description were not independently re-verified
  against the full text, which this evaluation flags rather than overstates.
- **Purpose**: Strong --- a systematic, third-party academic analysis explicitly
  designed to be more disinterested than the organiser's own press release it sits
  alongside.
- **Verdict**: The strongest single addition made this session on Authority grounds
  specifically, and a direct, deliberate upgrade to the weakest pre-existing citation's
  evidentiary support (`aixcc`).

## Overall assessment

- **No source in this bibliography should be mistaken for a close read of a top-tier,
  long-track-record venue.** Only two of twenty references (`qiplausibility`,
  `sokaixcc`) are confirmed peer-reviewed. This is a real, stated characteristic of
  working in a sub-field (LLM agents for offensive/defensive security) that is moving
  faster than the peer-review cycle, not a citation-practice failure specific to this
  thesis --- but it should be named explicitly rather than left implicit, which this
  document now does.
- **The three weakest sources by CRAAP (`weiss-khayet`, and secondarily the two press
  releases) are each used only for motivation, lineage, or background framing, never
  as the sole evidentiary basis for an empirical claim the thesis itself depends on.**
  That is the correct way to use a Weak-Authority source, and this evaluation found no
  case in this bibliography where a low-authority source is asked to carry more
  evidentiary weight than its Authority rating would justify.
- **Where a single weak source supported an empirical claim this project leans on**
  (`aixcc`'s headline AIxCC figures), this session's literature work closed that gap
  by finding and citing an independent, peer-reviewed source for the same claim
  (`sokaixcc`) rather than leaving the press release to stand alone.
- **This evaluation's own limitation, narrowed by a follow-up pass**: a first pass
  flagged that Accuracy for the 11 pre-existing sources rested on stated metadata, not
  a fresh re-verification. A targeted follow-up then re-checked the three pre-existing
  sources making specific, checkable numeric/technical claims --- `atlantis`,
  `openant`, and `fuzzingbrain` --- directly against their primary sources (the last
  one against its full text, not just its abstract), and all three held up exactly as
  cited; their Accuracy ratings above were updated from Adequate to Strong as a
  result. The remaining 8 pre-existing sources (`openai-incident`, `anthropic-agents`,
  `weiss-khayet`, `aixcc`, `osscrs`, `free5gc`, `sarif`, `ollama`) were deliberately
  left unverified in this pass because they support definitional, lineage, or
  background claims with no number or technical figure to check --- re-reading them
  would not surface anything a review of their citation type and Purpose rating
  already captures. That is a scoped decision, not an oversight, and is recorded here
  so the scope of what was and wasn't re-verified is explicit rather than implied.
