## Audit against the 2002 SCSE report-writing guide

Audits `free5gc_full_deployment/FYP_Report_main_upgraded.tex` against the School of
Computer Engineering's July 2002 report-writing guide
(`www3.ntu.edu.sg/scse/fyp/UsefulInfo/Report%20Guide.pdf`). This is a format/content
guide, not a mark scheme, and it predates the school's rename to the College of
Computing and Data Science by over two decades --- that context matters for how to
read the findings below, and is stated explicitly rather than glossed over.

Per the user's own scoping decision, this audit covers **content and structure only**;
physical layout (margins, line spacing, single font) is not checked here, since that
is normally governed by whatever template the current school issues, not a
24-year-old guide for a renamed department.

## 1. Length

**Guide**: main report body $\leq$ 10,000 words, excluding charts, diagrams,
appendices, tables, and references. No page limit stated.

**Finding: over the limit, substantially.** A word count of Chapters 1--5
(Introduction through Conclusion, i.e. everything between the Abstract and the
Bibliography --- the guide's own definition of what should be counted) gives:

| Scope | Word count |
|---|---|
| Full main-body text, including table/figure captions | ~18,700 |
| Main-body text with `table` and `figure` environments stripped entirely | ~17,100 |

Even under the more generous exclusion (whole tables and figures removed, not just
their captions), the main body is roughly **71% over** the 10,000-word ceiling this
specific guide states. This is a genuine finding, not a rounding issue --- it is not
close to the limit in either direction of measurement.

**Caveat that matters here**: this guide is from 2002 and targets a programme that no
longer exists under that name. A research-evidence-heavy project like this one, with
five evolving pipeline rounds, three real-upstream case studies, multiple model
comparisons, and the degree of trace-level methodological self-correction this report
documents, is a different kind of deliverable than what a 10,000-word ceiling was
likely calibrated for in 2002. This audit reports the number honestly rather than
assuming the limit still applies as written; whether the current CCDS FYP guidance
(which this audit was not given and has not checked) retains, raises, or drops this
specific ceiling is the actual question that determines whether this is actionable.

## 2. Structure

**Guide**: title page, abstract, acknowledgements, contents, lists of figures/tables,
main chapters, conclusions and recommendations, references, optional appendices.

| Element | Present? | Location |
|---|---|---|
| Title page | Yes | `\begin{titlepage}` |
| Abstract | Yes | `\chapter*{Abstract}` |
| **Acknowledgements** | **No** | Not found anywhere in the document |
| Contents | Yes | `\tableofcontents` |
| List of figures | Yes | `\listoffigures` |
| List of tables | Yes | `\listoftables` |
| Main chapters | Yes | Introduction, Literature Review, Methodology, Results and Discussion, Conclusion |
| Conclusions and recommendations | Yes | `\chapter{Conclusion}` includes a dedicated `\section{Future Work}`, which is this report's recommendations section in substance even though it is not labelled "Recommendations" |
| References | Yes | `\begin{thebibliography}`, correctly placed after the main chapters and before the appendices |
| Appendices (optional) | Yes | Four appendix chapters: Reproducibility Details, Selected Trace Excerpts, Verbatim Prompts, Repository and Artifact Access |

**One real structural gap: no Acknowledgements section.** This is the only item on
the guide's required list that is simply absent, not merely under-labelled. It is a
one-paragraph addition (supervisor, any other named support) and the lowest-risk,
highest-value fix in this entire audit --- unlike the word count, there is no
ambiguity about whether it's still expected.

## 3. Project content

**Guide**: problem and objectives, related work, methods, resources/tools, work
completed, results, discussion, a project schedule (with the revised schedule and an
explanation of changes if the actual work differed from the plan).

| Element | Present? | Location |
|---|---|---|
| Problem and objectives | Yes | Chapter 1: Background, Research Gap, Objectives, Scope |
| Related work | Yes | Chapter 2: Literature Review (20 sources, independently audited in `docs/SOURCE_EVALUATION_CRAAP.md`) |
| Methods | Yes | Chapter 3: Methodology (System Architecture, Data Sources, Algorithms, Implementation, Testing) |
| Resources/tools | Yes | Appendix A (Programming Environment: real hardware/OS specs, language versions) and scattered through Methodology |
| Work completed | Yes | Chapter 4: Results and Discussion |
| Results | Yes | Chapter 4, with tables, 2 plots, and a classification-ablation confusion matrix |
| Discussion | Yes | Chapter 4 \S4.2, and Chapter 5's Limitations |
| **Project schedule** | **No** | Not found anywhere --- no timeline, Gantt chart, milestone list, or phase breakdown |

**One real content gap: no project schedule anywhere, and no account of how the
actual work differed from an original plan.** This is the second item the guide
requires that this report genuinely does not have, and it is a notable omission given
that the project's own history (outside this report, in `CLAUDE.md` and the project's
session logs) explicitly records a real, material change of plan: the project's
original pitch was framed around "fuzzing LLMs to secure OSS," and was deliberately
dropped --- with the professor's agreement --- once it became clear nothing in the
pipeline does actual coverage-guided fuzzing, in favour of the honest framing this
report now uses throughout ("LLM-assisted exploit confirmation and patch validation
for known CVEs" plus "reachability-filtered static analysis on real upstream source").
That is precisely the "actual work differed from the plan, explain the changes"
scenario the guide anticipates, and it happened, but the report itself never says so
--- a reader only sees the final, settled framing, not that it changed or why. This is
a free, already-true, already-defensible story that simply has not been written down
in the report yet.

## 4. Results and conclusions

**Guide**: present key results, not a data dump; discuss what they mean and whether
objectives were met; conclusions should follow from the results and state limitations.

**Finding: fully satisfied, already independently audited.** This is not a fresh
finding --- `docs/RESULTS_DISCUSSION_CHECKLIST_AUDIT.md`, produced earlier this
session against a more detailed Results/Discussion checklist, already covers this
exact ground in more depth (17/20 pass, 2 gaps found and since fixed: plots and
classification metrics). The Objective Closure table (Chapter 5, \S "Objective
Closure") explicitly states met/partially-met status against each of Chapter 1's
stated objectives, which is precisely the "discuss whether objectives were met"
requirement in explicit, auditable form rather than left implicit. The Limitations
section (Chapter 5, \S "Limitations") is substantial and specific, not a token
paragraph.

## 5. Technical writing

**Guide**: SI units, clear organisation, correct grammar, enough method detail to
understand or reproduce the work.

- **SI units**: consistent throughout --- durations in seconds, file/data sizes in
  KB/MB/GB, percentages to one decimal place. No unit inconsistencies found in this
  pass.
- **Clear organisation**: strong --- the chapter/section hierarchy is consistent, and
  cross-references (`\ref{}`) resolve correctly throughout (verified by this session's
  own repeated 3-pass `lualatex` compiles with no undefined-reference warnings in the
  final pass).
- **Correct grammar**: not something this audit can certify with the same confidence
  as the structural checks above; no errors were noticed in the extensive reading this
  session involved, but that is incidental coverage, not a dedicated proofreading pass.
- **Reproducibility detail**: strong, and arguably this report's standout strength on
  this specific criterion --- Appendix C reproduces the actual system/user prompts
  verbatim, Appendix A gives real hardware/OS specs, and Appendix B gives trace
  excerpts and the exact repository/commit/tag references needed to reproduce every
  headline result.

## Summary

| Area | Verdict |
|---|---|
| Length | **Fails** the stated 10,000-word ceiling by a wide margin, but the ceiling's own currency for a 2026 research-heavy CCDS project is genuinely uncertain |
| Structure | **One gap**: no Acknowledgements section |
| Project content | **One gap**: no project schedule, and no documented account of the real framing-pivot that occurred |
| Results/conclusions | **Fully satisfied**, already independently audited in more depth elsewhere |
| Technical writing | **Fully satisfied** on every checkable dimension |

Two of the five areas have a concrete, low-risk, low-effort fix available
(Acknowledgements; a short project-schedule/framing-pivot note). The length finding is
real but should not be acted on by cutting ~7,000+ words from a nearly-finalised,
evidence-dense report without first checking whether the current CCDS guidance
actually retains this specific 2002-era ceiling --- that is a decision with real
stakes (content loss) resting on a premise (guide currency) this audit cannot itself
confirm.
