# Considered directions (not adopted)

Honest record of proposals evaluated and deliberately not pursued, so the
reasoning isn't lost and isn't repeated. Each entry: what was proposed,
why it wasn't adopted, and the condition under which it's worth
revisiting. This is the same evidence-over-assumption standard the rest
of this project holds to, applied to direction decisions themselves.

## 2026-09-14: GLM's "detect -> demonstrate -> repair" pure-LLM redesign

**Proposed** (via an external conversation with GLM, relayed into this
project): replace CVE-driven exploit confirmation with a pipeline where
an LLM (1) reads raw C source with no prior knowledge and hypothesizes
vulnerabilities, (2) synthesizes a byte-level triggering input purely by
reasoning (not search/mutation) and replays it once against an
ASan-instrumented build to convert the claim into evidence, (3) patches
it, (4) validates the patch. A new `aegis/detect.py` + `aegis/verify.py`
+ C driver harness were proposed to implement this, replacing this
project's existing pipeline architecture.

**What's actually correct in it**: the fuzzing-vs-single-replay
distinction is valid, and this project already implements that pattern —
`execute_exploit_artifacts()` (Stage 3.6) is exactly "one crafted input,
replayed once, confirmed by a real exit code, no search" — just for
HTTP-level exploits, not ASan crashes.

**Why not adopted:**

1. **The core assumption is unverified and was asked to be committed to
   before testing it.** The proposal's own validation plan was "run one
   smoke test against one toy C file with a local 7B model; if it works,
   the whole redesign is real." Restructuring four thesis chapters and a
   benchmark protocol around a single untested example is backwards —
   validate first, commit second.
2. **Internal inconsistency in the proposal's own risk assessment.** Its
   scope table labels the "Floor" (minimum viable) scope as "Low risk,"
   but Floor still requires the `detect()` stage — the same zero-shot
   detection capability the proposal's own cited literature (Steenhoek
   ICSE'24, Chakraborty TSE'22, the Copilot study) says has "serious
   precision problems." A caveat conceded in one paragraph and then
   priced as low-risk two paragraphs later doesn't hold up.
3. **A logical gap in the "your repo proves this is possible" claim.**
   This project's existing PoC generation (Stage 3.5) is always guided
   by the advisory's own root-cause description — the model is told what
   the bug is before writing anything. Blind zero-shot detection *and*
   byte-precise exploit synthesis with no prior knowledge is a
   different, harder problem; this project's results don't transfer as
   evidence that it works.
4. **It's a second, disconnected system**, not a delta on what exists —
   new modules, a new C harness, none of it wired to `cve_pipeline.py`
   or `src/reachability/`, which already do real dynamic confirmation
   and real patch validation.
5. **Real cost, no urgency.** Ollama is not installed in this
   environment; standing it up plus pulling a 7B+ model is a nontrivial
   setup cost for a speculative side-branch while the existing,
   verified project is in a strong, documented state
   (`docs/PROJECT_STATUS.md`).

**Condition to revisit**: if there is real schedule slack after the
report itself is in solid shape, run the bounded smoke test first — one
local model, one already-known bug from this project's own catalog (not
a freshly invented toy file, so the result means something either way),
report the outcome honestly whether it succeeds or fails — *before*
touching any thesis chapter, benchmark protocol, or sending anything to
the professor as a locked-in direction.
