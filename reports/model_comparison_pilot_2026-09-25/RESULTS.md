# Multi-model pilot: 6 Claude models x 2 CVEs (2026-09-25)

A pilot for the user's request to run the pipeline across six named Claude
model snapshots (haiku-4-5, sonnet-4-6, sonnet-5, opus-4-6, opus-4-7,
opus-4-8), collecting real per-CVE tokens/cost/runtime and judging
per-model success. Scoped to 2 CVEs first (CVE-2026-42208 - SQL
Injection, confirmed-easy in every prior round; CVE-2026-78683 -
Insecure Deserialization, previously hard) before committing to the
full 6-CVE catalog, given real, substantial per-call cost discovered
during setup (see below).

## Setup

- **Backend**: `claude -p --model <name> --output-format json`, via new
  `CLAUDE_MODEL` / `CLAUDE_TIMEOUT_S` env vars added to `cve_pipeline.py`
  this session specifically to support this comparison.
- **Protocol**: one shot per CVE per model, isolated (empty) lessons
  file reset before every one of the 12 runs (never shared, even across
  models), sandboxed Stage 1-3 cache reused from the existing catalog
  cache (advisory/analysis/probe are model-independent).
- All 6 model names were confirmed as accepted by the CLI (not rejected
  as `unrecognized_model`) in a separate validity check before this run.

## Three real problems found and fixed during this run (not before)

1. **`--output-format text` (the pipeline's original mode) exposes no
   cost or token data at all.** Switched to `--output-format json`,
   which does: `total_cost_usd` and a real `usage.input_tokens`/
   `output_tokens` breakdown, straight from the CLI itself.
2. **Silent Ollama fallback recurred mid-sweep**, a second time this
   session (first was the expired OAuth session documented in
   `docs/SESSION_2026-09-25_MULTI_AGENT_COMPARISON.md`) - this time
   triggered by a real account usage-limit hit partway through the
   initial 12-run sweep. 9 of the first 12 cells silently substituted
   Ollama under the requested model's own directory name, caught only
   by auditing `generation_backend` per report after the fact. **Fixed
   properly this time**, not just documented: `_call_live_model()` now
   refuses to fall back to Ollama whenever `CLAUDE_MODEL` is explicitly
   set, surfacing a visible `WARNING` instead. All 9 affected cells were
   re-run after the fix, verified individually for `generation_backend
   == "claude"` before moving to the next.
3. **A third, distinct issue** (not a code bug, a real model
   characteristic): `claude-opus-4-7` and `claude-opus-4-8` genuinely
   exceed this pipeline's original hardcoded 180s per-call timeout on
   realistic exploit-generation-scale prompts - confirmed directly (a
   representative ~7KB prompt took 234s on opus-4-8, not stuck, just
   slower). Added `CLAUDE_TIMEOUT_S` (default unchanged at 180s
   everywhere else) and re-ran the affected cells at 300s. All 12 cells
   now carry real, model-attributed generation and patch data.

## Full results

| Model | CVE | Confirmed | Refine | `patch_verdict` | Gen output tokens | Patch output tokens | Real cost | Time (s) |
|---|---|---|---|---|---|---|---|---|
| claude-haiku-4-5 | CVE-2026-42208 | True | 0 | `confirmed_fix` | 7,468 | 3,286 | $0.2569 | 112.3 |
| claude-haiku-4-5 | CVE-2026-78683 | True | 2 | `confirmed_fix` | 11,712 | 1,673 | $0.5506 | 323.0 |
| claude-sonnet-4-6 | CVE-2026-42208 | True | 0 | `confirmed_fix` | 6,751 | 1,623 | $0.7346 | 130.3 |
| claude-sonnet-4-6 | CVE-2026-78683 | True | 0 | `not_blocked` | 11,258 | 1,478 | $0.7988 | 173.5 |
| claude-sonnet-5 | CVE-2026-42208 | True | 0 | `confirmed_fix` | 7,429 | 1,637 | $0.6767 | 104.0 |
| claude-sonnet-5 | CVE-2026-78683 | True | 0 | `not_blocked` | 9,094 | 1,013 | $0.8733 | 123.8 |
| claude-opus-4-6 | CVE-2026-42208 | True | 0 | `inconclusive_crash` | 7,947 | 1,027 | $1.2379 | 187.7 |
| claude-opus-4-6 | CVE-2026-78683 | True | 0 | `confirmed_fix` | 13,864 | 820 | $1.3941 | 285.4 |
| claude-opus-4-7 | CVE-2026-42208 | True | 0 | `confirmed_fix` | n/a* | 789 | $1.1157 | 37.9 |
| claude-opus-4-7 | CVE-2026-78683 | True | 0 | `confirmed_fix` | 8,268 | 1,082 | $1.7073 | 150.1 |
| claude-opus-4-8 | CVE-2026-42208 | True | 0 | `confirmed_fix` | 6,666 | 4,024 | $1.7352 | 170.2 |
| claude-opus-4-8 | CVE-2026-78683 | True | 0 | `confirmed_fix` | 14,333 | 2,348 | $2.1295 | 249.2 |

\* Stage 3.5's cache-hit path skipped a fresh generation call for
CVE-2026-42208 on `claude-opus-4-7`'s successful attempt, so
`generation_output_tokens` wasn't recorded on that particular call;
`patch_gen_output_tokens` (a separate, always-fresh call) is real.

## Per-model summary

| Model | Confirmed | `confirmed_fix` | Total real cost (2 CVEs) | Total time (s) |
|---|---|---|---|---|
| claude-haiku-4-5 | 2/2 | 2/2 | **$0.8075** | 435.3 |
| claude-sonnet-4-6 | 2/2 | 1/2 | $1.5334 | 303.8 |
| claude-sonnet-5 | 2/2 | 1/2 | $1.5500 | 227.8 |
| claude-opus-4-6 | 2/2 | 1/2 | $2.6320 | 473.2 |
| claude-opus-4-7 | 2/2 | 2/2 | $2.8230 | **188.0** |
| claude-opus-4-8 | 2/2 | 2/2 | $3.8647 | 419.4 |

## Reading this honestly

- **Every model dynamically confirmed both exploits (12/12)** - at this
  sample size (2 CVEs), exploit *generation* is not the differentiator;
  patch *quality* is.
- **`confirmed_fix` rate**: haiku-4-5, opus-4-7, and opus-4-8 each
  produced a genuinely working patch (blocked the exploit AND preserved
  normal use) for both CVEs. sonnet-4-6, sonnet-5, and opus-4-6 each
  got only 1 of 2 - and note opus-4-6's one miss was
  `inconclusive_crash` (the patch broke the route entirely), not merely
  `not_blocked` - a worse failure mode than sonnet-4-6/sonnet-5's clean
  `not_blocked` misses.
- **Cheapest reliable result**: `claude-haiku-4-5` at $0.81 for 2/2
  `confirmed_fix` - the best cost-to-success ratio in this pilot by a
  wide margin, cheaper than every other model AND with a perfect patch
  record.
- **Cost scales roughly with model tier**, as expected: haiku ≈$0.40/CVE,
  sonnet ≈$0.65-0.90/CVE, opus ≈$0.85-2.1/CVE - but tier does **not**
  predict patch quality here: opus-4-6 (mid-tier cost) had the *worst*
  outcome of the six (one `inconclusive_crash`), while the cheapest
  model (haiku) tied for the *best* outcome.
- **opus-4-7 and opus-4-8 needed a longer timeout to participate at
  all** - under the pipeline's original fixed 180s budget, both would
  have shown as 0/2 (pure template fallback) purely from being slower,
  not from being worse at the task. This is now a documented,
  intentional deviation from the frozen `CLAUDE_TIMEOUT_S`-unset default
  used everywhere else, disclosed here rather than silently normalized
  into "the protocol."
- **This is 2 CVEs, one shot each, no fixed seed** (the Claude CLI
  exposes no temperature/seed control) - not a statistically powered
  comparison. It answers "can each model complete this pipeline's
  full stage chain and what does it cost when it does," not "which
  model is definitively best at this task class."

## What this does and does not establish

- **Does**: give real, first-of-its-kind per-model cost/token/timing/
  outcome data across 6 named Claude snapshots on this pipeline's actual
  stage chain (not a synthetic benchmark) - the exact ask in the user's
  request, at pilot scale.
- **Does not**: extrapolate reliably to the full 6-CVE catalog or to
  other vulnerability classes (SSRF, XSS, OS Command Injection, Path
  Traversal are untested here) - this pilot deliberately covers 2 of 6
  classes to bound cost before a larger commitment.
- **Not yet done**: the remaining 4 CVEs (CVE-2026-27602, CVE-2026-23949,
  CVE-2026-54729, CVE-2026-46492) x 6 models, pending a decision on
  whether to extend given real cost already observed (~$1.29 average per
  model-CVE cell across this pilot; a full 6x6 matrix at this rate would
  be roughly **$45-50** in real, additional API spend).

Raw reports: `reports/model_comparison_pilot_2026-09-25/<model>/<CVE-ID>.json`.

---

## Extension to the full 6x6 matrix (all 6 catalogue CVEs)

Extended to all 6 catalogue CVEs (CVE-2026-42208, CVE-2026-27602,
CVE-2026-23949, CVE-2026-78683, CVE-2026-54729, CVE-2026-46492) x the
same 6 models, per the user's explicit "continue 6 x 6 matrix"
instruction, same isolated-lessons-per-run protocol as the pilot above.

### A fourth real bug found and fixed during this extension

`claude-opus-4-7` and `claude-opus-4-8` failed 100% of their first pass
through the 4 new CVEs (all 4/4 each fell back to templates), this time
failing **fast** (21-23s), not via the earlier timeout signature.
Root-caused live: without `--tools ""`/`--permission-prompts none`,
these two models sometimes attempted to use their own Write tool on a
generation prompt instead of just returning text, hit an unanswerable
permission prompt in this non-interactive `claude -p` context, and
either stalled for minutes before an inline-text fallback or failed
fast with no output at all. A separate reproduction also showed a call
referencing an unrelated "prior session summary" - a real
session-persistence leak between what should be one-shot, stateless
calls. Fixed by adding `--tools ""`, `--permission-prompts none`, and
`--no-session-persistence` to every Claude CLI invocation in
`cve_pipeline.py`. Verified: the same realistic-scale prompt that
previously took 258s (with a mid-response permission stall) now
completes in 113s with clean text and real cost, unchanged model.

### Retry history (for the record, not hidden)

The first full-matrix pass left 12/36 cells on templates (the tool/
session bug above). A retry with the fix got 10 of those 12 real, but
hit a **second, unrelated** real-account usage-limit exhaustion mid-run
(the same kind of event that hit the very first pilot sweep too,
independent of any code bug) - 11 cells failed fast during that window.
Once the user's usage limit reset, a further retry got 10 of those 11
real; the last cell (`claude-opus-4-7`/CVE-2026-42208) needed one more
individual retry. Separately, `claude-sonnet-4-6`/CVE-2026-27602's
*exploit* generation succeeded on the first pass but its *patch*
generation call failed silently (`patch_attempted: False`, no verdict)
- caught only by checking `patch_verdict` wasn't just "not applicable"
but genuinely missing; one more individual retry produced a real
patch attempt. All 36 cells now carry real, model-attributed data for
both stages.

### Full 6x6 matrix - final complete results

| Model | CVE | Class | Confirmed | Verdict | Gen out tok | Patch out tok | Cost | Time (s) |
|---|---|---|---|---|---|---|---|---|
| claude-haiku-4-5 | CVE-2026-42208 | SQL Injection | True | `confirmed_fix` | 7468 | 3286 | $0.2569 | 112.3 |
| claude-haiku-4-5 | CVE-2026-27602 | OS Command Injection | True | `confirmed_fix` | 8825 | 1465 | $0.2647 | 119.02 |
| claude-haiku-4-5 | CVE-2026-23949 | Path Traversal | True | `confirmed_fix` | 5684 | 2106 | $0.2429 | 90.57 |
| claude-haiku-4-5 | CVE-2026-78683 | Insecure Deserialization | True | `confirmed_fix` | 11712 | 1673 | $0.5506 | 322.99 |
| claude-haiku-4-5 | CVE-2026-54729 | SSRF | True | `confirmed_fix` | 8299 | 2365 | $0.2563 | 120.41 |
| claude-haiku-4-5 | CVE-2026-46492 | XSS | True | `not_blocked` | 5780 | 1049 | $0.2369 | 84.31 |
| claude-sonnet-4-6 | CVE-2026-42208 | SQL Injection | True | `confirmed_fix` | 6751 | 1623 | $0.7346 | 130.29 |
| claude-sonnet-4-6 | CVE-2026-27602 | OS Command Injection | True | `confirmed_fix` | 3184 | 1305 | $0.3435 | 80.27 |
| claude-sonnet-4-6 | CVE-2026-23949 | Path Traversal | True | `confirmed_fix` | 7510 | 1058 | $0.7377 | 130.75 |
| claude-sonnet-4-6 | CVE-2026-78683 | Insecure Deserialization | True | `not_blocked` | 11258 | 1478 | $0.7988 | 173.49 |
| claude-sonnet-4-6 | CVE-2026-54729 | SSRF | True | `confirmed_fix` | 9529 | 1627 | $1.1397 | 257.75 |
| claude-sonnet-4-6 | CVE-2026-46492 | XSS | True | `not_blocked` | 7642 | 1427 | $0.7441 | 140.96 |
| claude-sonnet-5 | CVE-2026-42208 | SQL Injection | True | `confirmed_fix` | 7429 | 1637 | $0.6767 | 104.02 |
| claude-sonnet-5 | CVE-2026-27602 | OS Command Injection | True | `confirmed_fix` | 7123 | 1613 | $0.6935 | 99.81 |
| claude-sonnet-5 | CVE-2026-23949 | Path Traversal | True | `confirmed_fix` | 5798 | 1288 | $0.6505 | 88.62 |
| claude-sonnet-5 | CVE-2026-78683 | Insecure Deserialization | True | `not_blocked` | 9094 | 1013 | $0.8733 | 123.81 |
| claude-sonnet-5 | CVE-2026-54729 | SSRF | True | `confirmed_fix` | 6855 | 4647 | $0.7006 | 133.97 |
| claude-sonnet-5 | CVE-2026-46492 | XSS | True | `not_blocked` | 6420 | 1840 | $0.6697 | 104.47 |
| claude-opus-4-6 | CVE-2026-42208 | SQL Injection | True | `inconclusive_crash` | 7947 | 1027 | $1.2379 | 187.74 |
| claude-opus-4-6 | CVE-2026-27602 | OS Command Injection | True | `confirmed_fix` | 7395 | 761 | $1.4661 | 185.19 |
| claude-opus-4-6 | CVE-2026-23949 | Path Traversal | True | `confirmed_fix` | 12998 | 1005 | $1.3595 | 259.75 |
| claude-opus-4-6 | CVE-2026-78683 | Insecure Deserialization | True | `confirmed_fix` | 13864 | 820 | $1.3941 | 285.41 |
| claude-opus-4-6 | CVE-2026-54729 | SSRF | True | `confirmed_fix` | 9082 | 1330 | $1.2757 | 189.37 |
| claude-opus-4-6 | CVE-2026-46492 | XSS | True | `not_blocked` | 10111 | 1600 | $1.307 | 237.12 |
| claude-opus-4-7 | CVE-2026-42208 | SQL Injection | True | `confirmed_fix` | 3974 | 1047 | $0.7708 | 85.59 |
| claude-opus-4-7 | CVE-2026-27602 | OS Command Injection | True | `confirmed_fix` | 1140 | 1121 | $0.6973 | 70.53 |
| claude-opus-4-7 | CVE-2026-23949 | Path Traversal | True | `confirmed_fix` | 3983 | 1912 | $0.7925 | 106.8 |
| claude-opus-4-7 | CVE-2026-78683 | Insecure Deserialization | True | `confirmed_fix` | 8268 | 1082 | $1.7073 | 150.1 |
| claude-opus-4-7 | CVE-2026-54729 | SSRF | True | `confirmed_fix` | 1862 | 1720 | $0.7333 | 83.74 |
| claude-opus-4-7 | CVE-2026-46492 | XSS | True | `not_blocked` | 6084 | 1129 | $0.8236 | 128.19 |
| claude-opus-4-8 | CVE-2026-42208 | SQL Injection | True | `confirmed_fix` | 6666 | 4024 | $1.7352 | 170.19 |
| claude-opus-4-8 | CVE-2026-27602 | OS Command Injection | True | `confirmed_fix` | 12396 | 3601 | $2.0463 | 247.24 |
| claude-opus-4-8 | CVE-2026-23949 | Path Traversal | True | `confirmed_fix` | 5213 | 1596 | $0.81 | 189.32 |
| claude-opus-4-8 | CVE-2026-78683 | Insecure Deserialization | True | `confirmed_fix` | 14333 | 2348 | $2.1295 | 249.2 |
| claude-opus-4-8 | CVE-2026-54729 | SSRF | True | `confirmed_fix` | 8816 | 3296 | $0.9456 | 256.84 |
| claude-opus-4-8 | CVE-2026-46492 | XSS | True | `not_blocked` | 14789 | 1748 | $1.3767 | 258.49 |

### Per-model summary (all 6 CVEs)

| Model | Confirmed | `confirmed_fix` | `not_blocked` | `inconclusive_crash` | Total cost | Total time |
|---|---|---|---|---|---|---|
| claude-haiku-4-5 | 6/6 | **5** | 1 | 0 | **$1.81** | 850s |
| claude-sonnet-4-6 | 6/6 | 4 | 2 | 0 | $4.50 | 914s |
| claude-sonnet-5 | 6/6 | 4 | 2 | 0 | $4.26 | 655s |
| claude-opus-4-6 | 6/6 | 4 | 1 | 1 | $8.04 | 1345s |
| claude-opus-4-7 | 6/6 | **5** | 1 | 0 | $5.52 | **625s** |
| claude-opus-4-8 | 6/6 | **5** | 1 | 0 | $9.04 | 1371s |

**Grand total real spend across the full 6x6 matrix: $33.18.**

## Final reading, across all 6 vulnerability classes

- **Every model confirmed all 6 exploits (36/36).** Exploit generation
  is not a differentiator at this model tier for any of the 6 catalogue
  vulnerability classes - patch quality is the entire story.
- **Best `confirmed_fix` rate**: haiku-4-5, opus-4-7, and opus-4-8 tie at
  5/6. Sonnet-4-6, sonnet-5, and opus-4-6 all sit at 4/6.
- **Best cost-to-success ratio by a wide margin: `claude-haiku-4-5`** -
  $1.81 total for 5/6 confirmed_fix, roughly a third of every other
  model's cost for an equal-or-better result. No other model comes
  close on this axis.
- **Best cost-to-success among Opus tier: `claude-opus-4-7`** - matches
  haiku's and opus-4-8's 5/6 rate at $5.52 (vs. opus-4-8's $9.04 for the
  same 5/6), and by far the fastest Opus-tier model (625s vs. 1345s for
  opus-4-6 and 1371s for opus-4-8 across the same 6 CVEs).
- **`claude-opus-4-6` has the single worst outcome in the entire
  matrix**: its one miss (CVE-2026-42208, SQL Injection) is
  `inconclusive_crash` - a patch that broke the route entirely - the
  only crash-class failure across all 36 cells, despite opus-4-6 not
  being the cheapest or fastest model either.
- **XSS (CVE-2026-46492) is the one class every single model failed to
  patch** - all 6 models returned `not_blocked` for this CVE and no
  other. This is a real, consistent, cross-model finding: whatever this
  vulnerability class's patch challenge is, it isn't specific to one
  model's weakness.
- **Cost scales with tier as expected but does not track quality**:
  opus-4-6 (a mid-tier-cost model) had the worst single result in the
  whole matrix, while the cheapest model (haiku) tied for the best.
- **This is one shot per CVE per model, no fixed seed** (the Claude CLI
  exposes no temperature/seed control) - the standing single-shot
  caveat that applies to every live-LLM round in this project.

## Four real bugs found and fixed while producing this data (full list)

1. `--output-format text` exposed no cost/token data - switched to
   `--output-format json`.
2. Silent Ollama fallback recurred under `CLAUDE_MODEL` (a real account
   rate-limit, not the earlier OAuth expiry) - fixed at the source:
   `_call_live_model()` now refuses to substitute Ollama when a specific
   model is explicitly requested, surfacing a visible warning instead.
3. `claude-opus-4-7`/`claude-opus-4-8` genuinely exceeded the pipeline's
   original 180s timeout on realistic generation prompts - added an
   opt-in `CLAUDE_TIMEOUT_S` override.
4. `claude-opus-4-7`/`claude-opus-4-8` (and occasionally other models)
   sometimes attempted agentic tool use (Write) instead of returning
   plain text, stalling or failing in this pipeline's non-interactive
   context; a separate reproduction also showed cross-call session-state
   bleed. Fixed with `--tools ""`, `--permission-prompts none`, and
   `--no-session-persistence` on every Claude CLI call.

None of these were speculative fixes - each was root-caused with a live,
reproducible test before being patched, and each fix is committed to
`fyp` with its own commit explaining the finding.
