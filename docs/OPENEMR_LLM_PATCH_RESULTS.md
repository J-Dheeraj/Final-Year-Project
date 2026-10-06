# OpenEMR LLM patch-generation: can a model write the real admin.php fix?

Extends `docs/OPENEMR_TRANSFER_RESULTS.md` (which confirmed the REAL
upstream fix only) with the same question already asked of free5GC:
can a model write an equivalent fix from scratch, given only the
vulnerable file and a plain-English description of the required
behavior - not the real diff. Per explicit instruction, this extends
that branch's work (which had stopped deliberately) rather than
replacing it.

## Method

8 local Ollama models (the same set used throughout every free5GC
sweep), each asked to write a small PHP snippet - not a full-file
rewrite - implementing: "deny with 403 unless
`OPENEMR_ADMIN_PHP_ENABLED` is `1` via `$_SERVER` or `getenv()`."
The snippet is inserted at the exact same position as the real fix
(immediately after admin.php's header doc-comment), lint-checked with
`php -l`, then runtime-confirmed twice against the real Docker
deployment (`run_harness.py`'s own db/php lifecycle, reused unchanged):
once with no env var (expect denial), once with
`OPENEMR_ADMIN_PHP_ENABLED=1` (expect the real page, including the
`Multi Site Administration` leak marker, to render normally).

## A model-availability note, same as free5GC's

The first run used the 4 smaller models (`llama3.2:1b/3b`,
`qwen3:8b`, `deepseek-r1:14b`) that were the only ones available
earlier in this session - all 4 failed with `model not found` (Ollama's
locally-pulled model set changed again between runs). Checked live via
`curl localhost:11434/api/tags` rather than assumed, found the original
8-model set available again, and re-ran against that set instead -
consistent with this project's practice of using whatever is actually
verified-present rather than trusting a stale assumption.

## A harness gap found and worked around (not silently glossed over)

The original pass/fail check (`status==403 AND leak marker absent` for
the default case) turned out to conflate two different outcomes. Spot-
checked by manually re-running several "failed" models with full raw
response capture (the automated run only stored booleans, not bodies -
a real gap in the first version of this script) before trusting the
reported numbers:

- **`gemma2:9b`, `qwen2.5-coder:3b`, `qwen2.5-coder:1.5b`**: all three
  wrote `$_SERVER['OPENEMR_ADMIN_PHP_ENABLED'] !== '1'` directly,
  without an `isset()` guard. On the default (no env var) request, this
  triggers a PHP "Undefined array key" warning whose output gets
  flushed to the client BEFORE `http_response_code(403)`/`header()` is
  called - by then, PHP's "headers already sent" rule makes the status
  code silently stay 200. **The disclosure is still genuinely blocked**
  (verified: the leak marker is absent, the body shows the correct
  "admin.php is disabled by default" text, same as the real fix) - this
  is a real code-quality defect (wrong status code, two PHP warnings
  leaked into the response body), not a security failure. The
  automated boolean check reported `false` for all three because it
  required the status code to be exactly 403; the actual security
  property (no disclosure) holds.
- **`mistral:7b`**: wrote `!in_array(...) || !in_array(...)` (OR of two
  negations) where the correct logic is AND of two negations -
  equivalent to requiring BOTH checks to pass rather than EITHER. Net
  effect: denies the admin page even with `OPENEMR_ADMIN_PHP_ENABLED=1`
  set, because PHP's built-in dev server doesn't mirror the Docker
  `-e` environment variable into `$_SERVER` the same way Apache's
  `SetEnv` would, so the `$_SERVER` half of the check never passes -
  this fix fails SAFE (blocks a legitimate admin) rather than failing
  OPEN, matching this project's own established `regression_broke_route`
  verdict category from the original OpenEMR result.
- **`llama3.1:8b`**: wrote the condition with **inverted logic** -
  `if (enabled) { deny }` instead of `if (!enabled) { deny }`. Verified
  directly: with no env var set, the response is a real `200` with the
  actual admin page HTML and the leak marker present - the vulnerability
  is **completely unfixed**, and the model's own code would give a false
  sense of security if ever deployed (it correctly blocks the opt-in
  case, so a developer glancing at the opt-in test alone might believe
  it works). This is the most dangerous outcome observed among the 8 models.
- **`codellama:13b`**: left a stray, unterminated duplicate draft line
  before its real answer (`$_SERVER[...] === '1' && getenv(...) === '1'`
  with no semicolon, then a blank line, then the real `if`) - a
  malformed-output bug, not a logic bug; `php -l` correctly rejected it
  before anything was deployed.
- **`deepseek-coder-v2:16b`**: out-of-memory during Ollama startup -
  the same recurring hardware constraint noted in every prior free5GC
  sweep on this machine, not a new finding.

## Results

| Model | Lints | Default denies disclosure (real behavior) | Opt-in works | Verdict |
|---|---|---|---|---|
| `deepseek-coder-v2:16b` | — | — | — | never ran (OOM) |
| `codellama:13b` | **no** | — | — | malformed output, caught before deploy |
| `gemma2:9b` | yes | **yes** (wrong status code: 200 not 403) | yes | functionally safe, buggy status code |
| `mistral:7b` | yes | yes (denies always) | **no** | fails safe, breaks legitimate use |
| `llama3.1:8b` | yes | **NO - inverted logic, vulnerability unfixed** | yes (misleadingly) | **failed: no protection at all** |
| `qwen2.5-coder:7b` | yes | yes, status 403 correctly | yes | **clean pass** |
| `qwen2.5-coder:3b` | yes | **yes** (wrong status code: 200 not 403) | yes | functionally safe, buggy status code |
| `qwen2.5-coder:1.5b` | yes | **yes** (wrong status code: 200 not 403) | yes | functionally safe, buggy status code |

Scored honestly rather than by the brittle automated boolean alone:
**1/7 completed models** (`qwen2.5-coder:7b`) produced a genuinely
clean fix; **3/7** produced a fix that actually blocks the real
disclosure but with a real, separate code-quality bug (wrong status
code due to a missing `isset()` guard); **1/7** fails safe but breaks
the legitimate opt-in path; **1/7** is a complete failure with
inverted logic that leaves the real vulnerability fully open while
appearing to work in a superficial opt-in-only test; **1/8** produced
invalid PHP, caught by lint before deployment.

## Honest interpretation

This is a meaningfully worse success rate than free5GC's historical
"7/8 compiled and were runtime-confirmed" for the equivalent patch-
generation task. The two bug classes here - a missing `isset()` guard
and an inverted boolean condition - are exactly the kind of small,
easy-to-miss logic errors a human reviewer would also need to actually
run the code (not just read the diff) to catch; `llama3.1:8b`'s
inverted-logic case in particular would likely pass a superficial
manual code review ("yes, it checks the env var and denies/allows
based on it") without actually testing both branches. This is a
concrete illustration of why this project's evidence-tier discipline
(compile/lint-verified < runtime-confirmed) matters even more for
PHP than for Go: PHP's weaker type system and silent-by-default
warnings let a logically broken check still "work" syntactically and
even partially functionally (as in the three `isset()`-missing cases),
making a lint pass alone a much weaker signal here than a `go build`
pass was for free5GC.

## Scope, stated plainly

- Single run per model, not repeated - a natural target for this
  project's own multi-run-variance idea, not yet applied to OpenEMR.
- Only Ollama (free) models; no Claude/paid-backend run attempted here.
- The automated classifier's limitation (conflating "blocked but wrong
  status code" with "not blocked") was found and worked around by
  manual investigation for this write-up, but not yet fixed in
  `llm_experiment.py` itself - a natural, named follow-up rather than a
  silently-accepted gap.

## Artifacts

- `openemr_transfer_case/llm_experiment.py --task patch`
- `reports/reachability/openemr_llm_patch.json/.md`
