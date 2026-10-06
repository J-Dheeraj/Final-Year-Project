# Project Status

## Session log

- **2026-10-06 (free5GC multi-turn bypass-probe, on `main`) - 0/7
  genuine bypasses across 3 rounds each; verified two already-fixed
  false-positive patterns before trusting the clean result** —
  Continuing "do everything, do it in the right order", item 7
  (multi-turn adversarial probing - "let a model see the rejection and
  retry 2-3 rounds"). Built `run_multiturn_bypass_probe.py`, reusing
  `run_bypass_probe_sweep.py`'s prompt/classifier/seed logic unchanged;
  since the provider interface is single-turn only, folded each
  round's real proposal + real response/signal into the next round's
  prompt text rather than using a chat-history API. Ran all 8 Ollama
  models, up to 3 rounds each, against the real `free5gc-udr-custom:patched`
  build. Two of the 24 proposed requests landed on exactly the two
  false-positive shapes this project already fixed earlier this session
  (a re-encoded-but-identical path, and an inert query string on the
  canonical path) - verified both were correctly excluded by the
  already-fixed classifier (reused unmodified) before trusting the
  aggregate 0/7. Result: 0/7 completed models found a genuine bypass
  within 3 rounds; `deepseek-coder-v2:16b` OOM'd as usual. Seeing a
  rejection did change what most models tried next (new encoding/
  traversal/Unicode tricks each round, not repeats), but never toward
  anything that worked - strengthens rather than merely repeats the
  single-shot bypass-probe conclusion. Documented in
  `docs/FREE5GC_MULTITURN_BYPASS_PROBE_RESULTS.md`. Remaining "do
  everything" items (patch-quality scoring, methodology-pitfalls
  writeup) still queued.

- **2026-10-06 (main 6-CVE catalogue bypass-probe, on `main`) - 0/48
  genuine bypasses across every catalogue CVE; one apparent bypass
  traced to a test-oracle bug, not an app bug, before being reported**
  — Continuing "do everything, do it in the right order", item 6
  (main-catalogue bypass-probe - "never tried there" per the
  brainstormed list). Extended the already-run free5GC/OpenEMR
  bypass-probe idea to the main pipeline's own 6-CVE catalogue
  (`reports/CVE_CATALOG.md`), feeding each CVE's already-validated
  patched Flask target's COMPLETE real source (not an abstract
  description, unlike the free5GC/OpenEMR probes) to 8 Ollama models
  and executing every proposal for real. Reused each CVE's own
  already-established `poc.py` `verify()` oracle (`MARKER in
  response.text`) rather than inventing a new one. Raw run reported
  1/48 as a confirmed bypass (`gemma2:9b` vs. the XSS CVE, an
  `onerror=` payload) - checked the actual response body before
  trusting it and found the content WAS correctly HTML-escaped
  (`&lt;img ... onerror=...&gt;`, inert, not live executable HTML).
  The MARKER still appeared because of a real, pre-existing bug in
  that target app's OWN self-check regex (`\son\w+\s*=` matches the
  literal substring ` onerror=` even inside escaped, inert text -
  escaping only neutralizes `<`/`>`, not attribute-name text).
  Confirmed this is a genuinely NEW finding, not a retroactive
  invalidation: the original `poc.py`'s own payload
  (`<script>...</script>`) only exercises a DIFFERENT regex
  alternative that escaping does correctly defeat, so the original
  published "confirmed" result for this CVE is unaffected - this probe
  found an edge the original single-payload validation never
  exercised. Reclassified from already-captured data, no new model
  call. Final, corrected result: 0/48 genuine bypasses across all 6
  CVEs (SQLi, CMDi, deserialization, XSS, path traversal, SSRF) - a
  third independent confirmation, after free5GC and OpenEMR, that this
  project's real/validated fixes hold against LLM-proposed request-level
  tricks. `deepseek-coder-v2:16b` OOM'd identically on every CVE (same
  recurring hardware constraint). Documented in
  `docs/CATALOG_BYPASS_PROBE_RESULTS.md`. Remaining "do everything"
  items (multi-turn adversarial probing, patch-quality scoring,
  methodology-pitfalls writeup) still queued.

- **2026-10-06 (OpenEMR extended with LLM patch-gen + bypass-probe, on
  `main`) - 1/7 models produced a clean fix, several genuinely varied
  and interesting failure modes found by not trusting a binary
  pass/fail; bypass-probe held 0/7** — Per explicit instruction
  ("do everything, do it in the right order"), extended the OpenEMR
  transfer case (GHSA-q366-cv5v-83w8) with the same two experiments
  already run against free5GC. User explicitly confirmed overriding
  the branch's own prior "implement one target and stop" scope note
  before this began. First discovered the "not merged to main" note in
  `docs/OPENEMR_TRANSFER_RESULTS.md` was itself stale (commit `6cf91f5`
  is already on `main` via `git branch --contains`) - fixed alongside
  the extension.
  **Patch-generation** (8 Ollama models, same set as every free5GC
  sweep - the smaller 4-model substitute set from earlier in this
  session had vanished from Ollama again, then the original 8 came
  back; checked live rather than assumed): only `qwen2.5-coder:7b`
  produced a genuinely clean fix. The automated boolean check initially
  reported most others as outright failures, but manual investigation
  with full raw-response capture (the first version of the harness
  only stored pass/fail booleans, not bodies - a real gap, worked
  around by hand for this write-up) found real nuance: 3 models
  (`gemma2:9b`, `qwen2.5-coder:3b/1.5b`) wrote `$_SERVER[...] !== '1'`
  without `isset()`, which genuinely still blocks the disclosure but
  triggers a PHP warning that silently prevents the 403 status code
  from applying ("headers already sent") - a real code-quality bug,
  not a security failure; `mistral:7b` used the wrong boolean operator
  (OR instead of AND of negations), failing SAFE but breaking the
  legitimate opt-in path; `llama3.1:8b` wrote **completely inverted
  logic** - verified directly that its "fix" leaves the real
  vulnerability fully open by default while appearing to work in a
  superficial opt-in-only test, the most dangerous single result found
  this session; `codellama:13b` produced unparseable PHP (caught by
  lint); `deepseek-coder-v2:16b` OOM'd (same recurring hardware
  constraint as every free5GC sweep). Documented in
  `docs/OPENEMR_LLM_PATCH_RESULTS.md`.
  **Bypass-probe** (same 8 models, real upstream fix active): every
  proposal read and verified individually before trusting the 0/7
  aggregate (unlike free5GC's bypass-probe, no classifier bug was
  needed here - the oracle is unambiguous and every proposal was a
  genuinely distinct attempt: a cookie, POST form data, and four header-
  naming variations, all correctly guessing the right variable NAME but
  wrongly assuming an HTTP header can set a bare `$_SERVER` key rather
  than the `HTTP_`-prefixed one PHP actually uses). 0 genuine bypasses;
  one model (`mistral:7b`) hit a connection timeout, reported as
  inconclusive rather than folded into either outcome. Documented in
  `docs/OPENEMR_BYPASS_PROBE_RESULTS.md`. Remaining "do everything"
  items (main-catalogue bypass-probe, multi-turn adversarial probing,
  patch-quality scoring, methodology-pitfalls writeup) still queued.

- **2026-10-06 (free5GC real OAuth2 enforcement, on `main`) - OAuth2
  blocks unauthenticated callers but provides zero additional
  protection against CVE-2026-40248 once any validly-scoped token is
  held; two real complications traced and resolved before trusting the
  result** — Continuing "do everything, do it in the right order", item
  4 (OAuth2 enforcement). Every prior free5GC result in this project
  runs with OAuth2 explicitly disabled on the NRF
  (`run_full_deployment_harness.py`'s own docstring calls this "out of
  scope"). Added an opt-in compose override
  (`compose/docker-compose.oauth2.yaml` + `compose/config/nrfcfg_oauth2.yaml`,
  activated only via an explicit third `-f` file so the default stack
  every other script relies on is untouched) that turns `oauth: true`
  on, confirmed genuinely active via the UDR's own startup log line
  ("OAuth2 setting receive from NRF: true") rather than assumed. Minted
  an RS512 JWT directly with the NRF's own already-committed private
  key (`compose/cert/nrf.key`) - not "forging" a token, constructing
  one server-side with the same key the real NRF would use - and tested
  both the vulnerable and real-fix-patched UDR image under (a) no
  credentials at all and (b) a valid, correctly-scoped token. Found and
  resolved two real complications before trusting anything: (1) a first
  attempt with a made-up `sub` claim got rejected on every PUT with
  `401 REQUESTER_IDENTITY_UNRESOLVED` - traced into the real vendored
  source to a SECOND, independent authorization layer
  (`subscriptionCallbackTargetFromContext` doing a live `GetNFInstance`
  lookup against the NRF, only when OAuth2Required is true) that
  `VerifyOAuth()`'s basic scope check never exercises; fixed by using a
  real, currently-registered NF instance ID (queried live from NRF's
  own `NfProfile` collection) as `sub` instead. (2) a leaked-collection
  response body that looked suspiciously concatenated
  (`{"status":400,...}[{"dnns":...}]` with no separator) was verified
  via `repr()` and the response's own `Content-Length` header before
  being trusted - confirmed as a real, single response reproducing the
  same already-established leak heuristic, not a new artifact. Result:
  401 for both builds with no credentials (OAuth2 genuinely gates
  everything); with a valid token, the vulnerable build's collection
  and single-record leaks reproduce exactly as in every OAuth2-disabled
  result while the patched build's fix still holds, and the legitimate
  caller's benign path is preserved in both. Conclusion: OAuth2 and the
  CWE-285 fix are independent, complementary layers, not substitutes -
  OAuth2 blocks anonymous callers but provides no protection against a
  credentialed attacker (e.g. a compromised NF) once the CWE-285 bug is
  present. Documented in `docs/FREE5GC_OAUTH2_ENFORCEMENT_RESULTS.md`.
  Stack restored to its default OAuth2-disabled state afterward
  (confirmed via the same log line) so every other script/doc in this
  project keeps working as documented. Remaining "do everything" items
  (OpenEMR extension, main-catalogue bypass-probe, multi-turn
  adversarial probing, patch-quality scoring, methodology-pitfalls
  writeup) still queued.

- **2026-10-06 (free5GC multi-run variance via the new sweep.py, on
  `main`) - two more real bugs found and fixed, including a second
  variant of an already-fixed classifier false-positive** — Continuing
  "do everything, do it in the right order", exercised the new
  `sweep.py --runs N` flag (`--task bypass --backend ollama --models
  llama3.2:1b,llama3.2:3b --runs 3`) to test whether the bypass-probe's
  "fix holds" result is stable across repeated runs, not a single-shot
  fluke (a stated weakness in `docs/DEFENSE_PREP.md` for the main
  pipeline, never checked for free5GC). First attempt crashed outright:
  `llama3.2:1b` returned `"headers"` as a string instead of a JSON
  object on its 3rd attempt, and `proposal.get("headers") or {}` didn't
  catch it (non-empty string is truthy), so it reached
  `requests.get(headers=...)` and threw deep inside `requests` itself,
  killing the whole sweep. Fixed with an `isinstance(headers, dict)`
  check in `run_bypass_probe_sweep.py`. Second attempt completed but
  initially reported `llama3.2:3b` confirming a bypass on 2 of 3 runs -
  which would have been the first confirmed bypass in this project's
  history. Checked the raw request/response before believing it: both
  were the model asking for the exact correct, fully-authorized
  canonical path with a harmless, server-ignored `?influenceId=...`
  query string appended - the server correctly served the normal
  legitimate response. `_is_genuine_trick()` already guards against a
  re-encoded-but-identical path (the false-positive class caught in the
  original bypass-probe sweep) but never stripped the query string
  before comparing, so the inert suffix alone made it register as a
  "genuine trick." Fixed by comparing only the URL's path component;
  re-classified the 2 affected entries from already-captured raw HTTP
  data, no new model calls. Corrected result: 0/3 for both models, no
  run-to-run flip - the fix holding is not a one-run fluke, at least for
  this small sample. Documented in
  `docs/FREE5GC_MULTI_RUN_VARIANCE_RESULTS.md`. Both fixes live in the
  shared `run_bypass_probe_sweep.py`, so every caller (the original
  script, the Claude variant, and the new unified tool) benefits.
  Remaining "do everything" items (OAuth2 enforcement, OpenEMR
  extension, main-catalogue bypass-probe, multi-turn adversarial
  probing, patch-quality scoring, methodology-pitfalls writeup) still
  queued.

- **2026-10-06 (sweep-script unification + free5GC memorization control,
  on `main`) - new unified CLI tool; a genuine, controlled memorization
  test with mixed results and one real harness bug caught and fixed** —
  Per explicit instruction ("do everything, do it in the right order")
  against a previously-brainstormed enhancement list, started with the
  two lowest-risk/highest-value items. (1) Consolidated the 5
  near-duplicate free5GC sweep scripts (`run_model_sweep.py`,
  `run_claude_model_sweep.py`, `run_claude_sweep_extended.py`,
  `run_bypass_probe_sweep.py`, `run_claude_bypass_probe_sweep.py`, 869
  lines total) into one parameterized CLI
  (`free5gc_full_deployment/sweep.py`, `--task {patch,bypass} --backend
  {ollama,claude} [--models] [--runs N]`), reusing their existing
  functions rather than redefining them; the 5 originals are left
  unmodified since existing docs/reports cite their exact invocations.
  (2) Built a memorization control: injected a synthetic, never-
  publicly-disclosed CWE-285 bug (deleted a real, correctly-present
  `return`) into `HandleCreateAuthenticationStatus` - a real free5GC UDR
  handler in the same source file as the CVE-2026-40248 handlers, but
  not one of them, and never actually buggy - then asked models to fix
  it and compile-verified against a live clone of the real upstream
  module, same methodology as `run_free5gc_llm_patch.py`. Found and
  fixed a real bug in the control itself before trusting any result: the
  synthetic case file was written with Windows' default `\r\n`
  translation, so the pipeline's tree-sitter-parsed function body no
  longer byte-matched the `\n`-only strings used to splice into the real
  clone, producing false "patch doesn't match" failures for every model;
  fixed with an explicit `newline="\n"` write, re-verified empirically.
  The original 8-model Ollama list from every prior free5GC sweep is no
  longer pulled on this machine (disk/OOM churn between sessions);
  re-pulling multi-GB models was judged not worth it for one control
  experiment, so ran against the 4 models actually available
  (`llama3.2:1b`, `llama3.2:3b`, `qwen3:8b`, `deepseek-r1:14b`) plus a
  same-session matched baseline against the real CVE handler
  (`run_memorization_control_baseline.py`) for a fair comparison. Result:
  1/4 compiled on the synthetic bug, 1/4 on the real CVE - and the model
  that succeeded differed between the two arms (`llama3.2:1b` fixed the
  synthetic bug but not the real one; `llama3.2:3b` the reverse); the two
  reasoning models (`qwen3:8b`, `deepseek-r1:14b`) timed out identically
  on both arms (documented pre-existing hardware constraint, not a new
  finding). Honestly reported as a small-sample (2/4 completed), directionally-
  against-memorization data point, not proof either way. Documented in
  `docs/FREE5GC_MEMORIZATION_CONTROL_RESULTS.md`. Remaining items from the
  "do everything" list (multi-run variance, OAuth2 enforcement, OpenEMR
  extension, main-catalogue bypass-probe, multi-turn adversarial probing,
  patch-quality scoring, methodology-pitfalls writeup) are queued, not
  yet started.

- **2026-10-05 (free5GC adversarial bypass-probe: all 8 Ollama models +
  11 named Claude models vs. the real fix, on `main`) - 0 genuine
  bypasses found; 2 Claude models refused the task outright; a real
  classifier bug caught before being reported** — Per explicit
  instruction ("run all the ollama models and probe the patched version
  to see if all these models can potentially bypass", then "try it with
  claude models" + 11 named models), built a new kind of experiment,
  distinct from every prior free5GC result: instead of asking a model to
  *write* the fix, asked it to *find a way past* the real,
  already-deployed upstream fix (`free5gc-udr-custom:patched`), given
  full knowledge of exactly what it blocks (an unconditional `return`,
  no remaining code-path gap) - only an HTTP-request-level trick could
  possibly work. Each model's proposed request was actually executed
  against the live stack, not evaluated by inspection. Caught and fixed
  a real bug in the test's own classifier before reporting anything: the
  first version flagged 3 models as successful bypasses purely because
  they asked for the exact correct, already-authorized path (one via
  harmless `%2F`-encoding that decodes to the identical canonical path)
  - not a bypass of anything. Fixed by requiring the decoded path to
  differ from the canonical one before counting it as a genuine attempt;
  re-classified from already-captured data with no new model calls.
  Final Ollama result: 0/7 responding models found a genuine working
  bypass (3 of 7 didn't even produce a genuinely distinct attempt despite
  being asked for one); `deepseek-coder-v2:16b` never ran (same hardware
  OOM as every other free5GC result involving it). Extended to 11 named
  Claude models (paid, via the existing `ClaudeCLIProvider`): 0 genuine
  bypasses found among those that actually tried; `claude-opus-5` and
  `claude-opus-5-5` - the two most capable models asked - explicitly
  refused to produce an exploit payload at all, even under the same
  authorized-red-team framing every other model in this project accepted,
  a materially different finding from `claude-sonnet-5`'s earlier
  automated cyber-safeguard refusal on the patch-generation prompt; 3
  model-name strings (`sonnet-5`, `sonnet-5-5`, `opus-4-9`) failed to
  resolve this run, notably including `claude-sonnet-5-5`, which had
  worked without issue in an earlier sweep the same day - reported as an
  observed inconsistency, not explained, given the cost already incurred.
  Total measured cost for the Claude run: $11.6218, the largest single
  spend in this project to date (`claude-opus-5`'s refusal alone cost
  $4.23). Documented in `docs/FREE5GC_BYPASS_PROBE_RESULTS.md` and
  `docs/FREE5GC_CLAUDE_BYPASS_PROBE_RESULTS.md`. Exit criteria met: a
  real, honest adversarial result exists now, including a self-caught
  methodology bug, a genuine negative (no bypass), and two genuine
  refusal findings - none hidden or overstated.

- **2026-10-05 (free5GC Level 2 extended a third time: 5 more
  user-named Claude models, on `main`) - 4/5 confirmed, 1 real model
  blocked by Anthropic's own cyber safeguards, a real cost surprise
  flagged and accepted before spending** — Per explicit instruction
  ("claude sonnet 4.6 / claude sonnet 5 / opus 4.6 / opus 4.7 / opus
  4.8 - try with these models too"), extended the Claude sweep further.
  A cheap "reply OK" smoke test on all 5 names FIRST cost $5.49 total
  (100K-277K `cache_creation_input_tokens` each) - far more than the
  $0.21-$1.13 range seen for the 3 models in the prior sweep for the
  identical trivial prompt. Flagged to the user explicitly before
  spending anything further, given this project's own ~$6.88 overspend
  history; user reviewed and chose to proceed with the full pipeline
  for all 5 anyway. Real per-model cost on the actual patch-generation
  run turned out much lower ($0.15-$0.35) than the smoke test predicted
  - traced to Anthropic's prompt-cache pricing (first-call
  cache-creation cost vs. cheap cache-read reuse afterward), not a
  sustained per-call rate. Results: `claude-sonnet-4-6`, `claude-opus-
  4-6`, `claude-opus-4-7`, `claude-opus-4-8` all compiled and were
  runtime-confirmed (`confirmed_fix_all_four_handlers`); `claude-
  opus-4-8` needed one free retry after a transient `go build` timeout
  (before any LLM call, so no cost lost). `claude-sonnet-5` is a real,
  distinct model (confirmed via the CLI's own usage report - 1M context
  window, `firstParty` provider) but is refused by Anthropic's own
  real-time "cyber safeguards" for this patch-generation prompt (it
  mentions CVE/CWE/vulnerability) unless the account joins their Cyber
  Verification Program - and the refusal itself was still billed in
  full ($1.11). Not retried further since it is a deterministic policy
  block, not a flaky error. Documented in
  `docs/FREE5GC_LLM_CLAUDE_SWEEP_EXTENDED_RESULTS.md`. Exit criteria
  met: every one of the 5 user-named models given a real, honest
  outcome - 4 genuine confirmations, 1 genuine policy-block finding,
  nothing silently skipped or glossed over.

- **2026-10-05 (free5GC Level 2 extended again: real Claude models via
  the claude CLI, on `main`) - 3/3 confirmed the fix, real cost measured,
  two real bugs found and fixed** — Per explicit instruction ("test them
  with claude models"), extended the local-Ollama comparison to real,
  hosted Claude models. No `ANTHROPIC_API_KEY` was configured, but the
  `claude` CLI was already authenticated, so added `ClaudeCLIProvider`
  (`src/reachability/providers.py`) shelling out to `claude -p`,
  mirroring `cve_pipeline.py`'s existing `_call_claude_metered`
  mechanism - still gated by `NO_PAID_BACKEND`, and import order matters
  (that module-level constant is fixed at providers.py's first import,
  so `NO_PAID_BACKEND` must be set to `"0"` before any reachability
  import). Confirmed real cost with the user before spending anything -
  a trivial smoke-test call alone cost $0.21 (CLI session overhead, not
  list price), given this project's own documented ~$6.88 overspend
  history - user confirmed proceeding with all 3 tiers (haiku, sonnet,
  opus). Result: all 3 compiled and were runtime-confirmed
  (`confirmed_fix_all_four_handlers`); total measured cost $1.5116
  (haiku $0.21, sonnet $1.13, opus $0.16 - cost did not track capability
  tier). Found and fixed two real bugs along the way, both in
  `generate_patch()`'s shared response-cleanup code (so the fix benefits
  every provider, not just Claude): `claude-opus-5-5` twice ignored the
  "no commentary" instruction - once wrapping the fix in a fence then
  appending prose *after* the closing fence (old cleanup only stripped
  leading backticks), once with no fence at all and trailing prose
  straight after the code. Fixed by truncating at the target function's
  own last unindented closing brace unconditionally, fence or not. Also
  hit one transient network failure (Go module proxy connection reset
  during a Docker build) unrelated to the patch, which had already
  compiled cleanly - retried only the Docker+runtime stage without
  re-paying for the LLM call. Documented in
  `docs/FREE5GC_LLM_CLAUDE_SWEEP_RESULTS.md`; README and this log
  updated. Exit criteria met: real hosted-model data added to the
  comparison, real cost reported honestly, two genuine bugs found and
  fixed rather than worked around.

- **2026-10-05 (free5GC Level 2 extended: all 8 local Ollama models
  swept, on `main`) - 7/8 confirmed the fix, 1 compiled but did NOT fix
  it, 1 couldn't load** — Per explicit instruction ("did you run each
  and every single ollama model" -> "yes" to running all 8 with a
  comparison table), extended the single-model (`qwen2.5-coder:7b`)
  result to all 8 locally-pulled Ollama models via a new
  `free5gc_full_deployment/run_model_sweep.py`. Found and fixed a real
  environment bug along the way: every model initially failed with
  "model not found" because `http://localhost:11434` was resolving to
  `wslrelay.exe`'s IPv6 listener (forwarding an unrelated project's
  separate Ollama instance inside WSL2) instead of the real Windows
  `ollama.exe` on `127.0.0.1:11434` - fixed by pinning `OLLAMA_BASE_URL`
  explicitly, not a code bug. Also hardened the sweep after `mistral:7b`
  timed out and crashed the whole run: widened exception handling
  around the one network call that can legitimately time out, and made
  the report persist after every model instead of only at the end.
  Results: `deepseek-coder-v2:16b` never loaded (real OOM - 45GB buffer
  request, a hardware limit, not a patching failure); 7 of the other
  7 models (`codellama:13b`, `gemma2:9b`, `mistral:7b`, `llama3.1:8b`,
  `qwen2.5-coder:7b`, `qwen2.5-coder:3b`) compiled AND were runtime-
  confirmed (`confirmed_fix_all_four_handlers`); `qwen2.5-coder:1.5b`
  compiled cleanly but genuinely did NOT fix the bug - it appended an
  unrelated extra response line instead of the needed `return`
  statements, caught specifically by the runtime harness
  (`collection_get_leak_fixed: false`) where a compile-only check would
  have missed it entirely. Also directly observed (not just flagged as
  a risk) that re-running `qwen2.5-coder:7b` produced a textually
  different but semantically identical patch - concrete evidence for the
  already-documented "single run per model" limitation. Documented in
  `docs/FREE5GC_LLM_MODEL_SWEEP_RESULTS.md`. Exit criteria met: a real,
  honest, per-model breakdown exists now - including a genuine negative
  result and a genuine environment-caused failure, neither hidden nor
  overstated.

- **2026-10-05 (free5GC Level 2: runtime confirmation completed, on
  `main`) - the LLM patch is now confirmed at the same evidence tier as
  the real upstream fix** — Per explicit instruction ("run the runtime
  harness once Docker is back up"), waited for Docker Desktop to recover
  from its earlier startup failure, then built
  `free5gc-udr-custom:llm_patched` (the real vulnerable commit with the
  materialized, already compile-verified LLM patch swapped in via new
  `udr_build/Dockerfile.llm` and `udr_build/prepare_llm_patched_source.py`)
  and ran a new `run_full_deployment_harness_llm.py` against the real
  MongoDB + real NRF stack, mirroring `run_full_deployment_harness.py`'s
  method exactly. Result: `overall_verdict:
  "confirmed_fix_all_four_handlers"` - all four exploit paths (collection-
  GET leak, single-GET leak, unauthorized PUT write, DELETE exploit)
  confirmed on the vulnerable build and confirmed fixed on the LLM-patched
  build, benign path preserved on both. `docs/FREE5GC_LLM_PATCH_RESULTS.md`
  updated from "compile-verified only" to "compile-verified AND runtime-
  confirmed," with the full verdict JSON and evidence file list. Exit
  criteria met: Level 2 (`docs/FREE5GC_LLM_PATCH_SCOPE.md`) is now fully
  implemented end-to-end; the only remaining open item is the
  memorization-risk limitation already flagged in the scoping doc, which
  needs a separate experiment (a less-likely-memorized handler/fix pair)
  to address, not further work on this case.

- **2026-10-05 (free5GC Level 2: real LLM patch generated + compile-
  verified against real upstream, on `main`) - a genuine rule-based-vs-
  LLM comparison, not just "ran a model for its own sake"** — Per
  explicit instruction ("scope out what it would take to run a model on
  free5GC" then "go ahead and implement Level 2"), wrote
  `docs/FREE5GC_LLM_PATCH_SCOPE.md` first (plan only, no code), then
  implemented its compile-verified half via a new script
  `src/reachability/run_free5gc_llm_patch.py`. Targeted
  `HandleApplicationDataInfluenceDataSubsToNotifyGet` specifically
  because `docs/REACHABILITY.md` already documents it as the one
  handler where the deterministic rule-based patcher is known to insert
  only one of the two `return` statements the real root cause needs.
  Used the free, local `OllamaProvider` (`qwen2.5-coder:7b`, already
  pulled on this machine) for just the patch-generation stage, keeping
  triage/verify on the deterministic mock path so the comparison isolates
  the patch step. Found and fixed a real pre-existing bug on the way:
  `src/reachability/patch.py`'s LLM prompt template was hardcoded for a C
  target (` ```c ``` ` fence, "C developer" system prompt) despite
  free5GC being Go — added a Go-aware system prompt and `{lang}`-templated
  fence, selected by `fn.file.endswith(".go")`. Result: the LLM patch
  correctly inserted `return` after **both** early-exit `c.JSON(...)`
  calls (the rule-based patch only catches the first), each one properly
  scoped to the validation block that produced it — a genuine, verified
  improvement on this specific handler, not a wash. Compile-verified by
  cloning the real `github.com/free5gc/udr` at the real pre-fix commit
  and confirming `go build ./...` succeeds with the LLM patch applied for
  this handler and the existing rule-based patches for the other 3 — all
  4 applied byte-exact, build passed. Documented in
  `docs/FREE5GC_LLM_PATCH_RESULTS.md`, including what this does NOT
  claim: no runtime confirmation yet (Docker Desktop is failing to start
  on this machine — `initializing Inference manager: ... The system
  cannot find the file specified`, a real pre-existing environment issue,
  not attempted to be silently worked around), and no control for the
  model having possibly memorized the real public fix rather than
  genuinely re-deriving it (flagged in the scope doc in advance). Exit
  criteria: compile-verification half of Level 2 complete and documented
  truthfully; runtime-confirmation half (swapping this patch into the
  Docker full-deployment harness) explicitly left open, not implied done.

- **2026-10-04/05 (merged `free5gc-full-deployment` and
  `openemr-transfer-scope` into `main`; README brought current) -
  decision made to stop treating these as branch-only results** — Per
  explicit instruction, both previously-isolated branches were merged
  into `main` for real (not just tested): `free5gc-full-deployment`
  (`6bf871b`) fast-forwarded cleanly; `openemr-transfer-scope`
  (`6cf91f5`) conflicted in exactly the two files the pre-merge dry-run
  had already identified (`.gitignore`, `docs/PROJECT_STATUS.md`, this
  file) — both resolved using the already-tested recipe (combine both
  branches' additions; session-log entries kept newest-first). Pushed
  as `ee3eaa9`. A durable rollback point was created first and pushed:
  annotated tag `backup/main-before-merge-2026-10-04`, pointing at the
  pre-merge `main` tip (`c58483e`) — `git reset --hard
  backup/main-before-merge-2026-10-04` on `main` recovers the exact
  frozen, single-handler/no-OpenEMR state if ever needed. One real
  mistake was caught and fixed before it mattered: an initial dry-run
  used `git worktree add` checked out directly on `main`, which (since
  worktrees share branch refs with the primary checkout) silently moved
  the local `main` ref forward; caught before anything was pushed and
  reset to exactly match `fyp/main` before the real merge was attempted.
  `README.md` was then updated across three commits (`fb7735c`,
  `884c530`, `003c425`): a "Current state" section summarizing both
  merged results, the free5GC CVE-2026-40248 entry upgraded from
  compile-verified to all-four-handler runtime-confirmed, a new OpenEMR
  section, the project-structure listing extended with the three new
  top-level directories, the standalone "Paper" section removed (with
  its few live references folded inline instead of left dangling), and
  three previously-undocumented FYP results added: the real-upstream
  `jaraco.context` validation, both multi-model comparisons (8-model
  local Ollama, 36-run hosted Claude), and the patch validator's own
  two corrections (the confirmed false acceptance and the later
  crash-absence-only benign-check finding). The committed upgraded
  report PDF (`free5gc_full_deployment/FYP_Report_main_upgraded.pdf`)
  was independently recompiled from its own committed `.tex` source (3
  passes) to confirm it still renders cleanly — no undefined
  references, no missing figures, 74 pages, matching the committed
  file exactly. Exit criteria met: `main` now carries everything two
  sessions ago left on separate branches, with a tested, working
  conflict-resolution recipe and a named rollback point; nothing
  unverified was pushed.

- **2026-09-29 (OpenEMR transfer case implemented, on `openemr-transfer-scope`
  only - `main` untouched) - GHSA-q366-cv5v-83w8 confirmed_fix** —
  Implemented and ran the Docker-based harness scoped by the earlier
  design pass, per explicit instruction to implement only this one
  target and stop. Real MariaDB (`mariadb:10.11`, minimal two-table
  schema) and a minimal PHP image (`php:8.2-cli` + `mysqli`, no Apache,
  no setup wizard) with the real, unmodified OpenEMR checkout bind-
  mounted, switched between the real vulnerable commit
  (`b5313ea2...`) and fixed commit (`50f789fa...`, PR #13133).
  Three requests (vulnerable default, patched default, patched opt-in)
  all matched expectations exactly, confirmed against the raw response
  bodies, not just status codes: vulnerable discloses real site/DB/
  version metadata; patched blocks by default with the exact documented
  403 message; patched still works when the operator explicitly opts
  in via `OPENEMR_ADMIN_PHP_ENABLED=1`. Verdict: `confirmed_fix`.
  Found and fixed two genuine startup-race bugs while running the
  harness for real (a MariaDB bootstrap-instance race and a PHP
  built-in-server TCP-accept-before-ready race), documented in
  `docs/OPENEMR_TRANSFER_RESULTS.md` alongside a cosmetic schema gap
  (missing `v_database`/`v_acl` columns) found and fixed from the first
  clean run's own raw evidence. Evidence bundle committed under
  `openemr_transfer_case/evidence/`. Exit criteria met: one real,
  non-inconclusive OpenEMR transfer case, produced without any paid/
  model backend (`NO_PAID_BACKEND=1` held throughout), `main` and the
  report untouched, scope not expanded beyond this one target as
  instructed.

- **2026-09-28 (free5GC full-deployment extension, on `free5gc-full-deployment`
  only - `main` untouched) - all four CRUD handlers runtime-confirmed,
  stronger vulnerability characterization found** — After Docker Desktop
  started working again, extended CVE-2026-40248's runtime confirmation
  from the one handler on `main` (DELETE) to all four of the reachability
  engine's originally-flagged handlers (GET single, PUT single, DELETE
  single, GET collection), using the official `free5gc-compose` stack
  (real MongoDB, real free5GC NRF v4.2.3, OAuth2 disabled - see the
  results doc for why) instead of the minimal stand-in harness. Caught
  and immediately corrected one mistake before it produced a false
  result: the OpenEMR case's commit hashes (from earlier in this same
  session) were accidentally passed to the free5GC UDR Docker build;
  the build failed cleanly since that commit doesn't exist in
  `free5gc/udr`'s history, and the correct hashes were used instead.
  **Finding, materially stronger than what's in the frozen report**: all
  three newly-tested handlers share the same missing-`return` root cause
  as the already-documented DELETE bug, and two are more severe than
  previously known - the collection GET leaks every subscription in the
  system in a response that looks like a plain 400 rejection, and the
  single PUT actually creates/stores an attacker's data despite
  returning 404 (an unauthorized write, not just a leak). All four close
  cleanly on the patched build with the benign path preserved. Automated
  by `free5gc_full_deployment/run_full_deployment_harness.py`;
  `verdict.json`'s `overall_verdict` is `confirmed_fix_all_four_handlers`.
  Full write-up in `docs/FREE5GC_FULL_DEPLOYMENT_RESULTS.md`. Exit
  criteria met: real evidence bundle captured, `main` and the frozen
  report untouched. Whether to fold this stronger characterization into
  the report is left as a separate decision, not made here.

Format: date — what was attempted — exit criteria met or not. Newest
first. Add an entry at the end of every real work session so the next
one's opening move is unambiguous.

- **2026-09-28 (Docker Desktop confirmed working again)** — The prior
  entry's Docker-status finding is now stale. User reported Docker was
  working; verified live rather than taken on trust: `docker ps` and
  `docker version` now succeed (Docker Desktop 4.74.0, engine 29.4.3,
  real running containers). An attempt was made to clear the stale
  `dockerInference` runtime artifact directly (via both `rm -f` and
  PowerShell `Remove-Item -Force`), both failing identically to the
  earlier free5GC-blocker attempts ("The file cannot be accessed by the
  system"); Docker started working after a plain Docker Desktop restart
  instead, independent of those attempts. Updated
  `docs/OPENEMR_TRANSFER_CASE_PLAN.md` to correct its Docker-status
  section: the official OpenEMR Docker Compose route is now the
  recommended deployment path for the harness, not just the native
  PHP+MariaDB fallback. No harness implementation started.

- **2026-09-28 (OpenEMR read-only design pass, on `openemr-transfer-scope`
  only - `main` untouched)** — Answered the five design questions the
  branch's own plan doc had deferred, per explicit instruction to design
  only, not implement. (1) Verified GHSA-q366-cv5v-83w8's exact fix
  commit (`50f789fad45ada625fe8d0faf0c7a9c15ef52aa5`, PR #13133) and its
  parent as the vulnerable commit (`b5313ea25f7928538eb793d4b4184ed4601d9afd`)
  via the real GitHub API, cross-checked against the `v8_3_0` release
  tag; noted this advisory has no CVE number assigned (`cve_id: null`).
  (2)-(3) Re-tested Docker Desktop live: identical "Inference manager"
  socket failure as the free5GC blocker, confirmed from its own backend
  log; not repaired, per the same standing decision. Reading
  `admin.php`'s real source at the vulnerable commit found its actual
  dependency graph is much narrower than assumed when the branch was
  first scoped - no full app bootstrap, just two side-effect-free
  requires and a two-table DB read - so a native PHP (`php -S`, no
  Apache) + MariaDB harness is realistically comparable in effort to
  free5GC's native-MongoDB substitution, not a bigger lift as first
  guessed. (4) Defined the exact default-vs-opt-in HTTP request/response
  assertions (403 plain-text block by default, 200 disclosure restored
  under the documented opt-in env var on both commits - the same
  "legitimate use preserved" standard as free5GC's benign delete). (5)
  Wrote the evidence-bundle schema, reusing the free5GC case's four-
  outcome verdict vocabulary rather than inventing a new one. All of
  this is written to `docs/OPENEMR_TRANSFER_CASE_PLAN.md` on this branch
  only. Exit criteria met: no harness code written, no HTTP requests
  made against a running OpenEMR instance, `main` unchanged. Also
  discovered mid-session an unrelated branch on the same remote,
  `claude/intelligent-hypatia-1u5yvf`, from an apparently different,
  stale session - it deletes this session's entire free5GC evidence
  bundle - flagged to the user, not touched, not merged.

- **2026-09-28 (OpenEMR healthcare transfer case scoped on branch)** —
  Started a non-main branch, `openemr-transfer-scope`, to explore the
  professor's suggestion of particularising the AI-CVE workflow to another
  DARPA-relevant industry without destabilising the now-stable free5GC report.
  Added `docs/OPENEMR_TRANSFER_CASE_PLAN.md`, a source-backed scoping document
  for OpenEMR as a healthcare transfer case. The plan selects GHSA-q366-cv5v-83w8
  (unauthenticated `admin.php` information disclosure, fixed in OpenEMR 8.3.0)
  as the safest first candidate because it should be testable with harmless
  request/response evidence, while deferring RCE/file-write candidates until a
  repeatable harness exists. No report text, exploit implementation, or
  main-branch state was changed. Exit criteria met: branch contains a concrete
  OpenEMR plan, with go/no-go criteria, candidate advisories, dependencies, and
  next-step design tasks.
- **2026-09-27 (Post-review cleanup - artifact-level CVE hygiene and stale
  doc framing)** — An external review of the updated FYP report found
  the case was genuinely valid but flagged three remaining loose ends:
  (1) `free5gc_runtime_case/udrcfg.yaml`'s config description still read
  `CVE-2026-40246`, and since UDR logs that description at startup, both
  process logs had inherited the stale ID even after the earlier
  identifier correction; (2) the report's Future Work still said the
  free5GC case "could be extended from compile-time to runtime
  verification" in general, no longer accurate now that one handler has
  runtime evidence; (3) `docs/REACHABILITY.md` and
  `docs/BENCHMARK_PROTOCOL.md` still framed CVE-2026-40248 as
  compile-verified only. Fixed all three: corrected `udrcfg.yaml` and
  re-ran the harness (no cost, `NO_PAID_BACKEND=1`) to regenerate clean
  logs under an identical result; rewrote the Future Work sentence to
  scope the remaining work to the other three handlers or a fuller
  deployment; updated both docs to state the current evidence tier (3 of
  4 handlers compile-verified, the DELETE handler additionally
  runtime-confirmed). Recompiled the report PDF twice (71 pages, no
  undefined references). Committed `70281e5`, which supersedes `f09de67`
  as the evidence source of truth; the report's own citation was updated
  to match. Exit criteria met: no known stale CVE-2026-40246 references
  remain anywhere in the evidence bundle, docs, or report.

- **2026-09-27 (Phase 2 implementation completed - CVE-2026-40248
  runtime-confirmed and patch runtime-validated)** — Continued the
  free5GC harness after native MongoDB (8.3.11) finished installing via
  winget and was verified reachable at `mongodb://localhost:27017`
  (real pymongo ping + `server_info()`). First run failed: the
  vulnerable UDR process never bound to port 8000, diagnosed via its
  process log as an infinite NRF-registration retry loop (a genuine
  correction to this project's own earlier plan-doc conclusion that
  NRF failure was "logged, not fatal" - see
  `docs/FREE5GC_RUNTIME_VALIDATION_PLAN.md`'s "Correction" section).
  Built a stub NRF satisfying only the one `RegisterNFInstance` call
  UDR needs at startup. A first (Python `http.server`) version of that
  stub still failed, with a *different* real error: free5gc's NRF
  client dials HTTP/2 cleartext (h2c) with prior knowledge, and a plain
  HTTP/1.1 responder makes the client fail client-side with `http2:
  frame too large`. Fixed by writing a small standalone Go binary
  (`free5gc_runtime_case/stub_nrf/main.go`, using
  `golang.org/x/net/http2/h2c`, an existing indirect dependency - no
  new dependency added) that speaks real h2c. With that in place, both
  the vulnerable and patched commits produced real, non-inconclusive
  verdicts: the vulnerable build's malicious DELETE returns 404 to the
  caller but still deletes the record server-side (no `return` after
  the 404 write); the patched build returns 404 and leaves the record
  intact; the legitimate benign DELETE path works identically on both.
  This exactly matches the CVE's own description and is now confirmed
  against the real upstream binary at runtime, not just by static or
  compile-time review. Full evidence bundle saved under
  `free5gc_runtime_case/` (`manifest.json`, `verdict.json`,
  `patch.diff`, `*_response.log`, `*_process.log`, `build_*.log`).
  Caught and fixed one own mistake before writing anything into the
  report: this case was initially labeled CVE-2026-40246, but that
  identifier already belongs to a *different* existing free5GC case
  in this project (a hand-written reproduction with no fix commit on
  record); the fix commit this harness actually exercises is the same
  one this project's own reachability work already established as
  CVE-2026-40248 - corrected in artifacts and re-run to confirm an
  identical result under the right identifier (see
  `docs/FREE5GC_RUNTIME_VALIDATION_PLAN.md`'s "Correction, 2026-09-27:
  CVE identifier" note).
  Exit criteria met: one real, non-inconclusive free5GC runtime
  validation case, produced without any paid/model backend
  (`NO_PAID_BACKEND=1` held throughout). Not yet done: folding this
  result into `FYP_Report_main.tex`; scope intentionally still excludes
  OpenEMR, Codex/Claude comparisons, and OSS-CRS integration per
  explicit instruction.

- **2026-09-27 (Phase 2 implementation attempt - blocked on Docker
  Desktop, not this project's code)** — Started implementing the
  free5GC runtime harness per the approved plan (`NO_PAID_BACKEND=1`
  kept, no scope broadening). Docker Desktop's daemon wasn't running;
  launched the already-installed application and waited. It never came
  up: its own log shows its "Inference manager" component failing to
  clean up a stale socket at
  `C:\Users\dheer\AppData\Local\Docker\run\dockerInference`
  ("filename... syntax is incorrect"), blocking the whole app - `docker
  ps` failed identically for the full wait window, not a slow cold
  start. No native `mongod`/`mongosh`/`mongo` on PATH either. Stopped
  here per explicit instruction rather than repairing Docker Desktop's
  own internal state (a machine-configuration issue, not a harness
  design choice). Documented the exact blocker and two concrete unblock
  options (fix/reinstall Docker Desktop, or install a native MongoDB
  binary instead) in `docs/FREE5GC_RUNTIME_VALIDATION_PLAN.md`.
  Committed `c12d257`, pushed to `fyp`. Harness code itself: not yet
  written, blocked on one of the two options above.

- **2026-09-26 (Phase 2 read-only design pass - free5GC runtime
  validation plan, DONE)** — Per explicit user instruction: read-only
  target-selection pass only, no paid LLM calls, no OpenEMR yet, and an
  explicit no-paid-backend guard before anything else, given the Phase 1
  smoke-test cost overrun above.

  Added and **tested live** `NO_PAID_BACKEND` env guard in
  `cve_pipeline.py`: with it set, `_call_claude_metered` raises
  immediately before any subprocess/network call; confirmed it reads
  `False` (no behaviour change) when unset. Committed `32ae137`.

  Investigated the real, currently-published `github.com/free5gc/udr`
  source (a disposable shallow clone, network-only, no LLM involved;
  inspected then deleted) to write
  `docs/FREE5GC_RUNTIME_VALIDATION_PLAN.md` from verified facts, not
  guesses: confirmed the exact vulnerable/patched code
  (`HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete`,
  missing `return` at the same fix commit `86686276a7e226183ee786e3dd6714ec56c78fda`
  already used by the existing compile-verified case in
  `docs/REACHABILITY.md`); confirmed NRF registration failure is
  non-fatal (`pkg/service/init.go` only logs it), so no real NRF is
  needed; confirmed OAuth2 and TLS are both config-toggleable off
  (`internal/context/context.go`'s `OAuth2Required` field,
  `sbi.scheme: http`); fetched the real official reference config from
  `free5gc/free5gc`. Net conclusion: **only a real MongoDB is required**,
  a much smaller dependency footprint than a full free5GC deployment.
  Committed `07c5616`, pushed to `fyp`.

  Docker Desktop is installed but its daemon was not running at
  inspection time - noted as a prerequisite to start before
  implementation, not yet resolved. Implementation of the actual
  runtime harness is the next step, explicitly not started this pass.

- **2026-09-26 (Phase 1 of the professor-approved critical-infrastructure
  roadmap - artifact preservation fix, DONE)** — A third external review
  proposed a 6-phase reframing of the FYP (free5GC + a new OpenEMR
  healthcare case, AIxCC-style evidence schema, restructured report),
  professor-approved per the user. Phase 1 (fix artifact preservation)
  was executed now since it's cheap and scope-neutral; Phases 2+
  (free5GC runtime validation, OpenEMR pilot, report reframing) not yet
  started - next open items.

  Added `--run-id` CLI flag to `cve_pipeline.py` (default `""`, exact
  prior single-run behaviour unchanged) that scopes Stage 3.5/3.8's
  generated artifacts under `reports/<run-id>/<CVE-ID>/` instead of the
  bare `reports/<CVE-ID>/` - the root cause of the shared-path overwrite
  bug found on 2026-09-26 (destroyed 30 of 36 hosted-Claude comparison
  artifacts). Every run now also writes `manifest.json` (backend/model/
  cost/duration/tokens for both generation and patch stages, confirmed
  status, `patch_verdict`), `patch.diff` (real unified diff, vulnerable
  vs. patched), and `exploit_log.txt`/`benign_log.txt` alongside the
  generated files.

  Verified live, not just by reading the code: two real runs of
  CVE-2026-42208 against the same `--cache-dir` with `--run-id modelA`
  and `--run-id modelB` produced two complete, independent artifact
  directories with no overwrite - `reports/modelA/CVE-2026-42208/` and
  `reports/modelB/CVE-2026-42208/`, each with its own manifest/diff/logs.
  This smoke test cost more real money than intended (~\$6.88 total):
  the first run used the real Claude backend by default (not flagged as
  a concern beforehand), and an attempt to force free Ollama for the
  second run by hiding `claude` from `PATH` did not actually work (the
  CLI was still reachable through some other resolution path on
  Windows) - both runs ended up billed. The path-scoping fix itself is
  confirmed correct regardless of which backend answered either run.
  Updated `docs/BENCHMARK_PROTOCOL.md` with a new Section 2 documenting
  the bug, the fix, and this verification.

- **2026-09-26 (second external review response - report-writing fixes,
  DONE)** — A follow-up external review of `FYP_Report_main.pdf`
  (v9-equivalent, after the reassessment work below) confirmed the prior
  fixes held and requested writing-quality changes, applied to
  `C:\Users\dheer\Downloads\FYP_Report_main.tex` (this file lives outside
  the git repo, so this entry is its own record): shortened the abstract
  from ~4900 to ~2000 characters, moving detailed per-number caveats
  (13/27 HTTP 200, the shared-path artifact-survival count, the exact
  Claude model list) into Chapter 4 where they already lived in full;
  added a new Chapter 1 "Ethics and Responsible Use" section (local-only
  targets, no third-party systems touched, all CVEs already publicly
  disclosed, future-work commitment to coordinated disclosure); added an
  objective-by-objective closure table to Chapter 5 (Met/Partially
  Met/evidence per stated objective); fixed a real internal
  inconsistency the review found - Section 1.4 (Scope) said benign-route
  preservation was pure future work, while Chapter 4 already reported
  the stronger reassessment confirming it for 6 recoverable artifacts -
  reworded to state the reassessment was added later, for the cases it
  could reach, not performed uniformly. ProvTrail wording was already
  strict on inspection (no change needed) and the reviewer's figure-1
  cosmetic note was left as-is (out of scope for a same-day text pass).
  Recompiled clean, 65 pages, no undefined references.

  The reviewer's separate research roadmap (fix the artifact-overwrite
  bug properly + a clean model-comparison rerun; class-specific benign
  oracles - largely done by the reassessment above; a real free5GC
  *runtime* validation, the biggest remaining research upgrade; Codex +
  Claude Code as a controlled comparison, deferred; conceptual-only
  OSS-CRS integration) was presented back to the user for prioritization,
  not started unilaterally given real cost/scope for several items.

- **2026-09-25 (external review response + stronger patch reassessment,
  DONE)** — An external review of `FYP_Report_main.pdf` (paste, verified
  independently before acting on it) found the report's `confirmed_fix`
  label overstated what the corrected validator actually proves: its
  benign-route check only requires the absence of a crash signature, not
  a correct HTTP response or class-specific expected output. Verified
  every specific number in the review against `src/pipeline/patch.py`
  and the raw JSON reports before changing anything - all checked out
  exactly (27/27 `confirmed_fix` benign probes exited via the reused
  PoC's own failure path, only 13/27 returned HTTP 200 on the final
  benign request, the rest split 401/403/400; one case,
  `claude-haiku-4-5`/CVE-2026-42208, showed `[-] Target unreachable`
  during the exploit re-probe, a transient startup race in the reused
  script's own health check, not a deliberate block, which the
  crash-signature check does not distinguish from either).

  Rewrote the report's abstract, Section 4.1.2, Section 4.1.5,
  Discussion, Key Findings, Contributions, and both appendices to
  describe `confirmed_fix` as heuristic patch-screening (exploit
  rejected without a detected crash, benign probe also crash-free), not
  confirmed functional correctness; fixed "three-way validator" to
  "four-outcome verdict" throughout (the ambiguity the review flagged);
  reconciled earlier limitation-section text that predated the
  corrected validator. SGD cost columns were added per a separate user
  request (with a cited exchange-rate source), then reverted to
  USD-only per the user's immediate follow-up - both tables and the
  bibliography are back to their prior USD-only state.

  **Then closed part of the gap directly** (Step 2 of a 5-step roadmap
  the user set after the review, agreed via AskUserQuestion: Steps 1-3
  now, Codex-dependent Steps 4-5 deferred - Codex remains uninstalled in
  this environment, confirmed again via `which codex`). Defined a real,
  class-specific expected malicious/legitimate result for each of the 6
  main-catalogue CVEs by reading the actual generated target/PoC source
  (e.g. SQLi: token `sk-legit-user-001` must return exactly
  `{"status":"authenticated","user_id":"u1"}`). Locating saved patches
  to reassess surfaced a further, previously undocumented harness gap:
  Stage 3.5/3.8's artifact writer saves to a shared,
  non-model-specific scratch path regardless of a run's own `--out`
  destination, so every model that touched the same CVE in the 36-run
  comparison overwrote the same file - only 6 of the 36 patched targets
  survive on disk, one per CVE (whichever model ran last for it, mostly
  unattributable; CVE-2026-46492's survivor was identified as
  `claude-opus-4-8`'s via its unique `generation_output_tokens=14789`
  fingerprint). Re-tested all 6 survivors against the new
  content-verified criterion: **all 6 pass** - clean, class-appropriate
  rejection on the malicious request, exact expected content on the
  legitimate one. Also explained, not just found, a real discrepancy:
  `claude-opus-4-8`'s CVE-2026-46492 patch (a correct `html.escape()`
  fix, confirmed by direct testing) was originally recorded
  `not_blocked` because the generated target's own vulnerability
  self-check is a keyword regex over its *escaped* output, which still
  matches literal text like " onerror=" even though the markup itself
  is inert and would never execute in a real browser - a fidelity
  limitation of the synthetic target's self-check, not a bypass of the
  patch. Full writeup: `reports/patch_reassessment_2026-09-26/RESULTS.md`.
  Folded into the FYP report (abstract + Section 4.1.2 + repo-path
  appendix). Committed as `ad06a3a`, pushed to `fyp`.

  Step 3 (a substantial new free5GC upstream case, chosen from the real
  free5GC security advisories, independently verified vulnerable/fixed)
  was approved but **not started** this session - next open item.

- **2026-09-25 (CORRECTION: the "Claude Code catalog run" below never ran
  on Claude Code - it silently ran on Ollama, DONE)** — While building a
  full session documentation pass at the user's request, finally checked
  the protocol's own Section 6 provenance rule
  (`docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md`: every entry's
  `generation_backend`/`generation_model` must read
  `"claude"`/`"claude-cli"`, or be flagged) against the six reports from
  the run described in the entry directly below - a check that was NOT
  done before those results were first reported to the user, who was
  briefly (one conversation turn) told this was a genuine Claude Code
  comparison. It was not: every one of the 6 reports shows
  `generation_backend: "ollama"`, `generation_model: "qwen2.5-coder:7b"`,
  real token counts, and `generation_cost_usd: 0.0` - none of which the
  Claude CLI backend ever produces.

  **Root cause, verified directly, not guessed**: `_claude_available()`
  (`cve_pipeline.py:381`) only runs `claude --version` (no auth required,
  succeeded: `2.1.280 (Claude Code)`, exit 0). The actual generation calls
  use `claude -p <prompt> --output-format text`, which failed on *every*
  call in this run with `Failed to authenticate: OAuth session expired
  and could not be refreshed` (exit 1 - confirmed by running that exact
  command standalone in this session). `_call_live_model()`
  (`cve_pipeline.py:491-499`) treats any empty-text Claude response as
  "fall through to Ollama," and nothing in the pipeline surfaces that
  fallback as a warning anywhere in the logs - so the run completed
  looking entirely normal while silently substituting Ollama for Claude
  at every single LLM call. This is a real, undocumented observability
  gap in the pipeline itself (a broken primary backend degrades silently
  instead of warning), not fixed in this session - flagged here, not
  fixed yet, per this project's own convention of separating a finding
  from its fix as two distinct, auditable steps. The `claude` CLI's own
  OAuth session is separate from whatever authenticates this Claude Code
  conversation itself and needs re-authentication outside this pipeline's
  control before a genuine Claude Code run is possible.

  **Remediation taken**: the six report files were `git mv`'d from
  `reports/claude_code_catalog_run_2026-09-25/` to
  `reports/llm_catalog_run_2026-09-25_round6/` (their content is real,
  honest Ollama data - just not the comparison they were meant to be) and
  written up as Round 6 in `reports/LIVE_LLM_CATALOG_RUN.md`, using the
  corrected Step 1 validator's full verdict breakdown for the first time
  in that file's series. `docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md` is
  left as-is (still a valid, unexecuted protocol for whenever the `claude`
  CLI is re-authenticated) rather than deleted. The `src/pipeline/patch.py`
  bug fix documented in the entry below is unaffected by this correction -
  it was verified by direct code reading and by running the corrected
  logic, not by which backend answered the prompt, and both of its
  verification runs (recorded as "Claude-CLI" at the time) are now known
  to have actually run on Ollama too, which does not change the fix's
  correctness.

  **A genuine Claude Code catalog run, and the Codex leg of Step 2, both
  remain not yet done.**

- **2026-09-25 (originally reported as "Claude Code catalog run" - Steps
  2/3 of the 6-step multi-agent comparison plan; SUPERSEDED - see the
  correction entry directly above, kept verbatim below for the audit
  trail)** — Ran the same 6 main-catalogue
  CVEs (CVE-2026-42208/27602/23949/78683/54729/46492) through the
  unmodified pipeline with `claude -p` as the live-model backend instead
  of Ollama (`_call_live_model()` already prefers the `claude` CLI
  whenever `_claude_available()` is true - a pure backend swap, no code
  change). **This intent was not achieved - see the correction entry
  above.** Protocol frozen first in
  `docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md` (case selection, attempt
  limits, scoring rules using Step 1's corrected verdict fields as the
  headline metric, provenance rules) before running anything, same
  discipline as `docs/BENCHMARK_PROTOCOL.md`. Stages 1-3 (advisory,
  analysis, vuln probe) served from a sandboxed cache copy of the
  existing `.pipeline_cache/` since this environment has no
  NVD/GHSA API keys configured. `.pipeline_lessons.json` backed up and
  replaced with `{}` for the full run to isolate it from Ollama-learned
  fixes, then restored afterward - confirmed byte-identical
  (8286 bytes) post-restore.

  **Results** (real, but Ollama not Claude - see correction above): 4/6
  exploits dynamically confirmed (CVE-2026-27602,
  CVE-2026-23949 did not confirm after 3 refinement iterations each);
  4/6 patches attempted; **0/6 `patch_verdict=confirmed_fix`** - every
  generated patch either failed to block the exploit
  (`not_blocked`: CVE-2026-42208, CVE-2026-78683, CVE-2026-54729) or
  crashed the patched route entirely (`inconclusive_crash`:
  CVE-2026-46492). No `regression_broke_route` case occurred. Raw
  reports (now relabeled, see correction above) + per-CVE timing in
  `reports/llm_catalog_run_2026-09-25_round6/<CVE-ID>.json`.

  **Bug found and fixed during this run** (this part stands, unaffected
  by the backend mislabeling): while building the per-CVE
  timing/verdict table, `CVE-2026-46492`'s `patch_verdict` was an empty
  string despite `patch_attempted=True`. Root cause: the early-return
  path in `generate_and_validate_patch()`
  (`src/pipeline/patch.py`) for when the patched target's health check
  fails entirely returned before reaching Step 1's corrected-verdict
  block, which lives at the end of the function - a genuine gap in the
  Step 1 implementation, not backend-specific. Fixed by
  adding explicit `patch_exploit_blocked=False`,
  `patch_function_preserved=None`, `patch_verdict="inconclusive_crash"`
  assignments directly in that early-return branch (a target that never
  becomes healthy at all is the clearest possible "crashed" case - no
  heuristic needed there). Verified by re-running CVE-2026-46492 alone
  twice - both runs produced the identical `inconclusive_crash` verdict
  (both, it is now known, also ran on Ollama, which does not change the
  fix's correctness since it was verified by direct code reading first).

  Steps 2/3 remain not done for a genuine Claude Code leg: Step 3 also
  asks to "save each agent's prompt" - not yet done for any backend -
  and "cost" would read `None` for every Claude-CLI entry once a real
  run happens, since `claude -p --output-format text` exposes no
  token/cost data (a real, protocol-acknowledged asymmetry vs. Ollama's
  `$0.0000`, not an oversight). Codex's leg of Step 2 explicitly deferred
  by the user until a working Claude Code leg is complete.

- **2026-09-25 (corrected patch validator - Step 1 of a 6-step
  multi-agent comparison plan, DONE)** — The old two-check
  `patch_validated` flag (exploit fails + `/health` passes) cannot tell a
  deliberate security rejection apart from an unrelated crash in the
  patched route - this is exactly the bug that produced the round-5
  CVE-2026-78683 false acceptance (a missing `io` import crashed the
  route for every request, satisfied both checks, and was flagged
  `patch_validated: True`). Fixed additively in `src/pipeline/patch.py` +
  `cve_pipeline.py`'s `ExploitArtifacts` model: kept `patch_validated`
  with its original meaning (old reports/results stay under the old
  validator, unchanged), added three new fields on top -
  `patch_exploit_blocked` (did the exploit fail *without* an unhandled
  exception in the target's own log, via a
  `Traceback (most recent call last)` / `Exception on ... [` heuristic),
  `patch_function_preserved` (does a benign, non-malicious request to the
  same route still succeed, probed the same way the existing
  multi-payload re-probe already works via `extra_arg`), and
  `patch_verdict` (one of `confirmed_fix` / `regression_broke_route` /
  `inconclusive_crash` / `not_blocked`).

  Verified against the REAL preserved round-5 log (not synthetic data):
  replaying that exact scenario through `generate_and_validate_patch`
  with `execute_exploit_artifacts` mocked confirms `patch_validated=True`
  (the old bug still reproduces) while `patch_verdict=inconclusive_crash`
  (the new check correctly refuses to call it a fix). Also verified the
  `confirmed_fix` and `regression_broke_route` paths with synthetic
  clean-rejection/benign-probe logs. A real, non-obvious finding along
  the way: the crash heuristic also flags round 4's `ValueError`-based
  rejection as a "crash" (Flask logs any raised exception with the same
  `Exception on ... Traceback` banner regardless of whether the exception
  was deliberate or a bug) - this is correct, not a false positive: an
  automated check genuinely cannot distinguish "deliberately raised to
  reject" from "accidentally raised", which is exactly the same honest
  limitation already stated in the FYP report's Discussion for round 4's
  own accepted patch ("this project's evidence for that claim is the same
  kind of manual inspection... not an independently stronger automated
  guarantee").

  A first attempt at a pytest test file
  (`tests/test_patch_validator.py`) hit the SAME pre-existing, previously
  documented Windows/pytest capture-corruption bug this file already
  describes elsewhere (any `cve_pipeline` import, even lazy/function-local,
  corrupts pytest's own capture teardown) - written then removed once it
  couldn't be collected, same precedent as before. Verified instead via a
  direct, non-pytest script exercising the real functions with
  `execute_exploit_artifacts` mocked - real evidence, just not
  pytest-shaped evidence, matching this project's established practice for
  this specific, still-unsolved environment bug.

  **Exit criterion for Step 1: met.**

- **2026-09-25 (real-upstream validation - Step 4, DONE)** — Per the
  user's direction, validated CVE-2026-23949 (jaraco.context path
  traversal) against the REAL package installed from PyPI, not a
  reproduction: two isolated venvs, `jaraco.context==5.3.0` (advisory's
  own stated vulnerable range) and `==6.1.0` (advisory's own stated fixed
  version). Read the actual installed source in both venvs to confirm the
  real root cause (`strip_first_component` splits on the first `/` and
  keeps any `../` in the remainder) and the real fix (`6.1.0` composes
  stdlib `tarfile.data_filter`, PEP 706, ahead of the same
  `strip_first_component`). Built a real malicious tarball and a real
  legitimate tarball, served locally over HTTP (127.0.0.1, the same
  local-self-controlled-target discipline this project already uses
  elsewhere), and called the real, unmodified `jaraco.context.tarball()`
  directly - no mocking. Full real four-way matrix:
  vulnerable+exploit = EXPLOITED (canary file written outside the
  extraction dir); vulnerable+legitimate = OK; patched+exploit = BLOCKED
  (`tarfile.OutsideDestinationError`, a real stdlib safety exception, not
  a generic crash); patched+legitimate = OK. Verdict using the same
  vocabulary as Step 1's corrected validator:
  `patch_exploit_blocked=True`, `patch_function_preserved=True`,
  `patch_verdict=confirmed_fix` - the strongest evidence tier this
  project has produced for any single case. Full writeup + raw log:
  `real_upstream_case/CVE-2026-23949/RESULTS.md` and `raw_log.txt`.
  **Exit criterion: met.**

  Steps 2-6 of the user's 2026-09-25 plan
  (common experiment protocol across this pipeline + Codex + Claude Code,
  running and preserving that comparison, validating one case on real
  upstream software, updating the report from the evidence, then an
  OSS-CRS source-only adapter) are NOT started - they need user decisions
  this session can't make unilaterally (Codex CLI is not installed in
  this environment - confirmed via `which codex`, only `claude` and
  `ollama` are present; real-upstream-software testing needs a scope/time
  decision). Flagged to the user rather than silently attempted or
  skipped.

- **2026-09-24 (ProvTrail checking extended to cve_watcher.py)** — The
  user asked to check ProvTrail integration in `cve_watcher.py` too,
  after it was made the real default source in `provtrail_bridge.py`
  earlier the same session. Audited first: `cve_watcher.py` had zero
  ProvTrail awareness, by design, not oversight - it's architecturally
  a continuous NVD/GHSA feed poller, while ProvTrail is a static,
  point-in-time local scan with no live feed to poll the same way.
  Presented this distinction and a concrete extension option before
  writing any code; user chose to extend it.

  Added `fetch_provtrail()` (mirrors `fetch_nvd`/`fetch_ghsa`'s
  generator shape, reuses `provtrail_bridge`'s own default-discovery
  and `load_scan`/`dedupe` directly rather than duplicating them) and
  wired it into `poll_once()` alongside the existing NVD/GHSA/`--repos`
  sources. Design choice: no new mtime-tracking state needed - the
  existing `SeenStore` dedup (which already prevents re-processing an
  already-seen NVD/GHSA CVE) does the "pick up anything new since last
  poll" job for free, since every advisory in the CURRENT scan is
  yielded every cycle and already-seen ones are silently skipped. New
  flags: `--provtrail-scan PATH` (explicit override) and
  `--no-provtrail` (full opt-out, including auto-discovery).

  **A real, pre-existing bug found and partially addressed along the
  way**: `cve_watcher.py`'s Windows stdout-rewrap ran unconditionally
  at import time (not inside `main()`, unlike the same code in
  `cve_pipeline.py`/`provtrail_bridge.py`) - moved it into `main()` to
  match the already-proven pattern in those two files. This did NOT
  fully fix a deeper issue it happened to surface: merely importing
  `cve_pipeline` at module level (which `cve_watcher.py` has always
  done, eagerly, unlike `provtrail_bridge.py`'s lazy function-local
  import of the same module) corrupts pytest's own capture mechanism on
  Windows (`ValueError: I/O operation on closed file` at
  `tempfile.py:500`, inside pytest's own capture fixture) - confirmed
  via bisection to be triggered by `cve_pipeline` alone, not by
  `logging.basicConfig()` or `pydantic_ai` individually. Root cause not
  fully found; chasing it further was disproportionate to this task's
  actual scope. **Deliberately deferred, not silently dropped** - same
  "flagged, not chased down given cost" honesty as the
  `qwen2.5-coder:1.5b` timing outlier elsewhere in this file.
  Consequence: no pytest-based regression test for
  `fetch_provtrail()`/`poll_once()` exists (a first attempt was written
  then removed once it couldn't be collected). Verified instead via a
  live, non-mocked script exercising the real functions directly -
  confirmed correct in all 4 cases: no scan discoverable (empty),
  explicit fixture scan (6 real advisories from
  `tests/fixtures/provtrail/latest-scan.sarif`), `--no-provtrail`
  (never calls `fetch_provtrail`), and the existing test suite (9/9)
  still passing since nothing in `provtrail_bridge.py`/its own tests
  was touched. Real evidence, just not pytest-shaped evidence.

- **2026-09-24 (ProvTrail SARIF made the real default source)** — The
  user flagged that the just-published architecture diagram showed
  NVD/GHSA as the primary path and ProvTrail as a dotted "optional"
  feed - backwards from `provtrail_bridge.py`'s own documented
  `--source=auto` priority (ProvTrail then feed fallback), which only
  actually took effect if the caller remembered to pass `--scan`
  explicitly. Fixed both the framing and the real gap: added
  `_default_scan_path()`, which auto-discovers a scan at the
  conventional `.provtrail/latest-scan.{sarif,json,ai.txt}` location
  (SARIF preferred) when `--scan` isn't given, so ProvTrail is now the
  genuine default source with zero flags needed - `--source feeds`
  remains the explicit escape hatch to skip it entirely. Caught and
  fixed a real bug in my own first edit before it ever shipped: the
  function body still referenced the now-stale `args.scan` (always
  `None` on the auto-discovery path) instead of the resolved
  `scan_path`, which would have crashed with `Path(None)` the first
  time discovery actually found a file - caught by re-reading the
  function after the edit, not by running it. Two new offline tests
  added (`test_default_scan_auto_discovered_when_no_scan_given`,
  `test_source_feeds_skips_default_scan_discovery`); full suite (9/9,
  up from 7) passing. Both README.md's and architecture.html's Mermaid
  diagrams corrected to show ProvTrail as the solid/default path and
  NVD/GHSA as the dotted/fallback one, matching the code exactly.

- **2026-09-24 (ProvTrail JS/TS bounded validation — DONE)** — Picked up
  the ProvTrail integration item's step 3 (`provtrail_js_lab/`), the one
  remaining substantial open item after everything else this session had
  flagged was closed out. Full detail in the ProvTrail item's own entry
  above and `provtrail_js_lab/README.md`. Summary: `execute_exploit_artifacts`
  now spawns `node` instead of Python when the target is `.js` (the ONE
  pipeline change, additive - Python path re-verified unaffected after
  the change, not just before); built one hand-authored JS target
  (`CVE-2024-48910`, dompurify Prototype Pollution, CWE-1321, CRITICAL -
  picked from the real ProvTrail fixture over two other real candidates
  for being genuinely JS-native and honestly reproducible) and its PoC;
  ran it through the real Stage 3.6 mechanism via `run_demo.py`, not a
  parallel script. Caught and fixed a real false-positive during
  verification: a leftover node process from earlier manual testing
  made a broken spawn attempt (`EADDRINUSE`) look like a clean success
  by accident - found via `netstat`, killed the stale PID, re-ran
  genuinely clean. Exit criterion met: one real end-to-end case,
  `dynamically_confirmed: True`, verified twice. Auto-classification/
  auto-generation for JS classes and a second JS class remain explicitly
  out of scope, as planned from the start.

- **2026-09-24 (qwen2.5-coder:1.5b timing outlier, narrowed)** — Picked
  up the other open item from `reports/PATCH_VALIDATION_INVESTIGATION.md`:
  a 1636.5s generation call for the smallest model, flagged but never
  investigated. Structural read first, before any live call: the
  `(None, None)` `generation_input_tokens`/`generation_output_tokens`
  pairing on that historical record is only possible on
  `_call_ollama_metered`'s failure/timeout path - a successful `200`
  always carries Ollama's own `prompt_eval_count`/`eval_count` - so this
  was never a slow *successful* generation, it was a request that
  ultimately failed. Reproduced live to confirm: re-ran the exact same
  CVE/model (`CVE-2026-54729`/`qwen2.5-coder:1.5b`) and got the identical
  failure mode on demand - `generation_outcome: llm_live_failed`,
  `generation_duration_s: 180.001` (capped at the `timeout=180` default),
  tokens `None`/`None`. Narrowed, not fully root-caused: the *class* of
  failure (this CVE/model pairing genuinely struggles to converge within
  the timeout) is now confirmed and reproducible, not a one-off; the
  *exact* 1636.5s figure (9x the 180s timeout) remains unexplained in
  full - `requests`' `timeout=` is a per-read-chunk timeout, not a hard
  total-request cap, so a low-level connection event could in principle
  let a call run past its nominal timeout, but this wasn't directly
  observed, only plausible given how `requests` timeouts work. Read
  `reports/PATCH_VALIDATION_INVESTIGATION.md`'s updated note for the
  full reasoning - stated as narrowed, not solved, deliberately.

- **2026-09-24 (mistral:7b patch-parse bug, diagnosed and fixed)** —
  Picked up the open item from `reports/PATCH_VALIDATION_INVESTIGATION.md`:
  mistral:7b's confirmed CVEs showing `patch_skip_reason: "...didn't
  parse"`. Reproduced directly (replayed `_llm_generate_patch`'s exact
  prompt against `mistral:7b` outside the pipeline, printed the raw
  response) before touching any code. Root cause: mistral:7b's patch
  response never emits the literal `===PATCHED_TARGET_END===` marker -
  it goes straight from the patched code to `===SUMMARY_START===` - so
  `_extract_marker`'s strict `text.index(end, s)` raised and the whole
  patch was silently discarded as empty, even though real, usable code
  was sitting right there in the response. Fixed in the shared
  `_extract_marker` (used by Stage 3.5/3.7/3.8 alike): fall back to the
  next `===X_Y===`-shaped marker as an implicit boundary when the exact
  end marker is missing. Verified 4 ways before and after: a unit test
  against the exact captured failure shape (0 → 842 chars recovered,
  compiles), two control cases (normal both-markers response unaffected;
  a genuinely markerless response still safely returns empty), and a
  live unmodified pipeline re-run on `CVE-2026-42208`/`mistral:7b` -
  before: `patch_attempted: False`; after: `patch_attempted: True`, a
  real patch summary, and an honest `patch_validated: False` (the patch
  itself didn't work, evaluated and rejected for real, not skipped).
  Exit criterion met: the parsing gap is closed and independently
  verified live, not just theorized.

- **2026-09-24 (post-merge verification)** — Ran `CVE-2026-78683` end to
  end on the just-reconciled `main` (`5417c29`), since the merge combined
  two independently-tested code paths (this session's exit_code fix,
  the other session's multi-payload validation + pinned sampling) that
  had never actually run together. Result: `dynamically_confirmed=True`
  (exit_code 0), `patch_attempted=True`, `patch_validated=True`, and
  `payload_variants` populated with 2 real distinct alternate payloads —
  the patch survived re-probing with both, not just the original. This
  is the strongest single result across every round run so far: real
  generation → real dynamic confirmation → real patch → validated
  against 3 total distinct payloads, all on the merged code, with no
  stale `exit_code`/`dynamically_confirmed` anywhere in the run. One CVE,
  one shot - not a full catalog re-run (that's a larger, separate task if
  wanted later) - but it directly answers the open question from the
  reconciliation entry above: the merge did not silently break either
  side's capability. Exit criterion met: the two independently-fixed
  code paths coexist and both fire correctly in the same run.

- **2026-09-24 (reconciliation)** — Two Claude sessions worked this repo
  in parallel on 2026-09-23, both branching from the same commit
  (`4c1a386`) without initially knowing about each other: this session
  (on `main` directly) and a separate session on `feat/live-llm-gate1`.
  Both independently found and fixed the exact same Stage 3.7 dead-code
  bug (`main`'s `e344966` vs. the branch's `3f21eda` — functionally
  identical) and a markdown-fence-in-model-output bug (`main`'s
  `b05b45d` vs. the branch's fix earlier in its own sequence) via
  different-but-equivalent implementations. Cross-session messaging
  surfaced the divergence before either side merged or deleted anything;
  a side-by-side diff against the shared merge-base confirmed: the
  branch has strictly more capability (multi-payload patch validation —
  a genuinely new mechanism guarding against a patch that just
  blocklists one literal payload; the 8-model Ollama comparison; pinned
  sampling for reproducibility; 2 more real bugs fixed: a discarded
  patched-process diagnostic log, an IPv4/IPv6 `localhost` ambiguity
  flipping `_ollama_available()`'s answer); `main` had one real fix the
  branch was missing (`execute_exploit_artifacts` leaving `exit_code`/
  `dynamically_confirmed` stale on a crash instead of resetting them)
  plus two catalog re-runs (rounds 3/4) the branch never ran.
  **Resolution**: merged `feat/live-llm-gate1` into `main` (not a reset —
  both sessions' full commit history is preserved), keeping the branch's
  implementation for every case where both sides fixed the same thing
  (its `_strip_markdown_fence`, its `_extract_marker` shadowing pattern),
  and porting `main`'s exit_code/dynamically_confirmed fix on top since
  the branch was genuinely missing it. `execute_exploit_artifacts` on the
  merged code already carried that fix cleanly (no conflict there — only
  `cve_pipeline.py`'s duplicate fence-helper, `patch.py`'s duplicate
  `_extract_marker`, `self_improve.py`'s docstring/metrics-recording
  style, and this file's own session log needed manual resolution). Full
  test suite re-verified passing post-merge before push. Both original
  session-log entries below are kept as-written, not edited to match
  each other — each is what was actually known and true at the time it
  was written.

- **2026-09-23 (later same day)** — Found and fixed a real dead-code bug
  in Stage 3.7, then used the fix to run two more full catalog rounds
  (3 and 4), finding and fixing two more bugs along the way. Full detail
  in `reports/LIVE_LLM_CATALOG_RUN.md` and `docs/DEFENSE_PREP.md`; this
  entry is the index.

  1. **Stage 3.7 dead-code bug (commit `e344966`)**: `src/pipeline/
     self_improve.py`'s `_llm_revise_artifacts` called
     `_call_claude`/`_claude_available` directly instead of the
     provider-agnostic `_call_live_model`/`_live_model_available` helper
     Stage 3.5/3.8 already used. Under this machine's real conditions (no
     `claude` CLI, local Ollama only), that meant Stage 3.7 silently
     never ran at all — not "stub-tested," genuinely dead. Fixed by
     mirroring the proven Stage 3.5/3.8 pattern; also added
     `revision_backend`/`model`/`duration_s`/`input_tokens`/
     `output_tokens`/`cost_usd` per `refinement_history` entry. Verified
     live against a synthetic failing fixture before touching the real
     catalog: the fix correctly fell through to Ollama and confirmed a
     real revision.

  2. **Round 3 catalog run (commits `5ecd4d0`, `6f932b4`)**: re-ran the
     frozen 6-CVE catalog with the Stage 3.7 fix live. Only 1/6 confirmed
     (`CVE-2026-23949`, via genuine cross-CVE lesson reuse — the first
     time that code path ever fired) — not better than round 2's 2/6,
     but the *mechanism* now demonstrably runs. Digging into the raw
     `execution_log` (not just the summary numbers) to write an honest
     per-CVE pass/fail table surfaced two previously-undocumented bugs,
     deliberately documented in a separate commit *before* fixing them:
     (a) `_extract_marker` didn't strip a stray `` ``` `` markdown fence
     from the model's response, so 4/5 failures crashed with
     `SyntaxError` on `target_app.py`'s first line; (b)
     `execute_exploit_artifacts` left `exit_code`/`dynamically_confirmed`
     stale on a crash instead of resetting them, so `refinement_history`
     could misleadingly read a crash as "ran and cleanly failed."

  3. **Bug fixes (commit `b05b45d`)**: added `_strip_code_fence`; reset
     `exit_code`/`dynamically_confirmed` explicitly on the crash path;
     removed `src/pipeline/patch.py`'s duplicate `_extract_marker` in
     favor of importing the shared, now-fixed one. Each fix verified with
     a standalone targeted test before re-running anything: one against
     the exact round-3 failure shape (now parses as valid Python), one
     that runs a healthy target then swaps in a crashing one on the same
     artifacts object (now correctly resets instead of staying stale).

  4. **Round 4 catalog run (commit `9711fe5`)**: same protocol, both
     fixes live. **4/6 confirmed** (up from 1/6), and zero of the six
     reports contain the `SyntaxError` crash signature anywhere,
     confirmed programmatically. Two firsts for the project: `CVE-2026-27602`
     confirmed via a genuine from-scratch Stage 3.7 revision (not a
     reused lesson) — the first live-generated revision to ever fix a
     failing exploit; `CVE-2026-78683` got its Stage 3.8 patch
     **validated** — the first validated patch across all four rounds
     (0/8 prior attempts). `CVE-2026-42208` (SQLi) and `CVE-2026-23949`
     (Path Traversal) still didn't confirm — real clean failures, not
     crashes, so a diagnosis-quality gap for those two classes on this
     run, not a plumbing bug. Counting per-class across all 4 rounds
     combined (not per-round): **all 6 vulnerability classes in the
     catalog have now confirmed dynamically at least once.**

  5. **Documentation (commits `c7cfb19`, `39f0dc4`)**: added an explicit
     "what is a test case" section to `reports/LIVE_LLM_CATALOG_RUN.md`
     (real advisory data + the exact simulated route/payload/pass-condition
     each generated PoC uses, pulled from round 4's actual generated
     artifacts, not paraphrased); updated `docs/SCOPE_AND_LIMITATIONS.md`'s
     Limitation 6 (the "zero live-generated revisions succeeded" caveat
     no longer holds) and its summary table (patch validation now
     demonstrated once); updated `docs/DEFENSE_PREP.md`'s "weakest
     evidence" answer (no longer "LLM paths are stub-only") and added
     three new Q&A entries for this session's findings.

  **Exit criterion**: not formally re-stated here (see the live-LLM item
  below for the item's own framing) — but concretely, generation,
  dynamic confirmation, self-improvement, AND patch validation all
  succeeded together for the same CVE (`CVE-2026-78683`) in the same run
  for the first time. All 6 commits pushed to `fyp` only, per this
  project's git-remote convention; `git diff HEAD fyp/main --stat`
  verified empty (local and remote identical) as of `39f0dc4`.

- **2026-09-23 (live-LLM Gate 1/2, full session, branch
  `feat/live-llm-gate1`)** — Closed out the "wire in a live LLM" Phase 4
  item end to end across all three LLM-touching stages (3.5 generation,
  3.7 self-improve, 3.8 patch), with real per-call cost/time/token
  metrics throughout — not estimated, read directly from the Claude CLI
  or Ollama's own `prompt_eval_count`/`eval_count`/`total_duration`
  fields. Full commit sequence: `a6aec31` (Stage 3.5 + local Ollama
  backend) → `a3d802d` (Stage 3.8 wired) → `0eb4a29`/`25c2699` (per-call
  and per-pipeline metrics) → `390c316` (first full catalog run) →
  `4c1a386` (schemeless-URL bug fix, round 2) → `b0b3377` (pinned
  sampling: `temperature=0`, fixed seed) → `c2d76a5` (8-model comparison)
  → `ba24163` (2 patch-gen bugs + multi-payload validation) →
  `276f62f` (patch-validation investigation write-up + clean 48-run
  re-test) → `7c7cfbe` (2 payload-extraction bugs, found *after* that
  write-up — see correction below) → `3f21eda` (Stage 3.7 wired to the
  same backend, closing the one remaining unwired call site).

  **What exists now**: `_call_live_model`/`_live_model_available` in
  `cve_pipeline.py` — Claude CLI first, local Ollama fallback
  (`OLLAMA_HOST` defaults to explicit `http://127.0.0.1:11434` after a
  real IPv4/IPv6 localhost-ambiguity bug was found via `netstat`, see
  below) — is now the single call path for all three stages. Every call
  returns a `LiveModelResult` (`text, backend, model, duration_s,
  input_tokens, output_tokens, cost_usd`) that gets recorded on
  `ExploitArtifacts`/`PipelineReport` (`generation_*`, `patch_gen_*`,
  and now `revision_*` on `refinement_history` entries) and rolled up
  into `total_llm_*` in every report and `src/metrics.py`'s
  `METRICS.md`.

  **Full model catalog run**: 8 local Ollama models (qwen2.5-coder at
  1.5b/3b/7b, llama3.1:8b, mistral:7b, gemma2:9b, codellama:13b,
  deepseek-coder-v2:16b) × the 6-CVE frozen catalog, run twice (an
  initial comparison in `reports/MULTI_MODEL_COMPARISON.md`, then a
  clean re-test after the patch-gen bugs below were fixed, in
  `reports/PATCH_VALIDATION_INVESTIGATION.md`). Claude/OpenAI explicitly
  **dropped** for this round per direct instruction ("drop Claude for
  this round, Ollama only") — no CLI/API key available in this
  environment, never silently worked around. Headline, stated plainly
  rather than as a leaderboard: confirmation rate does not track model
  size (7B beat both 9B and 13B); qwen2.5-coder:7b is the strongest
  confirmer but also has the most prior prompt-tuning exposure (a real
  confound); patch generation does not reliably work with any of these
  8 models on a single deterministic shot even after the bugs below were
  fixed (3/48 "validated," and see the caveat on what that number
  actually means below).

  **Real bugs found by direct challenge, not by process** — the user's
  own words drove this: *"to validate a patch you have to try and probe
  the patch"*, then *"if you can potentially bypass them, that means the
  patch is not good"*. Investigating that surfaced four real bugs (all
  in `reports/PATCH_VALIDATION_INVESTIGATION.md`, commit `ba24163`):
  (1) all 17 patch attempts in the first comparison crashed on a
  markdown-fence artifact the model wrapped its output in; (2) once
  fixed, patches sometimes omitted the Flask `app.run()` startup block
  entirely, exiting silently with no traceback; (3) the patched
  process's real stdout/stderr was captured internally then discarded,
  which is why bugs 1–2 were invisible until fixed; (4) `localhost`
  resolved to two different services on this machine (`ollama.exe` on
  IPv4, an unrelated process on IPv6), silently flipping
  `_ollama_available()`'s answer call to call — found via `netstat
  -ano`, not guessed.

  **Built in direct response to that same challenge**: single-payload
  patch validation is not proof a vulnerability class is closed — a
  patch that blocklists one literal string would pass. Stage 3.5 now
  also asks for 2 structurally distinct alternate payloads
  (`ExploitArtifacts.payload_variants`); `poc.py`'s generated contract
  now accepts a payload override (`exploit(host, port, payload=None)`,
  `sys.argv[2]`); Stage 3.8 re-probes every would-be-validated patch
  with each alternate payload and overrides `patch_validated` back to
  `False` on the first one that still succeeds. Verified correct on a
  controlled synthetic case (a deliberately narrow blocklist patch
  passed the old single-payload check, then was correctly caught and
  rejected once a structurally different payload was tried) — no Ollama
  call needed for that proof.

  **Correction to `reports/PATCH_VALIDATION_INVESTIGATION.md`**: that
  report's "Bottom line" section states the payload-extraction quality
  gap (echoed placeholder text, unstripped backticks) was "not fixed
  here." That was true when written; it no longer is. Commit `7c7cfbe`
  (same day, after that report) fixed both: `_clean_payload_variants()`
  now drops a whole block that's a single parenthetical (the model
  echoing the prompt's own placeholder instructions back verbatim
  instead of real payloads) and strips a wrapping single backtick per
  line. Verified offline against the two real bad inputs that were
  found, plus a clean case and a mixed-line case, and with one live
  re-run (`qwen2.5-coder:1.5b` / `CVE-2026-46492`) confirming
  `payload_variants` now comes back clean or empty, never garbage. The
  report file itself was intentionally left as the honest record of
  what was true at the time it was written rather than rewritten after
  the fact — this entry is the correction, read both together.

  **Stage 3.7 wiring (`3f21eda`, last commit of the session)**: Stage
  3.7 (`src/pipeline/self_improve.py`) was the one remaining call site
  still checking `_claude_available()` only — under this session's
  Ollama-only conditions it silently never ran, the exact class of
  "silent fallback" gap Gate 1 was built to expose everywhere else.
  Mirrors the identical pattern already proven for Stage 3.5/3.8.
  Verified live: `CVE-2026-23949` / `qwen2.5-coder:7b` produced 3
  refinement attempts, each showing `revision_backend=ollama` with real
  duration/token counts — previously this returned `None` every time.

  **Exit criteria met**: all three LLM call sites use the unified
  backend with real recorded metrics (not estimated); multi-payload
  patch validation is built and proven correct; 4 real bugs found and
  fixed with direct evidence (not assumed).
  **Exit criteria explicitly NOT met / left open** (per
  `reports/PATCH_VALIDATION_INVESTIGATION.md`'s own honest framing —
  read that file for the full numbers): mistral:7b's patch responses
  fail to parse for a reason distinct from the `localhost` bug, not
  diagnosed; qwen2.5-coder:1.5b had one 1636.5s generation outlier,
  flagged not investigated; getting models to reliably produce
  well-formed alternate payloads in practice is still the real gap —
  the honest headline is **not** "3/48 patches validated," it's
  "0/48 patches have been tested against more than their original
  payload" (all 3 "validated" cases had `payload_variants: []`).
  ProvTrail's JS/TS dynamic-execution work (below) and further
  root-causing were both deliberately deferred given context budget,
  not silently dropped — see the plan file this session executed
  against for the explicit scope cut.

  **Also this session, but tooling, not project substance** (kept out
  of this project's own doc, noted here only for continuity): installed
  and started `claude-mem` (a separate, local, Claude-Code-native
  observation memory tool) at the user's explicit request, kept
  deliberately distinct from this project's own documentation/memory
  system — it does not replace or touch anything in this repo.

- **2026-09-23** — Built the *ingestion + orchestration* half of the
  Phase 4 ProvTrail item (`provtrail_bridge.py`, `package_labs.py`,
  `tests/test_provtrail_bridge.py` + SARIF/AI-text fixtures; pushed to
  `fyp` as `2e7a6b4`). The bridge reads a ProvTrail SARIF / AI-text / raw
  `provtrail_scan_v*` JSON scan, dedupes advisories, runs the existing
  `cve_pipeline` per advisory, and writes a combined detect+locate ->
  confirm+patch report; falls back to this project's own NVD/GHSA feeds
  when no scan is usable. **Gate 1 cleared** (see the ProvTrail item):
  a real sample from Elson confirms the CVE ID travels in
  `properties.provtrail.advisoryIds` (the generic properties bag, exactly
  as predicted), location in the standard `physicalLocation`,
  priority/confidence alongside; all three export formats resolve to the
  identical 6 advisories, verified by an offline test. **Exit criterion
  for the FULL item NOT met and not claimed**: the pipeline still
  generates only Python Flask targets, so every JS/npm advisory the bridge
  runs is honestly reported "static+patch only (no matching lab)" — zero
  dynamic confirmation of a ProvTrail finding yet. Steps 2-4 (JS/TS
  dynamic execution) remain; `package_labs.py` is the seam where a future
  Node/Express lab registers. JS/TS build still deferred per the Sept 28
  note in that item. Done this session at the user's direction, ahead of
  the item's original "revisit after Sept 28" framing — a deliberate
  divergence, not a silent one.

- **2026-09-15** — Extended the Stage 2 classification ablation from
  n=1 to the full 6-CVE catalog (`docs/BENCHMARK_PROTOCOL.md` §7), run
  directly against the real `_classify_from_text`/`_classify_from_cwe`
  functions and real stored advisory data. Exit criterion met: 1/6
  class-level failure, 2/6 CWE-level mismatches, both real and
  reproducible. Refined further same day: split into 3 metrics
  (class-match/exact-CWE-match/full-miss), cross-checked NVD's CWE
  against GitHub's independent advisory database for all 6 CVEs (6/6
  agree — real mitigation of the single-source circularity concern),
  pre-registered scoring methodology for the future live-LLM session.
  `origin` (AI-exploit-CVE) force-pushed back to `88844d2` at the user's
  explicit request — frozen for conference use; all work from here on
  goes to `fyp` (Final-Year-Project) only. Live-LLM wiring and the S1
  litellm stratum (below) were deliberately NOT attempted this
  session — still open.

Living checklist. Update after every real work session — mark nothing
done that isn't actually verified. Adapted from an external plan's
checklist pattern, applied to this project's actual stages, not a
parallel system.

## Phase 0 — Core pipeline (DONE)

- [x] Stages 1-4 implemented (`cve_pipeline.py`) — advisory fetch,
      classification, probe, report
- [x] Stage 3.5-3.7 implemented — exploit generation, dynamic execution,
      self-improvement
- [x] Stage 3.8 implemented — patch generation + two-check validation
- [x] 8 catalog entries run end-to-end, 6/8 dynamically confirmed
      (`reports/CVE_CATALOG.md`)
- [x] Can explain every stage without notes — **verified via Socratic
      walkthrough**; see corrections that were actually needed in
      `docs/SCOPE_AND_LIMITATIONS.md`

## Phase 1 — Refactor + metrics (DONE)

- [x] `cve_pipeline.py` extracted into `src/` package (3643 -> 2596 lines)
- [x] `src/metrics.py` reads `reports/*/report.json` for real numbers
      (no fuzzing/static baselines — deliberately not measured, see
      `docs/BENCHMARK_PROTOCOL.md` §2)
- [x] Stale duplicate folders + 12MB video removed from git history going
      forward

## Phase 2 — Real-source work (DONE, one case)

- [x] `src/reachability/` ported from reachcrs, reproduces its own known
      numbers exactly (102 functions, 4 reachable, 96.1% reduction)
- [x] Real free5GC/udr repo cloned, both vulnerable and fixed commits
      confirmed to build
- [x] Generated patch applied to the real cloned module, confirmed to
      still `go build ./...` — **new capability, not present in reachcrs**
- [ ] Real *dynamic* (HTTP-level) confirmation against the real free5GC
      service — blocked on standing up MongoDB + NRF registration, not
      attempted (`docs/SCOPE_AND_LIMITATIONS.md` Limitation 4)
- [ ] `free5gc_lab/` and `src/reachability/`'s free5GC case study unified
      into one effort — currently two disconnected pieces targeting the
      same bug family (Limitation 5)

## Phase 3 — Documentation & framing (DONE)

- [x] Project pitch corrected away from "fuzzing" (confirmed OK with
      professor; professor has since said they're open to whatever
      direction is taken — this project continues on engineering merit,
      not because fuzzing is off-limits)
- [x] `docs/CRS_MAPPING.md` — honest AIxCC/OSS-CRS alignment
- [x] `docs/SCOPE_AND_LIMITATIONS.md` — report-ready claim/evidence table
- [x] `docs/BENCHMARK_PROTOCOL.md` — frozen catalog, precise metrics,
      provenance tracking (adapted from external rigor pattern, no
      fuzzing baselines adopted)
- [x] `docs/DEFENSE_PREP.md` — Q&A built from actual walkthrough gaps

## Phase 4 — Open, not started (top two elevated to priority — see plans below)

- [ ] **Wire in a live LLM.** External supporting evidence this is worth
      doing, not just internally motivated: a September 2026 industry
      writeup (Val Marelox, ["Can AI weaponize new CVEs in under an
      hour?"](https://valmarelox.substack.com/p/can-ai-weaponize-new-cves-in-under))
      reports an independently-built pipeline with the same three-stage
      shape this project already has (advisory analysis -> generate
      vulnerable-app+exploit -> execute against vulnerable/patched
      versions) running end-to-end on a live model (Claude Sonnet 4.0),
      producing 10 working exploits across JS/Python/Ruby in ~10-15
      minutes and ~$1 per CVE. Useful as a rough benchmark for what to
      expect once this project's own live-LLM session runs — not
      equivalent evidence, since it's a blog post, not peer-reviewed,
      and the architecture match doesn't make its numbers this
      project's numbers. For contrast, Theori's own RoboDuck README
      (a real AIxCC finalist, not a blog post) warns their
      competition-tuned, multi-agent CRS "can easily spend $1,000 or
      more in under an hour" -- the two real data points bound a huge
      range (~$1/CVE vs. ~$1000/hour) depending entirely on model
      choice and agent count, useful context for scoping the frozen
      prompt set's cost before running it broadly. Also worth noting: the author's own caveat —
      "the refinement loop could generate exploits that worked but
      weren't genuinely exploitative" — is the same class of false-
      positive risk as the existence-only `verify()` bug found and
      fixed in this project's CVE-2026-78683 case (commit `da84781`),
      independently surfacing in someone else's pipeline too.

      **More precise first-party number, 2026-09-17**: FuzzingBrain's
      own README (correct current org is `fuzzingbrain`, not `o2lab` —
      same project, renamed) states one example run measured at
      **14.6 minutes and $2.14** against a $20 budget cap — a real,
      specific number from the tool's own docs, not an estimate.

      **Real citable paper found**: FuzzingBrain has an actual arXiv
      paper, not just a competition repo — "All You Need Is A Fuzzing
      Brain: An LLM-Powered System for Automated Vulnerability
      Detection and Patching" (Sheng, Xu, Huang, Woodcock, Huang,
      Donaldson, Gu, Huang, 2025), arXiv:2509.07225. Stronger and more
      specific than the generic DARPA AIxCC results-page citation
      already in the free5GC paper's Related Work — worth using in the
      *thesis*'s Related Work chapter (not the locked paper). Also
      genuinely runnable (`./FuzzingBrain.sh`, Docker mode, REST API,
      MCP server, Apache-2.0, active commits) unlike Atlantis/Buttercup,
      which need Kubernetes + Kythe/Sootup/SVF cloud infra to even start.

      **Buttercup (Trail of Bits)**: also deployment-focused at the top
      level, but confirms SARIF as a cross-team standard (`send_sarif.sh`
      is a real script in their orchestrator, independent of Atlantis) —
      further validating Elson's SARIF choice for ProvTrail against
      actual competition practice, not just one team's convention. Their
      `program-model/` (reachability-equivalent) uses Kythe + cscope +
      JanusGraph — again heavyweight, cloud-scale (n2-highmem-8 instance,
      70-minute Docker builds), not a porting candidate, same conclusion
      as Atlantis's Sootup/SVF.

      **Bug Buster (42-b3yond-6ug)**: README is deployment-only, no
      architecture detail without digging into individual `components/`
      subfolder READMEs, which the top-level README itself warns may be
      outdated. Not pursued further — diminishing returns.

      **SHERPA — real results, but a genuine fuzzing-framing tension,
      2026-09-17.** Checked the actual README, not just the one-line
      description. It's a real, results-backed tool: 127+ raw crashes
      across real OSS-Fuzz projects, auto-filtered by an LLM crash-triage
      agent down to 18 validated CVE-class bugs (67% precision, CWE
      breakdown published). Its core principle — prioritize
      attacker-controlled entry points over low-level internal APIs —
      is philosophically the same argument this project's reachability
      filtering already makes. **But its mechanism is explicit,
      proud, marketed fuzzing** ("Revolutionary LLM-powered fuzzing"),
      built on libFuzzer coverage-guided campaigns. This project
      deliberately dropped fuzzing framing this session, with the
      professor's blessing (see "Project framing" in `CLAUDE.md`).
      **Do not cite or adopt SHERPA's fuzzing mechanism without the
      user explicitly asking** — same rule as fuzzing language
      generally. The one separable, non-fuzzing part worth naming: its
      Stage 1 "Intelligent Target Selection" (attacker-controlled
      entry-point prioritization) is explicitly a distinct phase before
      any fuzzing starts — confirms the entry-point-first principle is
      sound industry practice, without requiring adoption of the
      fuzzing stages that consume it.

      **Repository Visualizer**: not a code-porting candidate (a
      Three.js-style data viz frontend, "Created by Undaunted," a
      contracted vendor). But it exposes real ground-truth data: the
      actual AIxCC Final Competition task list — real production C/Java
      projects (curl, wireshark, openssl, log4j2, xz, freerdp, poi,
      pdfbox...) with real per-task vulnerability counts and codebase
      scale (curl: ~4,000 files across many tasks; wireshark: ~7,000).
      Useful as an honest scale comparison for the thesis — AIxCC
      operates on huge, multi-thousand-file real projects at
      competition-grade cloud infrastructure scale; this project
      targets one CVE at a time with a lightweight, single-developer
      pipeline. Worth naming that contrast explicitly rather than
      letting page count silently imply equivalence.

      Per an external review of this project:
      the flagship worked example (`docs/CRS_MAPPING.md`,
      `materials_for_glm.md`) has zero live model calls end to end —
      fetch is an API call, classification is a lookup, generation was a
      hardcoded template, execution is LLM-independent, and patch
      generation was stubbed. That's a real gap for a project about
      using LLMs to secure OSS, not just a caveat. Concrete plan, in
      strict order — each step gates the next, not a checklist to
      reorder for convenience:
      1. **Gate**: fix the silent-fallback path in
         `generate_exploit_artifacts()` (`if not poc_code or not
         target_code: <template>` currently swallows a failed live
         attempt with no distinct signal). Add `generation_outcome`
         (`llm_live_success` / `llm_live_failed` / `template`) to
         `ExploitArtifacts`, surfaced through `compile_report()` into the
         final report — the live-generation failure rate becomes a
         measured result, not an invisible footnote. See
         `docs/BENCHMARK_PROTOCOL.md` §4's pre-registered rule. Nothing
         below runs until this gate clears.
      2. Install Ollama; pull a small code model (`qwen2.5-coder:7b` or
         similar). Add a provider-agnostic adapter alongside the existing
         `_call_claude()`/`_claude_available()` (same call sites Stage
         3.5/3.7/3.8 already use). Verify a single trivial call works
         before doing anything else.
      3. **Bounded prompt development**: draft prompts for each advisory
         condition (full/description-only/ID-only) and test freely
         against exactly ONE catalog CVE — iterate as much as needed here.
         The moment any catalog-condition run starts on a second CVE, the
         prompt set is **frozen** for the rest of the session. This is
         the line between honest prompt development and post-hoc tuning;
         don't let "draft inside the session" drift into "draft
         interactively, mid-condition."
      4. Run the catalog under the now-frozen conditions. Record
         `generation_mode`/`generation_outcome`, model ID, and
         temperature in every report. Exit criterion:  at least one CVE
         completes the full chain (live-generated PoC -> dynamically
         confirmed -> patch_validated) — not "all six work." Report
         degraded/failed generations honestly, don't cherry-pick.

         **Done, 2026-09-23 (branch `feat/live-llm-gate1`):** ran all 6
         catalog CVEs, one shot each, frozen prompt, real
         `qwen2.5-coder:7b` via local Ollama, real time/token/cost per
         report (see the live-LLM Gate-1/2 instrumentation above) — full
         results in `reports/LIVE_LLM_CATALOG_RUN.md`. **Exit criterion
         partially met**: CVE-2026-42208 reaches live-generation ->
         dynamic-confirmation (both True); patch was attempted but
         `patch_validated=False` (the model's patch used generic
         auth-format validation the injected payload still passes — a
         real, explained patch-quality failure). 5/6 other CVEs did not
         dynamically confirm on their single frozen shot (`exit_code=1`
         each) — reported honestly, not cherry-picked, not retried. Root
         cause: the prompt's success contract was iterated and converged
         against SQL Injection only (step 3); it does not reliably
         zero-shot transfer to the other 5 classes with a 7B model.
         Per-class prompt tuning (repeating step 3's bounded process per
         class) is the natural next step to raise the confirmation rate,
         not attempted here to keep this run an honest single-frozen-
         prompt baseline.

         **Round 2, same day:** found a real, shared bug in 3/5 failures
         (PoC used the schemeless `host:port` argv directly as a URL,
         silently swallowed by a broad `except`) and fixed it with one
         generalizable prompt rule. Re-ran the full catalog: 2/6 confirmed
         this round (SSRF, XSS — both new), but CVE-2026-42208 (SQLi,
         confirmed in round 1) did NOT confirm in round 2 with the
         identical wording — real model-sampling variance, not a
         regression. Correct combined statement: **3 distinct classes
         confirmed at least once across the two rounds (SQLi, SSRF, XSS),
         not "2/6."** Full honest comparison, including the fix's own
         first-attempt bug (an f-string escaping mistake that broke all 6
         re-runs identically before being caught and fixed), in
         `reports/LIVE_LLM_CATALOG_RUN.md`.

         **Done, same day (see the full session-log entry above)**: all
         three LLM call sites (Stage 3.5, 3.7, 3.8) wired to a single
         provider-agnostic backend with real per-call metrics; 8-model
         Ollama comparison run; multi-payload patch validation built and
         proven correct; 4 real bugs found and fixed (markdown fence,
         missing `app.run()`, discarded diagnostic, `localhost`
         ambiguity) plus 2 payload-extraction bugs. This Phase 4 item is
         now substantially closed — what remains open (mistral:7b parse
         failures, the 1.5b timing outlier, and reliably producing
         well-formed alternate payloads in practice) is tracked in
         `reports/PATCH_VALIDATION_INVESTIGATION.md`, not re-listed here.
- [ ] **S1 fidelity stratum — real litellm, not a reproduction, for one
      CVE.** The single highest-value upgrade to Limitation 1
      (`docs/SCOPE_AND_LIMITATIONS.md`). Concrete plan:
      1. `pip install litellm==<the CVE-2026-42208 vulnerable version>`
         in an isolated environment/container.
      2. Stand up litellm's actual proxy server with the config needed
         to reach the vulnerable database-backed API-key-check code path
         (real setup — litellm's proxy needs a master key and a DB
         backend configured; this is not a one-line run).
      3. Craft and confirm a real HTTP exploit against the real server
         (not `target_app.py`) — same dynamic-confirmation discipline as
         the rest of Stage 3.6, pointed at real code.
      4. Patch-validate against the real package if feasible, or state
         plainly why not (e.g. no upstream patch to apply cleanly).
      One successful S1 result turns Limitation 1 from a blanket
      disclaimer into a disclosed stratum with one real data point — a
      genuine strengthening, reportable either way it turns out.
- [ ] **ProvTrail integration — professor-suggested, 2026-09-16.** Combine
      this project with a classmate's FYP tool, ProvTrail (a local CLI
      that statically scans JS/TS codebases against a GHSA/OSV corpus and
      flags likely clones of known-vulnerable code, exact/inferred/
      needs-review, no runtime testing at all). Agreed shape: ProvTrail's
      static findings feed this project's dynamic-confirmation pipeline
      as a downstream stage — closing exactly the evidentiary gap
      ProvTrail itself doesn't close (a static resemblance match is not
      proof of exploitability). The other student is aware and has
      explicitly said their own implementation approach isn't binding —
      full freedom on how to build the integration.

      **Real size of this, stated honestly**: not a wire-up. Every
      existing exploit template (Stage 3.5) generates a Python Flask
      target; there is currently zero JS/TS dynamic-execution capability
      anywhere in this pipeline. Comparable in scope to when native-code
      memory-safety support was added, not a small addition.

      **Update, 2026-09-16**: the other student (Elson) is adding SARIF
      output to ProvTrail — a real OASIS-standardized, versioned JSON
      format for static-analysis results, not a bespoke schema
      (verified via sonarsource.com/resources/library/sarif, not taken
      on faith). A SARIF result carries a rule ID, message, source
      location, severity, and — directly relevant here — a CWE/CVE
      security mapping field. This meaningfully de-risks Gate 1 below:
      the integration parser can be designed against the public SARIF
      spec now, not blocked entirely on Elson's source. What still
      needs a real sample from him: exactly how ProvTrail populates the
      CVE-mapping field in practice (SARIF's security-mapping fields are
      somewhat tool-dependent in how strictly they're filled in), and
      whether the flagged snippet/file location comes through in the
      standard `physicalLocation` field or a custom `properties`
      extension.

      **Real SARIF field structure, verified against Microsoft's
      sarif-tutorials (not the marketing page), 2026-09-16:**
      - Base result shape (confirmed real ESLint example):
        `runs[].results[].{ruleId, level, message.text,
        locations[].physicalLocation.{artifactLocation.uri,
        region.startLine}}` — this part is standard, adapter-safe now.
      - CWE has a proper first-class path:
        `runs[].tool.driver.supportedTaxonomies` + a `taxonomies[]`
        block defining CWE as a taxonomy, and each `results[]` entry
        can carry `taxa: [{id, toolComponent: {name: "CWE"}}]`.
      - **CVE does not** — SARIF's taxonomy/`taxa` mechanism is built
        for stable classification systems (CWE, OWASP), not point-in-
        time identifiers like CVE numbers. ProvTrail's CVE ID will
        almost certainly travel through the generic `properties` bag
        (tool-specific, any name/value pairs) or be embedded in a
        rule's `helpUri`/`fullDescription`, not a dedicated field.
        This is the one thing genuinely still unknown without a real
        sample — everything else above is now designable from the
        public spec alone.

      **Progress, 2026-09-23**: the ingestion + orchestration layer is
      built and pushed (`provtrail_bridge.py`, `package_labs.py`, tests;
      commit `2e7a6b4`) — parses ProvTrail SARIF/AI-text/raw JSON, feeds
      each advisory to the existing `cve_pipeline`, writes a combined
      report, and falls back to NVD/GHSA feeds when no scan is usable.
      This is the wire-up the note above said is *not* the hard part; the
      hard part (steps 2-4, JS/TS dynamic execution) is untouched. Run
      today it dynamically confirms nothing — every JS advisory is
      "static+patch only (no matching lab)" — so the item stays open.

      **Gated plan, in order — each step gates the next:**
      1. **Gate — CLEARED 2026-09-23.** Real ProvTrail SARIF/AI-text
         samples are now in hand (`tests/fixtures/provtrail/`). The CVE ID
         travels in `properties.provtrail.advisoryIds` (the generic
         `properties` bag, exactly as predicted above — not a taxonomy),
         with `packages`, `confidence`, and `priority` alongside it, and
         the location in the standard `physicalLocation`. The raw
         `provtrail_scan_v*` scan JSON is ProvTrail's internal state, not a
         consumer contract — its advisory *selection* needs ProvTrail's own
         `finding_exports.project_findings`, so the bridge uses that when
         ProvTrail is importable and otherwise asks for the SARIF/AI-text
         export. Original gate text (kept for context): get one real sample
         SARIF report to see which `properties` key carries the CVE ID,
         since that's the one piece SARIF's standard doesn't fix; location
         and message fields were already known-good from the public spec.
      2. Decide integration mode explicitly, don't default to the
         harder one without weighing it:
         - **(a) Class-level confirmation (recommended MVP)**: build
           JS/TS exploit templates (Node/Express targets) mirroring the
           existing 6-class Python template architecture, keyed off the
           CVE's vulnerability class. Reuses Stage 3.5/3.6's already-
           proven pattern; confirms the *class* of bug is dynamically
           reachable, not literally the exact flagged line in the exact
           scanned project.
         - **(b) In-place confirmation (harder, more valuable, later)**:
           actually exercise the specific flagged function inside the
           real scanned codebase. Directly closes ProvTrail's evidentiary
           gap, but arbitrary third-party JS/TS projects have wildly
           inconsistent build/run requirements — closer in difficulty to
           the memory-safety harness-generation work than to the existing
           Python templates. Don't start here.
      3. **Bounded validation — DONE, 2026-09-24.** Built exactly ONE
         JS/TS template (`provtrail_js_lab/`), for exactly ONE
         ProvTrail-flagged CVE from the real fixture
         (`tests/fixtures/provtrail/latest-scan.ai.txt`):
         `CVE-2024-48910` (dompurify, Prototype Pollution, CWE-1321,
         CRITICAL) — chosen over the fixture's other two real
         high-confidence `VULN` entries (a Next.js HTTP-smuggling CVE, a
         fastify one) because prototype pollution is genuinely JS-native
         with no equivalent in this pipeline's existing 6 Python classes,
         and far more tractable to honestly reproduce than smuggling's
         precise HTTP-framing requirements. One real pipeline change,
         additive only: `execute_exploit_artifacts` now spawns `node`
         instead of the Python interpreter when the target file is
         `.js` — the Python path is otherwise completely untouched,
         verified by re-running an existing Python CVE end-to-end
         *after* the change (still confirms, still patches, still passes
         multi-payload validation, identical to before). `provtrail_js_lab/`
         has a hand-authored `target_app.js` (zero npm deps — Node's
         built-in `http`/`url` only) and `poc.py` (same 4-phase pattern
         as every other CVE's PoC), run through the *real*
         `execute_exploit_artifacts` (not a parallel script) via
         `run_demo.py`. Result: `dynamically_confirmed: True` — real
         global `Object.prototype` pollution, verified twice (once with
         a stale leftover process from manual testing giving a
         false-clean read, caught via `netstat`/`taskkill`, then re-run
         genuinely clean with a fresh spawned process).
      4. Exit criterion matches the live-LLM item's discipline above:
         **met** — one real end-to-end case (ProvTrail flag -> dynamic
         confirmation) succeeded. Explicitly not attempted: auto-
         classification (Stage 2) or auto-generation (Stage 3.5) for JS
         classes, or a second JS/TS class — both correctly out of scope
         for this bounded pass; "all classes work" was never the bar.

      **Strong precedent found, 2026-09-17**: Team Atlanta's Atlantis —
      the actual AIxCC Final Competition winner — has a real, working
      module for exactly this shape of integration:
      `example-crs-webservice/crs-sarif`. Verified against its own
      README (not the source itself): it runs as
      `python test_crs_sarif.py -s <sarif-report-path>`, taking a SARIF
      report as input and running reachability analysis against it to
      produce `sarif_analysis.json`. Sub-components: `sootup/`
      (callgraph generation via the established Sootup framework for
      Java), `tracer/` ("getting call traces from seed or pov" — a
      dynamic complement to static reachability), and a genuine TP/FP
      benchmark structure (SARIF reports from PoV-to-SARIF generation,
      commercial SAST, and custom generation, scored against known
      ground truth). This is real validation that "SARIF in ->
      reachability analysis -> validated output" is a legitimate,
      competition-winning architecture, not a shape this project
      invented in isolation. Not a code-porting candidate — Sootup/SVF
      are heavyweight academic frameworks, wrong scope for a student
      FYP — but worth citing as precedent, and their TP/FP benchmark
      methodology is worth a look for `docs/BENCHMARK_PROTOCOL.md`.

      **Explicitly NOT started before the free5GC paper's September 28
      deadline** — this needs the other student's actual code (not yet
      in hand) and is real new-language engineering, not something to
      rush alongside a submission. Revisit right after.
- [ ] **(Optional, low priority) Family-tolerant CWE matching** in
      `_classify_from_text()` — currently hardcodes one representative
      CWE per class (e.g. always CWE-79 for any XSS keyword hit), which
      is what causes the CVE-2026-46492 mismatch in
      `docs/BENCHMARK_PROTOCOL.md` §7. Deliberately NOT fixed now —
      patching the classifier after already running and reporting that
      ablation would turn a measurement into a moving target. If pursued
      later: accept any member of the real CWE family per class,
      sourced from the official CWE site at implementation time, not
      from memory.
- [ ] **LICENSE for this repo** — no LICENSE file exists yet. Explicitly
      deferred: check the university's IP policy for FYP work before
      publishing any license (some institutions claim rights over FYP
      code or restrict public licensing until after grading). Do not add
      a LICENSE file speculatively.
- [ ] `docs/BENCHMARK_PROTOCOL.md`'s freeze date — not yet set; catalog
      is still open to additions
- [ ] Second, independent CVE class for the free5GC reachability work
      (currently one case, CVE-2026-40248)
- [ ] Decision on whether to pursue full dynamic free5GC confirmation
      (needs a MongoDB + NRF deployment — real infrastructure work, not
      a quick add)
- [ ] Report/thesis writing — nothing in this repo constitutes report
      prose beyond the `docs/` reference material above; do not treat
      any `docs/*.md` file as report-ready without adapting the voice

See `docs/CONSIDERED_DIRECTIONS.md` for proposals evaluated and
deliberately not adopted, with reasoning — check there before revisiting
a direction that may have already been ruled out for a documented reason.

## What NOT to do without deliberately deciding to

- Don't add fuzzing (AFL++/libFuzzer/coverage-guided mutation) as a
  drive-by addition — if it happens, it should be a deliberate scope
  decision with its own rationale, not scope creep from an external plan.
- Don't build a second, parallel pipeline that duplicates
  `cve_pipeline.py` + `src/reachability/`'s existing capability.
- Don't claim `llm-live` provenance for any result until a real API key
  or `claude` CLI is actually configured and used in this environment.

