# Final evidence summary: the bounded conclusion across every access method

`docs/RESULTS_SUMMARY.md` indexes results by experiment, and
`docs/RESULTS_BY_ACCESS_METHOD.md` indexes the same results by access
mechanism. This page is neither index - it is the one-page, thesis-
facing conclusion both of those pages support, stating plainly what
this project has actually shown, across every backend that was ever
run, and what it has deliberately not shown.

## The bounded conclusion

Across 5 distinct access methods - a direct Claude API key (AIxTech
gateway), the `claude` CLI, the OpenAI API, the Codex CLI, and local
Ollama models - and well over 60 distinct model identities tested
against the free5GC real-upstream CVE, the OpenEMR real-upstream CVE,
and the 6-CVE main catalogue:

**Every already-validated patch held. Zero genuine bypasses were ever
confirmed, against any patch, from any model, through any access
method.** A handful of raw "bypass" hits did occur - always on the
same XSS catalogue target (CVE-2026-46492), always traced to the same
already-known, already-documented `_EXEC_HTML` test-oracle regex bug
(it matches escaped `onerror=`/`onclick=`/`javascript:` text that
never executes), and more than once self-diagnosed by the model's own
`reasoning` field before a human or script checked the raw response.
The legacy marker oracle is deliberately preserved for audit, but it is no longer the public XSS result. All 33 historical raw-positive proposals across Ollama, `claude -p`, the AIxTech gateway, and the OpenAI API were replayed in headless Chrome; the independent `browser_genuine_bypass` result is zero.

**Patch-generation quality varies substantially by model and backend,
but is not backend-dependent in any simple way** - the same model
family can succeed through one access path and fail through another
(e.g. `claude-sonnet-5` failed with `exit 1` via `claude -p` on one
free5GC pass, then produced a clean, fully-confirmed patch through the
AIxTech gateway on the very next). No backend's weaker results should
be read as that backend being unsound; every failure mode traced back
to either a specific model's generation quality or a specific
environment constraint (compile error, deprecated model ID, OAuth
expiry, per-key model allowlist), never to a flaw in the validation
harness itself once the methodology pitfalls below were fixed.

## Headline numbers by access method

| Access method | Models attempted | Best patch-gen result | Genuine bypasses found |
|---|---|---|---|
| Ollama (local, free) | ~8 distinct models across sweeps | 6/8 runtime-confirmed (free5GC snapshot) | 0 browser-confirmed bypasses (historical raw positives replayed) |
| Claude CLI (`claude -p`) | 6 named models, reused across 5 experiments, plus an 11-model bypass sweep | 5/6 clean gate (OpenEMR) | 0 browser-confirmed bypasses (historical raw positives replayed) |
| Claude API key (AIxTech gateway) | 10 requested, 4 resolve on this key | 4/4 reachable clean gate, 12/12 stable across a 3-run repeatability check | 0 browser-confirmed bypasses (historical raw positives replayed) |
| Codex CLI | 18 model IDs attempted | 7/18 runtime-confirmed (free5GC) | 0 |
| OpenAI API | 23 model IDs | 18/23 full four-handler validation pipeline passes (free5GC; one model-generated handler + three deterministic materializations), 16/23 (OpenEMR) | 0 browser-confirmed bypasses (12 historical raw positives replayed) |
| Claude Code (agentic, main pipeline) | 0 - frozen, never successfully executed | n/a | n/a |

Every row's figures are drawn from that access method's own doc
(linked in `docs/RESULTS_BY_ACCESS_METHOD.md`) and trace back to a raw
JSON report under `reports/reachability/` or `reports/`; none are
estimated or reconstructed from memory.

## What this project has not shown (scope, stated plainly)

- **No genuine "Claude Code" agentic comparison exists.** The one
  attempt silently fell back to Ollama due to an expired CLI OAuth
  session and is correctly filed as an Ollama result
  (`docs/RESULTS_BY_ACCESS_METHOD.md` category 2). The frozen protocol
  in `docs/CLAUDE_CODE_COMPARISON_PROTOCOL.md` remains valid and
  unexecuted.
- **No new CVE class, platform, or full-core-network deployment** was
  added in this pass - free5GC and OpenEMR remain the two real-upstream
  cases; the 6-CVE catalogue remains supporting, template-reproduction
  evidence, not primary evidence.
- **No fuzzing claim is made anywhere** - this project's own framing
  note (`docs/CRS_MAPPING.md`) already states the original "fuzzing
  LLMs to secure OSS" pitch was dropped; nothing in this evidence pass
  reopens it.
- **Dollar cost is not uniformly available.** `claude -p` reports a
  real billed figure (**$29.53** total, per `docs/RESULTS_SUMMARY.md`);
  the OpenAI API reports a real estimated figure where a published
  rate is known (~**$0.42** total across the catalogue and the three
  OpenEMR/free5GC reruns); the AIxTech gateway reports token counts but
  genuinely no dollar figure, and none was guessed for its 2026-era
  model names with no verifiable published price
  (`docs/METHODOLOGY_PITFALLS.md` #15).

## Reading this against the other two indexes

Use `docs/RESULTS_SUMMARY.md` for "what happened in experiment X, with
full method and raw-data links." Use `docs/RESULTS_BY_ACCESS_METHOD.md`
for "what has this project measured through access path Y." Use this
page for "what can this project actually claim, and what is explicitly
still open" - the two sentences a defense or a supervisor briefing
needs first.


XSS bypass columns use `browser_genuine_bypass` from the independent replay, not the legacy marker oracle.


The final targeted repeatability update recorded the OpenAI API key failure as an authentication/environment limitation rather than a model result. Claude and AIxTech prompt/cache sensitivity completed with unique-marker variants; see `docs/FREE5GC_PROMPT_CACHE_SENSITIVITY_RESULTS.md`.
