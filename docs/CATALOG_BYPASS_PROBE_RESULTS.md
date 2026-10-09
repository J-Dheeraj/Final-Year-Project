# Main-catalogue bypass-probe: do the 6-CVE catalogue's own patches hold?

## Why this experiment exists

The bypass-probe idea (ask a model to find a way past a real,
already-validated fix, then actually execute the proposal) had only
ever been run against free5GC and OpenEMR's real upstream fixes. The
main pipeline's own 6-CVE catalogue (`reports/CVE_CATALOG.md`) has
its own already-generated, already-validated patched targets
(`target_app.iter1.v0.patched.py` per CVE, from
`reports/claude_code_catalog_run_2026-09-25/`) that had never been
adversarially probed this way.

## Method

For each of the 6 catalogue CVEs, 8 local Ollama models are given the
patched target's COMPLETE, real source code (not an abstract
description - a step further than the free5GC/OpenEMR probes, since
each target app is small enough, ~40-130 lines, to pass in full) and
asked to propose ONE HTTP request that might still trigger the
original vulnerability. Each proposal is executed for real against the
live Flask process. The oracle reuses each CVE's own already-
established `poc.iter1.v0.py`'s `verify()` logic unchanged:
`MARKER in response.text`, where `MARKER` is a secret string each
target app only emits when the specific unsafe behavior genuinely
still fires (confirmed per-CVE by reading each app's own source before
trusting this oracle generically - see the XSS case below for why this
mattered).

## A false-positive bypass found, verified, and explained before being reported

The raw run reported 1/48 (CVE, model) pairs as a confirmed bypass:
`gemma2:9b` against CVE-2026-46492 (XSS), proposing
`<img src=x onerror=alert(1)>` as the `content` field. The response did
contain the MARKER - but inspecting the actual response body before
trusting this showed the escaped text
`&lt;img src=x onerror=alert(1)&gt;&lt;img&gt;` - correctly
HTML-escaped, inert, not live executable HTML. The MARKER appeared
anyway because of a real, pre-existing bug in the target app's OWN
self-check regex (`_EXEC_HTML = re.compile(r"<script\b|\son\w+\s*=|javascript:")`):
the `\son\w+\s*=` alternative matches the literal substring ` onerror=`
anywhere in the rendered text, escaped or not - HTML-escaping only
neutralizes `<`/`>`, not the attribute-name text inside what used to
be a tag, so an escaped ` onerror=` still matches this regex even
though it can never execute as JavaScript.

**This is not a retroactive invalidation of the already-published
CVE-2026-46492 result.** The original `poc.iter1.v0.py`'s own default
payload is `<script>alert(document.domain)</script>`, which only
exercises the regex's FIRST alternative (`<script\b`) - after escaping,
that becomes `&lt;script`, which does not match `<script\b` (no literal
`<` immediately before `script`). The original validation never tried
an event-handler-attribute payload, so it never hit this latent bug.
This adversarial probe found a genuinely new edge the original
author's single payload choice never exercised - exactly what an
adversarial probe is for, just surfacing a test-oracle defect rather
than a real application defect this time. Reclassified from the
already-captured response data (no new model call needed), matching
this project's established remediation pattern for this bug class.

## Results

| CVE | Class | Parsed proposals | Genuine bypasses |
|---|---|---|---|
| CVE-2026-42208 (litellm, SQLi) | SQL Injection | 7/8 | 0 |
| CVE-2026-27602 (modoboa, CMDi) | OS Command Injection | 7/8 | 0 |
| CVE-2026-78683 (nltk, deser.) | Insecure Deserialization | 4/8 | 0 |
| CVE-2026-46492 (md-fileserver, XSS) | XSS | 6/8 | 0 (1 false positive caught, see above) |
| CVE-2026-23949 (jaraco.context, path traversal) | Path Traversal | 6/8 | 0 |
| CVE-2026-54729 (dssrf, SSRF) | SSRF | 7/8 | 0 |

**0/48 genuine bypasses** across all 6 catalogue CVEs. `deepseek-coder-v2:16b`
failed identically on every CVE (OOM at Ollama startup - the same
recurring hardware constraint noted in every free5GC/OpenEMR sweep, not
a new finding). The remaining parse failures (`gemma2:9b` and
`qwen2.5-coder:3b/1.5b` on the deserialization CVE, `mistral:7b` on
XSS, `gemma2:9b` on path traversal) are models that didn't return
parseable JSON when given a full source file in-context - a longer,
more complex prompt than free5GC/OpenEMR's abstract-description style
bypass-probes, plausibly harder for smaller models to follow strictly.

## Honest interpretation

All 6 of this catalogue's own already-validated patches held against
every model that completed a genuine attempt - a third independent
confirmation (after free5GC and OpenEMR) that this project's real
upstream/validated fixes don't fall to request-level LLM-proposed
tricks. The one apparent exception traced to a test-oracle bug, not an
application bug, which is itself a useful, concrete illustration of
why this project insists on checking raw evidence before reporting a
result rather than trusting an aggregate pass/fail number - the same
discipline already applied (and already paid off) earlier this session
for free5GC's bypass-probe classifier.

## Update: Claude backend (6 named models, all 6 CVEs)

Re-run against the same 6 named Claude models, all 6 CVEs (36 total
pairs). A one-CVE smoke test ($1.21) was run first to estimate real
cost before committing to the full sweep, per this project's own
cost-transparency practice.

**A second false-positive cluster, same bug class as before - this time
self-diagnosed by the models themselves.** 3 of 36 pairs initially
reported a confirmed bypass, all against the same XSS CVE
(CVE-2026-46492) and the same already-documented `_EXEC_HTML` oracle
regex bug. Unlike the earlier Ollama false positive, each Claude
model's own `reasoning` field explicitly named the oracle flaw
(`claude-opus-4-8`: "exposing a detector false-positive rather than
genuine script execution") - the models correctly predicted their own
"bypass" wasn't real, and said so, while still technically triggering
the bug. Verified via the response bodies (properly escaped, no live
HTML) and reclassified from already-captured data, no new calls.

**Corrected result: 0/36.** `claude-sonnet-5` failed on every CVE,
consistently; one timeout occurred on a longer prompt
(`claude-sonnet-4-6` on the deserialization CVE).

Total measured cost: **$8.5028** for the full 6x6 sweep (plus $1.2081
for the earlier one-CVE smoke test, which re-tested CVE-2026-42208 and
is not double-counted as a separate finding).

## Scope, stated plainly

- Single run per (CVE, model) pair - not repeated for variance.
- Only Ollama (free) models; no Claude/paid-backend run for this probe.
- SSRF (CVE-2026-54729) was included despite `CVE_CATALOG.md`'s noted
  "unreachable network" limitation for the ORIGINAL exploit - that
  limitation was about reaching a real link-local address end-to-end,
  not about this probe's propose-and-execute mechanism against the
  app's own Flask routes, and it did not recur here.
- The `_EXEC_HTML` regex bug found is NOT fixed in this pass (the
  archived catalog run's files were left as historical artifacts,
  consistent with how this project treats prior results); noting its
  existence here is the deliverable, not a silent rewrite of someone
  else's already-published test.

## Update: AIxTech gateway backend (10 named models, all 6 CVEs)

Re-run via `--backend aixtech` (the AI Singapore LLM gateway added
2026-10-09) against the user's 10 requested model names, all 6 CVEs (60
total pairs). The gateway's per-key model allowlist is narrower than
`claude -p`'s: only 4 of the 10 resolve at all (`claude-haiku-4-5-20251001`,
`claude-haiku-5-5`, `claude-sonnet-4-6`, `claude-sonnet-5`); the other 6
(`claude-sonnet-5-5` and all 5 `claude-opus-*` entries) return a 403
`team_model_access_denied` on every CVE, recorded as an error per
pair rather than silently skipped - consistent with how this project
recorded the Codex sweep's environment-limited model IDs.

**A third occurrence of the same already-documented `_EXEC_HTML`
oracle bug** (first: `gemma2:9b` via Ollama; second: a 3-model cluster
via `claude -p`) - `claude-haiku-5-5` on CVE-2026-46492 (XSS) initially
reported a confirmed bypass. Its own `reasoning` field, like the
`claude -p` models before it, named the flaw directly: *"No request
should produce real XSS because every character is HTML-escaped, so
this only trips the marker's regex on the inert text ' onerror=' (a
false positive, not an executable injection)."* The response body
confirms this - `<p> onerror=alert(1)</p>` is literal, HTML-escaped
text, not an executing tag. Reclassified from already-captured data,
no new calls.

**Corrected result: 0/60 genuine bypasses.** Of the 4 reachable
models, `claude-sonnet-5` failed to return parseable JSON on 5 of its 6
CVEs (only CVE-2026-42208 parsed); the other 3 reachable models parsed
cleanly across all 6 CVEs.

Total measured cost: **not reported by this gateway** (see
`docs/METHODOLOGY_PITFALLS.md` #15's note on `AIxTechGatewayProvider`'s
`billing_basis` - token counts are captured per call, no dollar figure
is returned by this provider).

## Artifacts

- `catalog_bypass_probe.py`
- `reports/reachability/catalog_bypass_probe.json/.md`
