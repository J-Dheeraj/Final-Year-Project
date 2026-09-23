# Patch validation investigation — 2026-09-23

Triggered by direct challenge: *"to validate a patch you have to try and
probe the patch"*, then *"if you can potentially bypass them, that means
the patch is not good."* Both led to real, substantive findings. This
supersedes the "0/48 patch validated" framing in
`MULTI_MODEL_COMPARISON.md` and `LIVE_LLM_CATALOG_RUN.md` — read this
file for the corrected picture.

## What was already true (verified, not assumed)

`generate_and_validate_patch` (`src/pipeline/patch.py`) already **did**
probe the patch: start the patched target as a real subprocess, re-run the
unmodified `poc.py` against it, require both `/health` to pass and the
original exploit to now fail. Not a static or LLM self-report check.

## Bugs found while probing why every attempt failed

1. **Markdown fence (all 17 patch attempts in the prior comparison
   crashed on this).** The model wraps its patch in a ```` ```python ````
   fence despite "no markdown fences" already being in the prompt
   (primed by the prompt showing the *original* code fenced as context).
   Written literally into the `.py` file → immediate `SyntaxError`. Fixed:
   `_extract_marker` (shared by Stage 3.5 and Stage 3.8) now defensively
   strips a wrapping fence via `_strip_markdown_fence()`.
2. **Missing `app.run()`.** Once the fence was stripped, the next crash
   was a patch that omitted the Flask startup block entirely — process
   exits silently, no server, no traceback, looks like an unrelated
   crash. Fixed with an explicit prompt rule requiring the complete file
   including the unchanged `app.run(port=5000, debug=False)` block.
3. **Discarded diagnostic.** `patch_validation_log` only ever kept the
   generic "never became healthy" message — the patched process's real
   stdout/stderr (the actual traceback) was captured internally then
   thrown away. Neither bug above could have been diagnosed without
   fixing this first. Now included.
4. **`localhost` resolves to two different services on this machine.**
   `netstat` showed `ollama.exe` (this project's 8 pulled models) on
   IPv4 `127.0.0.1:11434`, and an unrelated pre-existing process on IPv6
   `[::1]:11434` with a completely different model set. `_ollama_available()`
   silently flipped True/False call to call depending on which one
   `localhost` resolved to. `OLLAMA_HOST` now defaults to `127.0.0.1`
   explicitly. Found via `netstat -ano`, not guessed.

## The actual ask: single-payload validation is not proof

Defeating the *one* payload the original PoC happens to use does not
prove the vulnerability class is closed — a patch that just blocklists
that literal string would pass the old check while remaining trivially
bypassable. Built and verified:

- Stage 3.5's prompt now also requests 2 additional, structurally
  distinct payloads for the same vulnerability class
  (`ExploitArtifacts.payload_variants`).
- `poc.py`'s generation contract now requires
  `exploit(host, port, payload=None)` to accept an override, and `main()`
  to read it from an optional `sys.argv[2]`.
- `execute_exploit_artifacts` gained an optional `extra_arg` parameter to
  pass a payload override through to a running probe.
- Stage 3.8 re-probes a would-be-validated patch with every alternate
  payload; **all** must also fail for `patch_validated` to stand. The
  first payload that still succeeds overrides it back to `False`.

**Verified with a controlled synthetic test (no Ollama calls needed):** a
deliberately narrow "patch" that blocklists only the literal default
payload passed the old single-payload check (`patch_validated=True`) but
was correctly caught and rejected once a structurally different payload
was tried (`patch_validated=False`) — exactly the failure mode this exists
to catch.

## The full clean re-test (all fixes applied, 8 models x 6 CVEs = 48 runs)

Ran after all four bugs above were fixed, `OLLAMA_HOST` explicit, sampling
still pinned. Canonical `reports/<CVE-ID>/` folders verified untouched.

| Model | Confirmed | Patch attempted | Patch validated | Time (s) | Tokens in/out |
|---|---|---|---|---|---|
| qwen2.5-coder:1.5b | 5/6 | 5/6 | 3/6 | 2199.6 (see note) | 6716/3208 |
| qwen2.5-coder:3b | 1/6 | 1/6 | 0/6 | 221.9 | 8627/3320 |
| qwen2.5-coder:7b | 2/6 | 2/6 | 0/6 | 105.0 | 10733/4111 |
| llama3.1:8b | 0/6 | 0/6 | 0/6 | 85.8 | 9276/3278 |
| mistral:7b | 2/6 | 0/6 (see note) | 0/6 | 1530.7 | 8998/4010 |
| gemma2:9b | 0/6 | 0/6 | 0/6 | 199.3 | 9891/3743 |
| codellama:13b | 0/6 | 0/6 | 0/6 | 845.0 | 11032/4210 |
| deepseek-coder-v2:16b | 1/6 | 1/6 | 0/6 | 168.4 | 10912/4841 |
| **Total** | **11/48** | **9/48** | **3/48** | **5355.7** | **76185/30721** |

Total cost: $0.0000 (all local). Raw reports:
`reports/patch_validation_retest_2026-09-23/<model>/<CVE-ID>.json`.

**Note on qwen2.5-coder:1.5b's 2199.6s:** one call in this total took
1636.5s (27+ minutes) - a severe, unexplained outlier for the *smallest*
model in the comparison. `output_tokens` for that call is `None`.
Flagged, not investigated further given cost; not papered over with a
guessed cause.

**Note on mistral:7b's 0/6 patch attempts despite 2/6 confirmed:** even
with the `localhost` fix confirmed stable (3/3 direct checks), 2 of
mistral:7b's confirmed CVEs still show `patch_skip_reason: "no AI
backend available... or the response didn't parse"`. Since availability
is now verified stable, this is most likely the "didn't parse" half of
that message - a further, distinct parsing issue in mistral's patch
response, not yet diagnosed.

## The most important caveat: "3/48 validated" overstates confidence

**All 3 validated patches have `payload_variants: []`.** The smallest
model (1.5B) never successfully produced the alternate-payload section for
those specific cases, so the multi-payload safety check had nothing to
probe with and was skipped - not because it found the patches robust.
Read precisely: these 3 patches survived the *one* original payload and
were **never actually tested** against an alternate one. "Validated" here
means "unbypassed by the only payload tried," the same weaker claim the
whole multi-payload feature exists to move past - it just wasn't
exercised for these specific cases.

Separately, where payload_variants *were* produced, extraction quality is
inconsistent: one case (`CVE-2026-78683`) literally echoed the prompt's
placeholder instruction text back as a "payload" instead of replacing it
with a real one; another (`CVE-2026-46492`) left literal backtick
characters wrapping each payload string, unstripped. Neither is fabricated
data - both are shown exactly as extracted - but both mean the "payload"
tested in those specific cases wasn't a real, well-formed exploit attempt.
Not fixed here; noted as a further extraction-robustness gap.

## Bottom line

Four real bugs found and fixed (fence, missing run block, discarded
diagnostic, `localhost` ambiguity), each proven with direct evidence, not
assumed. The multi-payload validation mechanism is built and proven
correct on a controlled synthetic case. But the honest headline number
from this session is **not** "3/48 patches validated" - it's **"0/48
patches have been validated against more than their original payload."**
The mechanism to do that right now exists and works; getting models to
reliably produce well-formed alternate payloads to feed it is the next
real gap, not yet closed.
