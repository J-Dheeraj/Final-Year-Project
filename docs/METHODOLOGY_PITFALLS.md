
# Methodology pitfalls: real bugs found while building this project's own evidence

This project's standing discipline has been to check real evidence
before reporting a result, rather than trusting an aggregate pass/fail
number or an LLM's own claim. That discipline only has value if the
pitfalls it caught are written down - this document is that record,
spanning this session's "do everything" enhancement pass and the
handful of earlier, equally real findings worth keeping alongside them.
Every entry here is a genuine bug that was caught BEFORE being
reported, not a hypothetical risk - each one changed what this project
would otherwise have claimed.

## From this session

1. **A CRLF/LF mismatch silently corrupted a memorization-control
   experiment's first result.** Writing the synthetic vulnerable case
   file with Python's default text-mode translation turned `\n` into
   `\r\n` on Windows; the reachability pipeline's tree-sitter parser
   then read the file back byte-for-byte with `\r\n` intact, so the
   in-memory function-body text handed to the patcher no longer
   byte-matched the `\n`-only strings used to splice into the real
   upstream clone - producing a uniform "patch doesn't match" failure
   for every model that looked, at first glance, like a real 0/4
   result. Caught by comparing the pipeline's own extracted text
   against the in-memory string directly (`p.original == injected_func`)
   before trusting a single model call. Fixed with `newline="\n"` on
   the one write that mattered. See `docs/FREE5GC_MEMORIZATION_CONTROL_RESULTS.md`.

2. **A weaker model's malformed field crashed an entire sweep.**
   `llama3.2:1b` returned `"headers": "<some string>"` instead of a
   JSON object on its third multi-run attempt; `proposal.get("headers")
   or {}` doesn't catch a non-empty string (truthy), so the string
   reached `requests.get(headers=...)` and threw deep inside the
   `requests` library's own header-preparation code, taking the whole
   sweep down with it - a crash the stronger 8-model sweeps never
   happened to trigger, only surfaced by testing a model weak enough to
   produce a malformed shape. Fixed with an `isinstance(headers, dict)`
   check. See `docs/FREE5GC_MULTI_RUN_VARIANCE_RESULTS.md`.

3. **The SAME classifier bug class recurred in a new shape, immediately
   after being "fixed."** The free5GC bypass-probe's `_is_genuine_trick`
   check (added earlier to stop re-encoded-but-identical paths from
   counting as bypasses) still missed appending an inert, server-ignored
   query string to the exact correct path - which would have been
   reported as "first confirmed bypass in this project's history" had
   the raw request/response not been read before trusting the
   `bypass_confirmed: true` flag. One class of bug, two independent
   near-misses, caught by the same discipline both times: never trust
   the boolean, read the actual HTTP exchange. See the same doc as #2.

4. **A second, hidden authorization layer, invisible with the feature
   it depends on turned off.** Enabling real OAuth2 on free5GC's NRF
   for the first time (every prior result ran with it explicitly
   disabled) revealed that the PUT handler calls a SEPARATE live
   `GetNFInstance` lookup against the NRF to resolve the caller's
   claimed identity for notification-callback purposes - code that is
   a complete no-op, and therefore invisible, whenever
   `OAuth2Required` is false. A synthetic token with a made-up `sub`
   passed the primary `VerifyOAuth()` check but still got rejected
   here, which looked at first like the whole OAuth2 experiment was
   broken rather than working correctly. Fixed by using a real,
   currently-registered NF instance ID. The broader lesson: a
   feature-flagged code path can hide an entire second security
   mechanism that no test with the flag off will ever exercise. See
   `docs/FREE5GC_OAUTH2_ENFORCEMENT_RESULTS.md`.

5. **Three distinct, real logic bugs in LLM-generated security code,
   found only by running it.** Extending the patch-generation
   experiment to OpenEMR surfaced a wider variety of failure modes than
   free5GC's equivalent ever had: a missing `isset()` guard that
   silently corrupted the HTTP status code via PHP's "headers already
   sent" rule while still (by accident) blocking the real disclosure;
   a swapped boolean operator (`OR` instead of `AND` of two negations)
   that failed safe but broke the legitimate path; and, most seriously,
   **completely inverted logic** (`if (enabled) { deny }`) that left
   the real vulnerability fully open while LOOKING correct under a
   superficial opt-in-only test. None of these would have been caught
   by reading the diff alone - only running both branches (default
   AND opt-in) against a real server exposed them. See
   `docs/OPENEMR_LLM_PATCH_RESULTS.md`.

6. **A false-positive bypass traced to a bug in someone else's already-
   published test oracle, not a real vulnerability.** The main
   catalogue's bypass-probe reported a confirmed XSS bypass; the actual
   response showed correctly HTML-escaped, inert text. The target
   app's OWN `_EXEC_HTML` detection regex (`\son\w+\s*=`) matches the
   literal substring ` onerror=` whether or not it's inside real,
   executable HTML - escaping neutralizes `<`/`>` but not attribute-
   name text, so an escaped payload still tripped the self-check.
   Confirmed this was a genuinely NEW finding (the original author's
   own `poc.py` only ever tried a `<script>`-tag payload, which a
   different regex branch correctly handles), not a retroactive
   invalidation of an already-published result. See
   `docs/CATALOG_BYPASS_PROBE_RESULTS.md`.

7. **An alarming-looking pattern that, on investigation, was not a
   bug.** Scoring patch quality found 9 of 14 already-generated free5GC
   patches were byte-identical to each other in two clusters - 6
   different Claude model names producing the exact same output was
   the kind of pattern that, in a less narrow task, would suggest
   several model names secretly resolving to one underlying model (a
   real, previously-documented risk in this exact project). Checked
   against each model's own already-recorded, genuinely distinct API
   cost before concluding otherwise: the task was narrow enough (one
   short function, one obviously-correct one-line fix) that real,
   independent convergence is the better-supported explanation.
   Recorded as a probability judgment, not a certainty. See
   `docs/PATCH_QUALITY_SCORING_RESULTS.md`.

8. **The same classifier bug class recurred a THIRD time, again in a
   new shape, this time against stronger models.** Re-running the
   multi-turn bypass-probe against 6 Claude models reported 3/6 found a
   genuine bypass - the first time any bypass-probe in this project
   reported more than a single-digit count. All 3 were the exact
   correct, legitimate path disguised two new ways: a trailing slash
   and a `..`-segment traversal, both of which Gin/Go's net-http
   normalize away before routing but which `_is_genuine_trick()` still
   compared as literally-different strings. Fixed with
   `posixpath.normpath()`; before trusting the fix, re-scanned every
   other free5GC bypass-probe report from the entire session for the
   same gap - found none, confirming the fix was scoped correctly.
   Three real bugs in the same ~15-line function, each caught by
   reading the raw request/response before trusting the boolean, never
   by assuming the previous fix was complete.

9. **A local plugin's own outage notice silently corrupted a model's
   code output.** One Claude model's "patch" failed to compile; the
   actual diff showed a `<system-reminder>` block about a `claude-mem`
   memory-observer outage, injected unfenced directly into the
   completion text the project's own cleanup logic parses as code.
   Confirmed isolated to this one call by checking every other model's
   diff for the same contamination string. Not a model capability
   failure - a local environment artifact that happened to land inside
   a code-generation response this one time.

## From earlier in this project (kept for the same reason)

8. **A WSL/Ollama port-forwarding gap** that made `OllamaProvider`
   unreachable from a process on the wrong side of the WSL2/Windows
   boundary - not a bug in the model, a networking assumption that
   silently failed until explicitly checked.

9. **A markdown-commentary-corrupting-patch bug** in `generate_patch()`:
   an LLM's response sometimes included trailing prose after a fenced
   code block, or no fence at all, corrupting the target file when
   spliced in verbatim. Fixed in two stages (fence-extraction, then a
   fence-independent closing-brace truncation), because the first fix
   covered only the common case.

10. **The original free5GC bypass-probe classifier bug** (predecessor
    to #3 above): the first version had no genuine-trick check at all,
    crediting 3 models with "bypasses" that were actually re-encoded
    copies of the exact legitimate request.

11. **Anthropic's own real-time cyber safeguards refusing the patch-
    generation prompt** for `claude-sonnet-5` (and, separately, two
    models outright refusing the bypass-probe's exploit-proposal
    prompt) - not a bug in this project's harness, but a real, billed,
    externally-imposed constraint that had to be reported honestly
    rather than silently retried or omitted.

## What these pitfalls have in common

Every one of these was caught by the same small set of habits, applied
repeatedly rather than invented fresh each time: read the raw
request/response or file content before trusting a boolean; verify a
sanity check (does the control's "clean" baseline actually look clean,
does the injected version actually get flagged) before running the
real experiment; check a surprising pattern against independent
evidence (cost data, a second test, the original source) rather than
either dismissing it or over-reacting to it; and distinguish a genuinely
new finding from a stale or already-superseded one before writing
anything down. None of these are exotic techniques - they are "look at
the actual data" repeated with discipline, which is precisely why they
keep working across completely different domains (Go, PHP, Python,
Docker networking, LLM provider APIs) and completely different kinds
of bug (encoding mismatches, logic inversions, test-oracle defects,
false alarms that weren't bugs at all).
