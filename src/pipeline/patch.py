"""Stage 3.8 - patch generation & validation.

Stages 3.5-3.7 together only ever produce a CONFIRMED VULNERABILITY - never
a fix. This stage closes that gap: given a dynamically-confirmed exploit,
ask an LLM to patch the vulnerable handler in target_app.py, then trust the
result only if re-running against the patched target proves BOTH that the
original exploit now fails (the vuln is actually closed, not just moved)
and that /health still passes (the patch didn't just break the app). This
mirrors OSS-CRS's own apply-patch-build / run-pov / run-test validation
cycle, and reuses cve_pipeline's own execute_exploit_artifacts() rather
than reimplementing subprocess/health-check logic - same battle-tested
path Stage 3.6 already uses, pointed at a different (patched) target file.

Function-local imports back into cve_pipeline (not top-of-file) for the
same reason as src/pipeline/self_improve.py: cve_pipeline.py imports
generate_and_validate_patch from here, so a module-level import the other
direction would be circular.
"""
import re
from pathlib import Path

# Corrected validator (2026-09-25). The original check below (exploit fails,
# /health passes) cannot distinguish a deliberate rejection from an unrelated
# crash in the patched handler: CVE-2026-78683 round 5's patch crashed with
# `NameError: name 'io' is not defined` on every request, which still made
# the exploit "fail" and left /health (a DIFFERENT route) reporting 200 -
# satisfying the old check while fixing nothing. See
# docs/PATCH_VALIDATION_INVESTIGATION.md and the FYP report's Section 4.1.2
# for the full trace. This block adds two further, independent checks:
# (1) did the exploit request itself fail cleanly, without an unhandled
# exception, and (2) does a benign, non-malicious request to the SAME route
# still succeed. Both use the crash-signature heuristic below, since none of
# this pipeline's generated targets expose a structured way to distinguish
# "the security check rejected this" from "the handler crashed" other than
# the presence of an unhandled Python traceback in the process's own log.
_CRASH_SIGNATURE_RE = re.compile(
    r"Traceback \(most recent call last\)|Exception on .* \[", re.IGNORECASE
)
_BENIGN_PROBE_PAYLOAD = "benign-legitimate-request-2026-not-an-attack-payload"


def _response_shows_crash(execution_log: str) -> bool:
    """True if the target process's own log contains an unhandled Python
    exception (a crash), as opposed to a clean HTTP-level rejection. This is
    a heuristic over stdout/stderr text, not a structured signal - the best
    available without changing every generated target's own error handling."""
    return bool(_CRASH_SIGNATURE_RE.search(execution_log or ""))


def _llm_generate_patch(vuln_class: str, root_cause: str, fix_summary: str,
                         target_text: str):
    """Ask a live model to patch the vulnerable target's handler. Returns
    (patched_source, one_line_summary, LiveModelResult) or None if
    unavailable/unparseable - never raises, mirroring every other AI-optional
    path in this pipeline. Uses the same provider-agnostic backend as Stage
    3.5 (Claude CLI first, local Ollama fallback), not just the Claude CLI.
    The LiveModelResult carries this call's real duration/tokens/cost."""
    from cve_pipeline import _call_live_model, _live_model_available, _extract_marker
    if not _live_model_available():
        return None
    prompt = f"""\
Below is a minimal Flask app that deliberately reproduces a real
{vuln_class} vulnerability (CVE root cause: {root_cause[:300] or 'see class'}).
Advisory's own fix summary: {fix_summary[:300] or '(none provided)'}

Current target_app.py:
```python
{target_text}
```

Patch ONLY the vulnerable logic so the {vuln_class} exploit against it no
longer works. Keep the /health endpoint, the Flask app structure, and the
port unchanged - fix the security bug, don't redesign the app. Preserve
every route path and method exactly as they are; only change what's needed
to close the vulnerability (input validation, parameterized queries, safe
deserialization, path canonicalization, output escaping, etc. - whatever
actually applies to this vuln class).

CRITICAL: output the COMPLETE file, including the exact
`if __name__ == "__main__": app.run(port=5000, debug=False)` block at the
end, unchanged from the original. Do not truncate the file after the
routes — a patch missing the run block starts no server at all, which
looks like an unrelated crash rather than a missing startup block.

Output EXACTLY two sections, no markdown fences, no commentary outside them:

===PATCHED_TARGET_START===
(complete patched target_app.py)
===PATCHED_TARGET_END===

===SUMMARY_START===
(one sentence describing the fix)
===SUMMARY_END===
"""
    gen_call = _call_live_model(prompt, timeout=180)
    if not gen_call.text:
        return None
    patched = _extract_marker(gen_call.text, "===PATCHED_TARGET_START===", "===PATCHED_TARGET_END===")
    summary = _extract_marker(gen_call.text, "===SUMMARY_START===", "===SUMMARY_END===")
    if not patched:
        return None
    return patched, (summary or "LLM-generated patch (no summary returned)"), gen_call


def generate_and_validate_patch(artifacts: "ExploitArtifacts", vuln_class: str,
                                 root_cause: str = "", fix_summary: str = "") -> "ExploitArtifacts":
    from cve_pipeline import ExploitArtifacts, execute_exploit_artifacts, log

    if not artifacts.dynamically_confirmed:
        artifacts.patch_skip_reason = (
            "exploit was not dynamically confirmed - nothing proven to patch"
        )
        return artifacts

    target_path = Path(artifacts.target_app_path).resolve()
    if not target_path.exists():
        artifacts.patch_skip_reason = "target_app.py not found on disk"
        return artifacts

    result = _llm_generate_patch(
        vuln_class, root_cause, fix_summary,
        target_path.read_text(encoding="utf-8"),
    )
    if result is None:
        artifacts.patch_skip_reason = (
            "no AI backend available to generate a patch, or the response "
            "didn't parse"
        )
        return artifacts

    patched_source, summary, gen_call = result
    patched_path = target_path.with_name(target_path.stem + ".patched.py")
    patched_path.write_text(patched_source, encoding="utf-8")

    artifacts.patch_attempted = True
    artifacts.patched_target_path = str(patched_path)
    artifacts.patch_summary = summary
    artifacts.patch_gen_duration_s    = gen_call.duration_s
    artifacts.patch_gen_input_tokens  = gen_call.input_tokens
    artifacts.patch_gen_output_tokens = gen_call.output_tokens
    artifacts.patch_gen_cost_usd      = gen_call.cost_usd

    # Reuse Stage 3.6's own execution logic against a throwaway artifacts
    # object: same poc.py (unmodified - it must now FAIL), pointed at the
    # PATCHED target instead of the vulnerable one.
    shadow = ExploitArtifacts(
        generated=True,
        poc_path=artifacts.poc_path,
        target_app_path=str(patched_path),
        vuln_class=vuln_class,
    )
    shadow = execute_exploit_artifacts(shadow)

    if not shadow.executed or shadow.execution_skip_reason:
        # shadow.execution_log carries the patched process's own real
        # stdout/stderr (its actual traceback, if it crashed) - previously
        # discarded here, leaving only the generic "never became healthy"
        # summary with no way to see WHY every crash-type rejection happened.
        artifacts.patch_validated = False
        artifacts.patch_validation_log = (
            f"patched target failed the /health regression check: "
            f"{shadow.execution_skip_reason or 'did not execute'}\n\n"
            f"{shadow.execution_log}"
        ).rstrip()
        log.info("[Stage 3.8] Patch REJECTED (health check failed): %s",
                  shadow.execution_skip_reason or 'did not execute')
        return artifacts

    # exit_code convention (documented in every generated poc.py): 0 means
    # the exploit succeeded. Against a validated patch it must NOT succeed.
    artifacts.patch_validated = (shadow.dynamically_confirmed is False)
    artifacts.patch_validation_log = shadow.execution_log
    log.info("[Stage 3.8] Patch %s (original exploit exit_code=%s against patched target)",
              "VALIDATED" if artifacts.patch_validated else
              "REJECTED - exploit still succeeded against the patch",
              shadow.exit_code)

    # Defeating the ONE payload the original PoC happens to use is not proof
    # the vulnerability class is closed - a patch that just blocklists that
    # literal string would pass the check above while remaining trivially
    # bypassable. Re-probe with every alternate payload the generation stage
    # produced for this same vulnerability class (a fresh target process per
    # payload, same poc.py, same patched file); ALL must also fail for the
    # patch to stand. The first payload that still succeeds overrides
    # patch_validated back to False, with which payload proved it in the log.
    if artifacts.patch_validated and artifacts.payload_variants:
        for variant in artifacts.payload_variants:
            probe = ExploitArtifacts(
                generated=True,
                poc_path=artifacts.poc_path,
                target_app_path=str(patched_path),
                vuln_class=vuln_class,
            )
            probe = execute_exploit_artifacts(probe, extra_arg=variant)
            bypassed = bool(probe.executed and not probe.execution_skip_reason
                            and probe.dynamically_confirmed)
            log.info("[Stage 3.8] Multi-payload re-probe %r: %s",
                      variant, "BYPASSED patch" if bypassed else "still blocked")
            if bypassed:
                artifacts.patch_validated = False
                artifacts.patch_validation_log = (
                    f"Patch defeated the original PoC's payload but was "
                    f"BYPASSED by an alternate payload for the same "
                    f"{vuln_class} class: {variant!r}\n\n{probe.execution_log}"
                )
                break

    # --- Corrected validator: exploit-blocked, function-preserved, verdict ---
    # Uses the FINAL state of patch_validated above (after the multi-payload
    # re-probe, if any), so a patch bypassed by an alternate payload is
    # correctly treated as not blocked here too.
    exploit_crashed = bool(artifacts.patch_validated) and _response_shows_crash(shadow.execution_log)
    artifacts.patch_exploit_blocked = bool(artifacts.patch_validated) and not exploit_crashed

    if artifacts.patch_exploit_blocked:
        # The exploit failed cleanly. Now probe the SAME route with a
        # benign, non-malicious request to confirm the patch didn't just
        # break legitimate use of it (round 5's crash-on-every-request bug
        # would fail this check too, independently of the crash check above).
        benign_probe = ExploitArtifacts(
            generated=True,
            poc_path=artifacts.poc_path,
            target_app_path=str(patched_path),
            vuln_class=vuln_class,
        )
        benign_probe = execute_exploit_artifacts(benign_probe, extra_arg=_BENIGN_PROBE_PAYLOAD)
        benign_ran = bool(benign_probe.executed and not benign_probe.execution_skip_reason)
        benign_crashed = _response_shows_crash(benign_probe.execution_log)
        artifacts.patch_function_preserved = benign_ran and not benign_crashed
        artifacts.patch_benign_probe_log = benign_probe.execution_log
    else:
        artifacts.patch_function_preserved = None  # not applicable - exploit wasn't cleanly blocked

    if exploit_crashed:
        artifacts.patch_verdict = "inconclusive_crash"
    elif not artifacts.patch_validated:
        artifacts.patch_verdict = "not_blocked"
    elif artifacts.patch_function_preserved:
        artifacts.patch_verdict = "confirmed_fix"
    else:
        artifacts.patch_verdict = "regression_broke_route"

    log.info(
        "[Stage 3.8] Corrected verdict: %s (exploit_blocked=%s, function_preserved=%s)",
        artifacts.patch_verdict, artifacts.patch_exploit_blocked, artifacts.patch_function_preserved,
    )

    return artifacts
