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
from pathlib import Path


def _extract_marker(text: str, start: str, end: str) -> str:
    i = text.find(start)
    j = text.find(end)
    if i == -1 or j == -1 or j < i:
        return ""
    return text[i + len(start):j].strip()


def _llm_generate_patch(vuln_class: str, root_cause: str, fix_summary: str,
                         target_text: str):
    """Ask a live model to patch the vulnerable target's handler. Returns
    (patched_source, one_line_summary, LiveModelResult) or None if
    unavailable/unparseable - never raises, mirroring every other AI-optional
    path in this pipeline. Uses the same provider-agnostic backend as Stage
    3.5 (Claude CLI first, local Ollama fallback), not just the Claude CLI.
    The LiveModelResult carries this call's real duration/tokens/cost."""
    from cve_pipeline import _call_live_model, _live_model_available
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
        artifacts.patch_validated = False
        artifacts.patch_validation_log = (
            f"patched target failed the /health regression check: "
            f"{shadow.execution_skip_reason or 'did not execute'}"
        )
        log.info("[Stage 3.8] Patch REJECTED (health check failed): %s",
                  artifacts.patch_validation_log)
        return artifacts

    # exit_code convention (documented in every generated poc.py): 0 means
    # the exploit succeeded. Against a validated patch it must NOT succeed.
    artifacts.patch_validated = (shadow.dynamically_confirmed is False)
    artifacts.patch_validation_log = shadow.execution_log
    log.info("[Stage 3.8] Patch %s (original exploit exit_code=%s against patched target)",
              "VALIDATED" if artifacts.patch_validated else
              "REJECTED - exploit still succeeded against the patch",
              shadow.exit_code)
    return artifacts
