"""Stage 3.7 - self-improvement: reflect on a failed exploit and retry.

Extracted from cve_pipeline.py as part of the repo's src/ refactor. Calls
back into cve_pipeline for the Claude helpers, ExploitArtifacts, and
execute_exploit_artifacts via function-local imports rather than a
top-of-file import - cve_pipeline.py imports refine_and_reexecute from
here, so a module-level "from cve_pipeline import ..." here would be a
circular import. Function-local imports resolve it cleanly because by
the time these functions are actually CALLED, cve_pipeline has finished
loading.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3.7 — Self-improvement: reflect on a failed exploit and retry
# ─────────────────────────────────────────────────────────────────────────────
#
# ExploitArtifacts.iterations and the "poc.iter1.v0.py" filename convention
# already anticipated this (an iteration number, a version number) but
# nothing ever looped - Stage 3.6 would report False and stop. When it
# genuinely DID run and genuinely did NOT reproduce the bug (not "couldn't
# test" - a real, informative failure), this stage:
#
#   1. Checks a persistent lessons store (.pipeline_lessons.json) for a fix
#      already learned for this vulnerability class + failure signature -
#      cheap, instant, no LLM call. This is the part that makes it
#      self-improving ACROSS runs, not just within one CVE's own retries:
#      a fix discovered while working on CVE A is immediately available
#      for CVE B of the same class hitting the same failure shape,
#      without re-diagnosing it from scratch.
#   2. Falls back to asking Claude to revise the artifacts given the
#      actual failure log, when an AI backend is available.
#   3. Falls back further to a small, honest, narrow set of built-in
#      revision rules for failure signatures this project has concretely
#      observed and verified - same "illustrative, not exhaustive" honesty
#      as every other non-LLM fallback in this pipeline. Right now that's
#      exactly one rule, discovered and verified empirically while
#      building this: the CMDi template's injected payload used ';' as a
#      command separator and a POSIX-only ping flag, both of which
#      silently fail on Windows (cmd.exe treats ';' as a literal character,
#      not a separator, and rejects '-c'); '&' works as a separator on
#      BOTH cmd.exe and POSIX sh, so the fix swaps to that plus an
#      'echo <marker>' payload whose output is identical on either OS.
#
# Patches are applied as targeted string replacements to the ALREADY-
# GENERATED source, not a full regeneration - the same minimal-diff
# philosophy as Stage 4's own patch generation. Stops at the first
# confirmed success or after max_iterations, whichever comes first; a
# newly-successful revision is written back to the lessons store.

_LESSONS_PATH = Path(".pipeline_lessons.json")


def _load_lessons() -> dict:
    if _LESSONS_PATH.exists():
        try:
            return json.loads(_LESSONS_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_lesson(vuln_class: str, signature: str, rule: dict) -> None:
    lessons = _load_lessons()
    lessons.setdefault(vuln_class, {})[signature] = {
        **rule, "learned_at": datetime.now(timezone.utc).isoformat(),
    }
    _LESSONS_PATH.write_text(json.dumps(lessons, indent=2), encoding="utf-8")


def _failure_signature(execution_log: str) -> str:
    """A short, stable key for WHY an attempt failed, so a future run can
    match on the reason rather than needing an exact string match against
    a log that also carries timestamps/ports/other run-specific noise."""
    text = (execution_log or "").lower()
    if "administrative privileges" in text or "option -c" in text:
        return "posix_only_shell_syntax"
    if "404" in text or "not found" in text:
        return "endpoint_not_found"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    return "generic_failure"


# Verified empirically (see this module's own test run against
# CVE-2026-27602/modoboa): on this Windows host, `ping -c 1 127.0.0.1; id`
# resolves "127.0.0.1;" as a literal (invalid) hostname - ';' is never a
# cmd.exe separator - while `ping -n 1 127.0.0.1 & echo MARKER` correctly
# runs both commands and captures MARKER in the output, on Windows AND
# POSIX sh alike.
_BUILTIN_REVISIONS: dict[str, dict] = {
    "posix_only_shell_syntax": {
        "description": (
            "the injected test command relied on POSIX-only shell syntax "
            "(';' as a separator, and/or a ping flag like '-c' that only "
            "POSIX ping accepts) - switched to '&' (a separator both "
            "cmd.exe and POSIX sh accept) and an 'echo <marker>' payload "
            "whose output is identical on either platform, instead of an "
            "OS-specific command like 'id' or a POSIX-only ping flag."
        ),
        "poc_patches": [
            ('"host": "127.0.0.1; id"',
             '"host": "127.0.0.1 & echo CMDI_PWNED_MARKER"'),
            ('"uid=" in r.text or "root" in r.text',
             '"CMDI_PWNED_MARKER" in r.text'),
        ],
        "target_patches": [],
    },
}


def _llm_revise_artifacts(vuln_class: str, poc_text: str, target_text: str,
                           execution_log: str) -> tuple[str, str] | None:
    """Ask Claude to diagnose why the generated exploit failed and rewrite
    both files to fix it. This is the path that lets Stage 3.7 handle a
    failure NOBODY anticipated - not just the ones already recognized by
    a failure-signature match and hand-coded into _BUILTIN_REVISIONS. The
    other two paths (lessons store, built-in rules) can only ever cover
    what a human already noticed and coded a fix for; this one can, in
    principle, cover anything the log itself makes diagnosable. Returns
    None (never raises) if no AI backend is available or the response
    doesn't parse - the caller falls back to reporting "no known
    revision" rather than pretending a fix was attempted."""
    from cve_pipeline import _call_claude, _claude_available, _extract_marker
    if not _claude_available():
        return None
    prompt = f"""\
You previously wrote a proof-of-concept exploit (poc.py) and a minimal
vulnerable target (target_app.py) for a {vuln_class} vulnerability. It did
NOT work - here is exactly what happened when it was run:

```
{execution_log[-2000:]}
```

Current poc.py:
```python
{poc_text}
```

Current target_app.py:
```python
{target_text}
```

Diagnose why the exploit failed from the execution log, then output BOTH
files again, corrected so the exploit actually succeeds against the
target's real vulnerability. Preserve the existing 4-phase pattern
(health/exploit/verify/exit 0-or-1) and the target's /health endpoint -
fix only what's needed to make the exploit succeed, don't redesign it.

Output EXACTLY two sections, no markdown fences, no commentary outside them:

===POC_START===
(complete corrected poc.py)
===POC_END===

===TARGET_START===
(complete corrected target_app.py)
===TARGET_END===
"""
    raw = _call_claude(prompt, timeout=180)
    if not raw:
        return None
    poc_code = _extract_marker(raw, "===POC_START===", "===POC_END===")
    target_code = _extract_marker(raw, "===TARGET_START===", "===TARGET_END===")
    if not poc_code or not target_code:
        return None
    return poc_code, target_code


def refine_and_reexecute(artifacts: "ExploitArtifacts", vuln_class: str,
                          max_iterations: int = 3) -> "ExploitArtifacts":
    from cve_pipeline import execute_exploit_artifacts, log
    if artifacts.dynamically_confirmed or not artifacts.executed:
        # Already confirmed - nothing to improve. Or never ran at all (no
        # compiler on PATH, target never became healthy) - a revised
        # PAYLOAD can't fix a structural unavailability, only a wrong
        # payload can be revised, so there is nothing productive to retry.
        return artifacts

    for iteration in range(1, max_iterations + 1):
        signature = _failure_signature(artifacts.execution_log)
        lessons = _load_lessons()
        known = (lessons.get(vuln_class) or {}).get(signature)
        rule = known or _BUILTIN_REVISIONS.get(signature)
        source = "lesson" if known else ("builtin" if rule else None)

        poc_path = Path(artifacts.poc_path)
        target_path = Path(artifacts.target_app_path)
        poc_text = poc_path.read_text(encoding="utf-8")
        target_text = target_path.read_text(encoding="utf-8")

        new_poc_text: str | None = None
        new_target_text: str | None = None

        if rule is not None:
            # Lesson or built-in rule: two shapes exist. Patch-based
            # (poc_patches/target_patches) is a targeted string
            # replacement, same minimal-diff philosophy as Stage 4's own
            # patch generation. Full-file (poc_full/target_full) is what
            # an LLM-derived fix persists as, below - reapplying it means
            # writing the whole saved file back, not diffing against
            # whatever the current template happens to say.
            if "poc_full" in rule or "target_full" in rule:
                new_poc_text = rule.get("poc_full") or poc_text
                new_target_text = rule.get("target_full") or target_text
            else:
                p, t, changed = poc_text, target_text, False
                for old, new in rule.get("poc_patches", []):
                    if old in p:
                        p = p.replace(old, new)
                        changed = True
                for old, new in rule.get("target_patches", []):
                    if old in t:
                        t = t.replace(old, new)
                        changed = True
                if changed:
                    new_poc_text, new_target_text = p, t

        if new_poc_text is None:
            # No lesson, no built-in rule, or the rule didn't match this
            # source - the path that lets Stage 3.7 handle a failure
            # nobody anticipated, instead of stopping here unconditionally.
            llm_fix = _llm_revise_artifacts(vuln_class, poc_text, target_text,
                                             artifacts.execution_log)
            if llm_fix is not None:
                new_poc_text, new_target_text = llm_fix
                source = "llm"
                rule = {"description": "LLM-diagnosed revision from the execution log",
                        "poc_full": new_poc_text, "target_full": new_target_text}

        entry = {"iteration": iteration, "signature": signature, "source": source,
                  "exit_code_before": artifacts.exit_code}

        if new_poc_text is None:
            entry["outcome"] = ("no known revision, and no AI backend available "
                                 "to attempt one") if source is None else \
                                "revision rule didn't match current source"
            artifacts.refinement_history.append(entry)
            log.info("[Stage 3.7] No usable revision for signature=%s - stopping", signature)
            break

        poc_path.write_text(new_poc_text, encoding="utf-8")
        target_path.write_text(new_target_text, encoding="utf-8")
        artifacts.iterations = iteration + 1
        log.info("[Stage 3.7] Applying revision (iteration %d, source=%s): %s",
                  iteration + 1, source, rule["description"][:100])

        artifacts = execute_exploit_artifacts(artifacts)
        entry["exit_code_after"] = artifacts.exit_code
        entry["confirmed_after"] = artifacts.dynamically_confirmed
        entry["revision_description"] = rule["description"]
        artifacts.refinement_history.append(entry)

        if artifacts.dynamically_confirmed:
            log.info("[Stage 3.7] Revision succeeded on iteration %d (source=%s)",
                      iteration + 1, source)
            if known is None:
                _save_lesson(vuln_class, signature, rule)
                log.info("[Stage 3.7] Learned new lesson: %s / %s (source=%s)",
                          vuln_class, signature, source)
            break

    return artifacts
