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
import copy
import concurrent.futures
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


# ─────────────────────────────────────────────────────────────────────────────
# Propose→Probe→Compose cycle — harness² adaptation
# Xu et al., 2026 — arXiv 2610.14224
# ─────────────────────────────────────────────────────────────────────────────
# Instead of one LLM call, generate K candidate revisions with K different
# prompting strategies in parallel (PROPOSE), execute each against the same
# CVE target (PROBE), then select the confirmed winner or compose a final
# synthesis from the K failure logs (COMPOSE). This matches harness²'s core
# cycle without requiring their infrastructure (Vertex AI, OpenCode executor):
# the pipeline's own _call_live_model and execute_exploit_artifacts stand in.

_PPC_STRATEGIES = ("diagnose", "minimal", "step_back")


def _build_ppc_prompt(strategy: str, vuln_class: str, poc_text: str,
                       target_text: str, execution_log: str) -> str:
    shared = (
        f"\nExecution log (what actually happened):\n```\n{execution_log[-2000:]}\n```\n\n"
        f"Current poc.py:\n```python\n{poc_text}\n```\n\n"
        f"Current target_app.py:\n```python\n{target_text}\n```\n\n"
        f"Output EXACTLY two sections, no markdown fences, no commentary outside them:\n\n"
        f"===POC_START===\n(complete corrected poc.py)\n===POC_END===\n\n"
        f"===TARGET_START===\n(complete corrected target_app.py)\n===TARGET_END==="
    )
    if strategy == "diagnose":
        return (
            f"A {vuln_class} proof-of-concept exploit and its minimal target failed. "
            f"Diagnose the root cause from the execution log and output both files corrected. "
            f"Preserve the 4-phase pattern (health→exploit→verify→exit 0/1) and fix only "
            f"what is broken.\n{shared}"
        )
    if strategy == "minimal":
        return (
            f"A {vuln_class} proof-of-concept exploit and its minimal target failed. "
            f"The structure is probably correct. Make the SMALLEST possible change — "
            f"find the one or two lines that are wrong and fix only those. Do not redesign.\n{shared}"
        )
    if strategy == "step_back":
        return (
            f"A {vuln_class} exploit failed. Set aside the existing implementation — the whole "
            f"approach may be wrong. Think from first principles: what must a {vuln_class} "
            f"exploit demonstrate? Write a clean implementation from scratch. Keep the 4-phase "
            f"pattern (health→exploit→verify→exit 0/1).\n{shared}"
        )
    raise ValueError(f"Unknown PPC strategy: {strategy!r}")


def _ppc_revise_artifacts(vuln_class: str, poc_text: str, target_text: str,
                           execution_log: str, artifacts):
    """Propose→Probe→Compose: K parallel proposals with different strategies,
    each probed by actually running it against the CVE target, then composed
    into the best revision.

    Adapts the harness² cycle (Xu et al., 2026, arXiv 2610.14224) natively:
    same PPC logic, same parallel exploration, but driven by the pipeline's
    own _call_live_model and execute_exploit_artifacts.

    Returns (poc_code, target_code, gen_call, ppc_meta) or None.
    ppc_meta carries per-strategy probe outcomes for telemetry."""
    from cve_pipeline import _call_live_model, _live_model_available, _extract_marker, execute_exploit_artifacts
    if not _live_model_available():
        return None

    poc_path = Path(artifacts.poc_path)
    target_path = Path(artifacts.target_app_path)

    # ── Stage 1: PROPOSE ──────────────────────────────────────────────────────
    prompts = {
        s: _build_ppc_prompt(s, vuln_class, poc_text, target_text, execution_log)
        for s in _PPC_STRATEGIES
    }
    raw: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_PPC_STRATEGIES)) as ex:
        future_to_s = {ex.submit(_call_live_model, p, 180): s for s, p in prompts.items()}
        for fut in concurrent.futures.as_completed(future_to_s):
            s = future_to_s[fut]
            try:
                result = fut.result()
            except Exception:
                continue
            if not result.text:
                continue
            poc_code = _extract_marker(result.text, "===POC_START===", "===POC_END===")
            tgt_code = _extract_marker(result.text, "===TARGET_START===", "===TARGET_END===")
            if poc_code and tgt_code:
                raw[s] = (poc_code, tgt_code, result)

    if not raw:
        return None

    # ── Stage 2: PROBE ────────────────────────────────────────────────────────
    # Each candidate gets its own temp files so probes don't clobber each other.
    probed: dict = {}
    for s, (poc_code, tgt_code, gen_call) in raw.items():
        ppc_poc = poc_path.parent / f"poc.ppc_{s}.py"
        ppc_tgt = target_path.parent / f"target_app.ppc_{s}.py"
        try:
            ppc_poc.write_text(poc_code, encoding="utf-8")
            ppc_tgt.write_text(tgt_code, encoding="utf-8")
        except OSError:
            continue
        probe = copy.copy(artifacts)
        probe.poc_path = str(ppc_poc)
        probe.target_app_path = str(ppc_tgt)
        probe.dynamically_confirmed = False
        probe.exit_code = -1
        probe.execution_log = ""
        try:
            probe = execute_exploit_artifacts(probe)
        except Exception:
            continue
        probed[s] = (probe, gen_call, poc_code, tgt_code)

    if not probed:
        return None

    ppc_meta = {
        s: {"strategy": s, "confirmed": p.dynamically_confirmed, "exit_code": p.exit_code}
        for s, (p, *_) in probed.items()
    }

    # ── Stage 3: COMPOSE ──────────────────────────────────────────────────────
    # Priority 1: a confirmed exploit — use the first winner.
    for s, (probe, gen_call, poc_code, tgt_code) in probed.items():
        if probe.dynamically_confirmed:
            return poc_code, tgt_code, gen_call, {"winner": s, "k": len(probed), "probes": ppc_meta}

    # Priority 2: compose from K failure logs. This is the genuine harness²
    # composition step: behavioral diffs between K failed attempts guide the
    # synthesized fix, rather than simply retrying the best single attempt.
    failure_evidence = "\n\n".join(
        f"=== Strategy '{s}' (exit {p.exit_code}) ===\n{p.execution_log[-800:]}"
        for s, (p, *_) in probed.items()
    )
    compose_prompt = (
        f"K={len(probed)} different exploit strategies for {vuln_class} all failed. "
        f"Here are their execution logs — look for patterns across them (what consistently "
        f"works vs. consistently fails) to identify the real blocker:\n\n"
        f"{failure_evidence}\n\n"
        f"Output a SYNTHESIZED fix using the best elements from each attempt. "
        f"Original poc.py:\n```python\n{poc_text}\n```\n"
        f"Original target_app.py:\n```python\n{target_text}\n```\n"
        f"Keep the 4-phase pattern. Output:\n"
        f"===POC_START===\n(complete corrected poc.py)\n===POC_END===\n"
        f"===TARGET_START===\n(complete corrected target_app.py)\n===TARGET_END==="
    )
    try:
        compose_call = _call_live_model(compose_prompt, 240)
    except Exception:
        compose_call = None
    if compose_call and compose_call.text:
        poc_code = _extract_marker(compose_call.text, "===POC_START===", "===POC_END===")
        tgt_code = _extract_marker(compose_call.text, "===TARGET_START===", "===TARGET_END===")
        if poc_code and tgt_code:
            ppc_meta["composed"] = True
            return poc_code, tgt_code, compose_call, {"winner": "composed", "k": len(probed), "probes": ppc_meta}

    # Fallback: return the first probe's artifacts (better than nothing).
    s0 = next(iter(probed))
    _, gen_call, poc_code, tgt_code = probed[s0]
    return poc_code, tgt_code, gen_call, {"winner": f"{s0}_partial", "k": len(probed), "probes": ppc_meta}


def _llm_revise_artifacts(vuln_class: str, poc_text: str, target_text: str,
                           execution_log: str):
    """Ask a live model to diagnose why the generated exploit failed and
    rewrite both files to fix it. This is the path that lets Stage 3.7
    handle a failure NOBODY anticipated - not just the ones already
    recognized by a failure-signature match and hand-coded into
    _BUILTIN_REVISIONS. The other two paths (lessons store, built-in
    rules) can only ever cover what a human already noticed and coded a
    fix for; this one can, in principle, cover anything the log itself
    makes diagnosable. Uses the same provider-agnostic backend as Stage
    3.5/3.8 (Claude CLI first, local Ollama fallback), not just the
    Claude CLI. Returns (poc_code, target_code, LiveModelResult), or None
    (never raises) if no AI backend is available or the response doesn't
    parse - the caller falls back to reporting "no known revision" rather
    than pretending a fix was attempted."""
    from cve_pipeline import _call_live_model, _live_model_available, _extract_marker
    if not _live_model_available():
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
    gen_call = _call_live_model(prompt, timeout=180)
    if not gen_call.text:
        return None
    poc_code = _extract_marker(gen_call.text, "===POC_START===", "===POC_END===")
    target_code = _extract_marker(gen_call.text, "===TARGET_START===", "===TARGET_END===")
    if not poc_code or not target_code:
        return None
    return poc_code, target_code, gen_call


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

        revision_call = None
        ppc_meta = None
        if new_poc_text is None:
            # No lesson, no built-in rule, or the rule didn't match this source.
            # Use the Propose→Probe→Compose cycle (harness², Xu et al. 2026) to
            # generate K candidate revisions in parallel, probe each by running it,
            # and compose the winner from behavioral diffs across the K attempts.
            # Falls back gracefully to the single-call path if no backend is up.
            ppc_fix = _ppc_revise_artifacts(vuln_class, poc_text, target_text,
                                             artifacts.execution_log, artifacts)
            if ppc_fix is not None:
                new_poc_text, new_target_text, revision_call, ppc_meta = ppc_fix
                winner = (ppc_meta or {}).get("winner", "?")
                k = (ppc_meta or {}).get("k", 1)
                source = "ppc_llm"
                rule = {
                    "description": (
                        f"harness²-PPC revision (winner={winner}, k={k})"
                    ),
                    "poc_full": new_poc_text,
                    "target_full": new_target_text,
                }

        entry = {"iteration": iteration, "signature": signature, "source": source,
                  "exit_code_before": artifacts.exit_code}
        if ppc_meta is not None:
            entry["ppc_meta"] = ppc_meta
        # Real, measured cost of this iteration's live-model call, per the
        # benchmark protocol's "record time/tokens/cost for every call"
        # rule - same shape as generation_*/patch_gen_* on ExploitArtifacts,
        # but scoped per-attempt here since a single CVE can retry multiple
        # times. None (not 0) when this iteration used a lesson/built-in
        # rule instead of a live call, or when no revision was attempted.
        if revision_call is not None:
            entry["revision_backend"]       = revision_call.backend
            entry["revision_model"]         = revision_call.model
            entry["revision_duration_s"]    = revision_call.duration_s
            entry["revision_input_tokens"]  = revision_call.input_tokens
            entry["revision_output_tokens"] = revision_call.output_tokens
            entry["revision_cost_usd"]      = revision_call.cost_usd

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
