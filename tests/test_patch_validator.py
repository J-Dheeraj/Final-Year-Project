"""Offline tests for Stage 3.8's patch validator (src/pipeline/patch.py).

Mocks cve_pipeline.execute_exploit_artifacts and
src.pipeline.patch._llm_generate_patch so every test runs with no real
subprocess, network, or LLM call - focused on the validator's own
control flow: the timeout/skip-reason handling, the multi-payload
re-probe loop (including the two bugs fixed this session: a failed-to-
start probe being conflated with a genuine block, and the verdict
standing even when zero variants were actually tested), and the
crash-signature benign-probe check.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

import cve_pipeline as pipeline  # noqa: E402
from src.pipeline import patch as patchmod  # noqa: E402


class _FakeGenCall:
    """Stands in for cve_pipeline's LiveModelResult."""
    duration_s = 1.0
    input_tokens = 10
    output_tokens = 5
    cost_usd = 0.0


def _artifacts(target_app_path: str, **overrides) -> "pipeline.ExploitArtifacts":
    base = dict(
        generated=True,
        dynamically_confirmed=True,
        poc_path="poc.py",
        target_app_path=target_app_path,
        vuln_class="CMDi",
    )
    base.update(overrides)
    return pipeline.ExploitArtifacts(**base)


def _write_target(tmp_path: Path) -> Path:
    p = tmp_path / "target_app.py"
    p.write_text("# vulnerable target\n", encoding="utf-8")
    return p


def _patch_llm_generate(monkeypatch, patched_source="# patched\n", summary="fix"):
    monkeypatch.setattr(
        patchmod, "_llm_generate_patch",
        lambda *a, **k: (patched_source, summary, _FakeGenCall()))


def test_skip_reason_timeout_is_inconclusive_not_validated(tmp_path, monkeypatch):
    """A probe shadow result with execution_skip_reason set (e.g. the
    exploit probe timing out) must NOT be silently treated as a
    confirmed block - this is the Stage 3.8 bug fixed alongside
    cve_pipeline.py's execute_exploit_artifacts (commit e4d4570)."""
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target))
    _patch_llm_generate(monkeypatch)

    def fake_execute(shadow, extra_arg=None):
        shadow.executed = True
        shadow.execution_skip_reason = "poc.py timed out after 20s (possible hang)"
        shadow.exit_code = None
        shadow.dynamically_confirmed = False
        shadow.execution_log = "=== target_app.py ===\n...\n"
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "CMDi")

    assert result.patch_validated is False
    assert result.patch_verdict == "inconclusive_crash"
    assert result.patch_exploit_blocked is False
    assert result.patch_function_preserved is None


def test_multipayload_all_variants_untested_rejects_validated(tmp_path, monkeypatch):
    """If the single-payload check passes but every alternate-payload
    re-probe fails to produce a real signal, the patch must not be
    validated on multi-payload evidence it was never actually tested
    against (the second fix in commit 98c3922)."""
    target = _write_target(tmp_path)
    artifacts = _artifacts(
        str(target),
        payload_variants=["'; DROP TABLE users --", "' OR '1'='1"],
    )
    _patch_llm_generate(monkeypatch)
    call_count = {"n": 0}

    def fake_execute(shadow, extra_arg=None):
        call_count["n"] += 1
        shadow.executed = True
        if extra_arg is None:
            shadow.dynamically_confirmed = False
            shadow.execution_log = "=== target_app.py ===\nclean rejection\n"
        else:
            shadow.execution_skip_reason = "target_app.py never became healthy"
            shadow.dynamically_confirmed = False
            shadow.execution_log = ""
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "SQLi")

    assert call_count["n"] == 1 + len(artifacts.payload_variants)
    assert result.patch_validated is False
    assert "not every declared payload was actually tested" in result.patch_validation_log


def test_multipayload_bypass_overrides_validated_false(tmp_path, monkeypatch):
    """An alternate payload that still succeeds must flip patch_validated
    back to False, even though the original payload was blocked."""
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target), payload_variants=["'; DROP TABLE users --"])
    _patch_llm_generate(monkeypatch)

    def fake_execute(shadow, extra_arg=None):
        shadow.executed = True
        if extra_arg is None:
            shadow.dynamically_confirmed = False
            shadow.execution_log = "=== target_app.py ===\nclean rejection\n"
        else:
            shadow.dynamically_confirmed = True
            shadow.execution_log = "=== target_app.py ===\nbypassed\n"
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "SQLi")

    assert result.patch_validated is False
    assert "BYPASSED" in result.patch_validation_log


def test_multipayload_one_untested_variant_still_rejects(tmp_path, monkeypatch):
    """Tightened 2026-10-13: the validator's own contract is that ALL
    declared alternate payloads must be tested and found still-blocked.
    Even one untested variant (among others that did run clean) must
    reject the patch - an independent review found the previous
    "at least one tested" carve-out inconsistent with that contract."""
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target), payload_variants=["skip-me", "test-me"])
    _patch_llm_generate(monkeypatch)

    def fake_execute(shadow, extra_arg=None):
        shadow.executed = True
        if extra_arg is None:
            shadow.dynamically_confirmed = False
            shadow.execution_log = "=== target_app.py ===\nclean rejection\n"
        elif extra_arg == "skip-me":
            shadow.execution_skip_reason = "target_app.py never became healthy"
            shadow.dynamically_confirmed = False
        else:
            shadow.dynamically_confirmed = False
            shadow.execution_log = "=== target_app.py ===\nalso blocked\n"
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "SQLi")

    assert result.patch_validated is False
    assert "incomplete" in result.patch_validation_log
    assert "skip-me" in result.patch_validation_log


def test_multipayload_all_variants_tested_and_blocked_validates(tmp_path, monkeypatch):
    """The positive case: every declared variant actually ran and none
    bypassed the patch - this must still validate."""
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target), payload_variants=["v1", "v2"])
    _patch_llm_generate(monkeypatch)

    def fake_execute(shadow, extra_arg=None):
        shadow.executed = True
        shadow.dynamically_confirmed = False
        shadow.execution_log = "=== target_app.py ===\nclean rejection\n"
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "SQLi")

    assert result.patch_validated is True
    assert result.patch_verdict in ("heuristic_fix_screened", "regression_broke_route")


def test_benign_probe_crash_sets_function_preserved_false(tmp_path, monkeypatch):
    """The exact Round 5 shape, replayed on the benign probe: a crash on
    a legitimate request must flag patch_function_preserved False."""
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target))
    _patch_llm_generate(monkeypatch)

    def fake_execute(shadow, extra_arg=None):
        shadow.executed = True
        if extra_arg is None:
            shadow.dynamically_confirmed = False
            shadow.execution_log = "=== target_app.py ===\nclean rejection\n"
        else:
            shadow.dynamically_confirmed = False
            shadow.execution_log = (
                "=== target_app.py ===\n"
                "Traceback (most recent call last):\n"
                "NameError: name 'io' is not defined\n"
            )
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "Deserialization")

    assert result.patch_exploit_blocked is True
    assert result.patch_function_preserved is False
    assert result.patch_verdict == "regression_broke_route"


def test_deleted_route_passes_crash_check_but_fails_strict_check(tmp_path, monkeypatch):
    """The exact gap this redesign closes, found by an independent
    review and verified empirically against real Flask/werkzeug this
    session: a patch that deletes the vulnerable route produces a clean
    404 access-log line, no traceback - patch_function_preserved alone
    reads that as "preserved" (unchanged, historical meaning), but
    patch_function_preserved_strict must catch it via the status code."""
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target))
    _patch_llm_generate(monkeypatch)

    def fake_execute(shadow, extra_arg=None):
        shadow.executed = True
        if extra_arg is None:
            shadow.dynamically_confirmed = False
            shadow.execution_log = "=== target_app.py ===\nclean rejection\n"
        else:
            # Real werkzeug access-log shape for a deleted route, as
            # captured empirically this session.
            shadow.dynamically_confirmed = False
            shadow.execution_log = (
                "=== target_app.py ===\n"
                '127.0.0.1 - - [13/Oct/2026 10:34:25] "GET /health HTTP/1.1" 200 -\n'
                '127.0.0.1 - - [13/Oct/2026 10:34:25] "POST /ping HTTP/1.1" 404 -\n'
            )
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "CMDi")

    assert result.patch_function_preserved is True  # unchanged historical meaning
    assert result.patch_benign_probe_status_code == 404
    assert result.patch_function_preserved_strict is False  # the new, stricter signal catches it
    assert result.patch_verdict == "heuristic_fix_screened"  # label, not changed logic


def test_working_route_passes_both_crash_and_strict_check(tmp_path, monkeypatch):
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target))
    _patch_llm_generate(monkeypatch)

    def fake_execute(shadow, extra_arg=None):
        shadow.executed = True
        shadow.dynamically_confirmed = False
        if extra_arg is None:
            shadow.execution_log = "=== target_app.py ===\nclean rejection\n"
        else:
            shadow.execution_log = (
                "=== target_app.py ===\n"
                '127.0.0.1 - - [13/Oct/2026 10:34:25] "GET /health HTTP/1.1" 200 -\n'
                '127.0.0.1 - - [13/Oct/2026 10:34:25] "POST /ping HTTP/1.1" 200 -\n'
            )
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "CMDi")

    assert result.patch_benign_probe_status_code == 200
    assert result.patch_function_preserved_strict is True


def test_last_http_status_parses_last_match():
    log = (
        '"GET /health HTTP/1.1" 200 -\n'
        '"POST /ping HTTP/1.1" 403 -\n'
    )
    assert patchmod._last_http_status(log) == 403


def test_last_http_status_none_when_no_match():
    assert patchmod._last_http_status("no http lines here") is None


def test_exploit_crash_is_inconclusive_round5_regression(tmp_path, monkeypatch):
    """The exact Round 5 false-acceptance shape: the exploit request
    itself crashed the route rather than being cleanly rejected - the
    finding that motivated the corrected validator in the first place."""
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target))
    _patch_llm_generate(monkeypatch)

    def fake_execute(shadow, extra_arg=None):
        shadow.executed = True
        shadow.dynamically_confirmed = False
        shadow.execution_log = (
            "=== target_app.py ===\n"
            "Traceback (most recent call last):\n"
            "NameError: name 'io' is not defined\n"
        )
        return shadow

    monkeypatch.setattr(pipeline, "execute_exploit_artifacts", fake_execute)

    result = patchmod.generate_and_validate_patch(artifacts, "Deserialization")

    assert result.patch_verdict == "inconclusive_crash"
    assert result.patch_exploit_blocked is False


def test_not_dynamically_confirmed_skips_patch_entirely():
    artifacts = _artifacts("target_app.py", dynamically_confirmed=False)
    result = patchmod.generate_and_validate_patch(artifacts, "CMDi")
    assert result.patch_skip_reason
    assert not result.patch_attempted


def test_no_llm_backend_skips_with_reason(tmp_path, monkeypatch):
    target = _write_target(tmp_path)
    artifacts = _artifacts(str(target))
    monkeypatch.setattr(patchmod, "_llm_generate_patch", lambda *a, **k: None)
    result = patchmod.generate_and_validate_patch(artifacts, "CMDi")
    assert result.patch_skip_reason
    assert not result.patch_attempted


def test_missing_target_file_skips_with_reason():
    artifacts = _artifacts("/no/such/path/target_app.py")
    result = patchmod.generate_and_validate_patch(artifacts, "CMDi")
    assert result.patch_skip_reason
    assert not result.patch_attempted


def test_response_shows_crash_detects_traceback():
    assert patchmod._response_shows_crash(
        "Traceback (most recent call last):\nNameError: x") is True


def test_response_shows_crash_ignores_clean_log():
    assert patchmod._response_shows_crash(
        '127.0.0.1 - - [x] "POST /ping HTTP/1.1" 404 -') is False


def test_response_shows_crash_detects_exception_on_route():
    assert patchmod._response_shows_crash(
        "Exception on /ping [POST]") is True
