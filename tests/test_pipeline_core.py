"""Tests for cve_pipeline utility functions and _run_pipeline_direct orchestration.

Covers:
  - _extract_marker: marker extraction + implicit boundary fallback
  - _strip_markdown_fence: fence stripping
  - _clean_payload_variants: placeholder/backtick filtering
  - _safe_id_component: path-traversal validation
  - compile_report: CVSS risk mapping, summary construction, JSON decode
  - _run_pipeline_direct: stage sequencing, skip_probe gating, error isolation
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

import cve_pipeline as _p


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_deps(tmp_path: Path, *, skip_probe: bool = True, run_id: str = "") -> _p.PipelineDeps:
    cache = _p.FileCache(tmp_path / "cache")
    return _p.PipelineDeps(
        cve_id="CVE-2026-99999",
        pipeline_id="test-run",
        cache=cache,
        lab_url="http://127.0.0.1:8000",
        skip_probe=skip_probe,
        no_cache=True,
        run_id=run_id,
    )


def _make_ctx(tmp_path: Path, **kwargs) -> _p._DirectCtx:
    return _p._DirectCtx(_make_deps(tmp_path, **kwargs))


# ── _extract_marker ────────────────────────────────────────────────────────────

def test_extract_marker_normal():
    text = "===START===hello world===END==="
    assert _p._extract_marker(text, "===START===", "===END===") == "hello world"


def test_extract_marker_missing_start_returns_empty():
    assert _p._extract_marker("no markers here", "===START===", "===END===") == ""


def test_extract_marker_missing_end_falls_back_to_next_marker():
    text = "===FOO_START===actual content===BAR_START===other"
    result = _p._extract_marker(text, "===FOO_START===", "===FOO_END===")
    assert result == "actual content"


def test_extract_marker_missing_end_and_no_next_marker_uses_rest():
    text = "===FOO_START===tail content"
    result = _p._extract_marker(text, "===FOO_START===", "===FOO_END===")
    assert result == "tail content"


def test_extract_marker_strips_inner_markdown_fence():
    text = "===S===\n```python\ncode here\n```\n===E==="
    assert _p._extract_marker(text, "===S===", "===E===") == "code here"


# ── _strip_markdown_fence ──────────────────────────────────────────────────────

def test_strip_markdown_fence_removes_lang_fence():
    assert _p._strip_markdown_fence("```python\ncode\n```") == "code"


def test_strip_markdown_fence_removes_plain_fence():
    assert _p._strip_markdown_fence("```\ncode\n```") == "code"


def test_strip_markdown_fence_no_fence_unchanged():
    assert _p._strip_markdown_fence("plain code") == "plain code"


# ── _clean_payload_variants ────────────────────────────────────────────────────

def test_clean_payload_variants_normal_lines():
    raw = "payload1\npayload2\npayload3"
    assert _p._clean_payload_variants(raw) == ["payload1", "payload2", "payload3"]


def test_clean_payload_variants_drops_parenthetical_placeholder():
    raw = "(list each payload on its own line)"
    assert _p._clean_payload_variants(raw) == []


def test_clean_payload_variants_drops_per_line_placeholder():
    raw = "real_payload\n(echoed placeholder instruction)\nanother_payload"
    assert _p._clean_payload_variants(raw) == ["real_payload", "another_payload"]


def test_clean_payload_variants_strips_backtick_wrapper():
    raw = "`/etc/passwd`\n`../../secret`"
    assert _p._clean_payload_variants(raw) == ["/etc/passwd", "../../secret"]


def test_clean_payload_variants_skips_blank_lines():
    raw = "a\n\nb\n\nc"
    assert _p._clean_payload_variants(raw) == ["a", "b", "c"]


# ── _safe_id_component ─────────────────────────────────────────────────────────

def test_safe_id_component_valid_cve():
    assert _p._safe_id_component("CVE-2026-12345", label="cve_id") == "CVE-2026-12345"


def test_safe_id_component_rejects_path_traversal():
    import pytest
    with pytest.raises(ValueError, match="unsafe"):
        _p._safe_id_component("../../etc/passwd", label="cve_id")


def test_safe_id_component_rejects_double_dot():
    import pytest
    with pytest.raises(ValueError, match="unsafe"):
        _p._safe_id_component("CVE-2026-..1", label="cve_id")


def test_safe_id_component_rejects_slash():
    import pytest
    with pytest.raises(ValueError, match="unsafe"):
        _p._safe_id_component("CVE/2026/1", label="cve_id")


def test_safe_id_component_rejects_empty():
    import pytest
    with pytest.raises(ValueError):
        _p._safe_id_component("", label="cve_id")


# ── compile_report ─────────────────────────────────────────────────────────────

def test_compile_report_cvss_critical(tmp_path):
    ctx = _make_ctx(tmp_path)
    advisory = {"cve_id": "CVE-X", "cvss_score": 9.8, "severity": "CRITICAL",
                "package_name": "pkg", "ecosystem": "PyPI",
                "affected_versions": ["< 1.0"], "patched_versions": ["1.0"]}
    result = _p.compile_report(ctx, json.dumps(advisory), "{}", None)
    assert result["overall_risk"] == "CRITICAL"


def test_compile_report_cvss_high(tmp_path):
    ctx = _make_ctx(tmp_path)
    advisory = {"cve_id": "CVE-X", "cvss_score": 7.5, "package_name": "pkg",
                "ecosystem": "npm", "affected_versions": [], "patched_versions": []}
    result = _p.compile_report(ctx, json.dumps(advisory), "{}", None)
    assert result["overall_risk"] == "HIGH"


def test_compile_report_cvss_medium(tmp_path):
    ctx = _make_ctx(tmp_path)
    advisory = {"cve_id": "CVE-X", "cvss_score": 5.0, "package_name": "pkg",
                "ecosystem": "go", "affected_versions": [], "patched_versions": []}
    result = _p.compile_report(ctx, json.dumps(advisory), "{}", None)
    assert result["overall_risk"] == "MEDIUM"


def test_compile_report_cvss_low(tmp_path):
    ctx = _make_ctx(tmp_path)
    advisory = {"cve_id": "CVE-X", "cvss_score": 2.0, "package_name": "pkg",
                "ecosystem": "go", "affected_versions": [], "patched_versions": []}
    result = _p.compile_report(ctx, json.dumps(advisory), "{}", None)
    assert result["overall_risk"] == "LOW"


def test_compile_report_zero_cvss_is_unknown(tmp_path):
    ctx = _make_ctx(tmp_path)
    advisory = {"cve_id": "CVE-X", "package_name": "p", "ecosystem": "PyPI",
                "affected_versions": [], "patched_versions": []}
    result = _p.compile_report(ctx, json.dumps(advisory), "{}", None)
    assert result["overall_risk"] == "UNKNOWN"


def test_compile_report_bad_json_degrades_gracefully(tmp_path):
    ctx = _make_ctx(tmp_path)
    result = _p.compile_report(ctx, "not json", "also bad", None)
    assert "overall_risk" in result
    assert isinstance(result["recommendations"], list)


def test_compile_report_ssrf_adds_ssrf_recommendations(tmp_path):
    ctx = _make_ctx(tmp_path)
    advisory = {"cvss_score": 8.0, "package_name": "p", "ecosystem": "e",
                "affected_versions": [], "patched_versions": []}
    analysis = {"vulnerability_class": "SSRF"}
    result = _p.compile_report(ctx, json.dumps(advisory), json.dumps(analysis), None)
    assert any("URL" in r or "egress" in r for r in result["recommendations"])


def test_compile_report_marks_stage_completed(tmp_path):
    ctx = _make_ctx(tmp_path)
    _p.compile_report(ctx, "{}", "{}", None)
    assert "4_report" in ctx.deps.completed


# ── _run_pipeline_direct orchestration ────────────────────────────────────────

def _stub_advisory():
    return {"cve_id": "CVE-2026-99999", "package_name": "pkg", "ecosystem": "PyPI",
            "cvss_score": 7.0, "severity": "HIGH",
            "affected_versions": ["< 1.0"], "patched_versions": ["1.0"],
            "raw_description": "test"}


def _stub_analysis():
    return {"vulnerability_class": "SQLi", "fix_summary": "use params",
            "diff_summary": {"code_before": "x", "code_after": "y"}}


def _stub_probe():
    return {"confirmed": False, "poc_payload": ""}


def _stub_artifacts(*, generated=False, executed=False, dynamically_confirmed=False):
    a = _p.ExploitArtifacts(generated=generated, skip_reason="" if generated else "test")
    if generated:
        object.__setattr__(a, "executed", executed)
        object.__setattr__(a, "dynamically_confirmed", dynamically_confirmed)
    return a


def _run(coro):
    return asyncio.run(coro)


def test_run_pipeline_direct_completes_all_four_stages(tmp_path):
    deps = _make_deps(tmp_path, skip_probe=True)
    with (
        patch.object(_p, "fetch_advisory",        return_value=_stub_advisory()),
        patch.object(_p, "analyze_vulnerability", return_value=_stub_analysis()),
        patch.object(_p, "run_vuln_probe",        return_value=_stub_probe()),
        patch.object(_p, "generate_exploit_artifacts",
                     return_value=_stub_artifacts(generated=False)),
        patch.object(_p, "_call_claude",          return_value=""),
        patch.object(_p, "obsidian_ingest",       return_value=None),
    ):
        report = _run(_p._run_pipeline_direct(deps))

    assert "4_report" in report.stages_completed
    assert report.cve_id == "CVE-2026-99999"


def test_run_pipeline_direct_skip_probe_skips_stage_36(tmp_path):
    deps = _make_deps(tmp_path, skip_probe=True)
    with (
        patch.object(_p, "fetch_advisory",        return_value=_stub_advisory()),
        patch.object(_p, "analyze_vulnerability", return_value=_stub_analysis()),
        patch.object(_p, "run_vuln_probe",        return_value=_stub_probe()),
        patch.object(_p, "generate_exploit_artifacts",
                     return_value=_stub_artifacts(generated=True, executed=False)),
        patch.object(_p, "execute_exploit_artifacts") as mock_exec,
        patch.object(_p, "_call_claude",          return_value=""),
        patch.object(_p, "obsidian_ingest",       return_value=None),
    ):
        _run(_p._run_pipeline_direct(deps))

    mock_exec.assert_not_called()


def test_run_pipeline_direct_stage_failure_is_isolated(tmp_path):
    deps = _make_deps(tmp_path, skip_probe=False)
    bad_artifacts = _stub_artifacts(generated=True, executed=False)

    with (
        patch.object(_p, "fetch_advisory",        return_value=_stub_advisory()),
        patch.object(_p, "analyze_vulnerability", return_value=_stub_analysis()),
        patch.object(_p, "run_vuln_probe",        return_value=_stub_probe()),
        patch.object(_p, "generate_exploit_artifacts",
                     return_value=bad_artifacts),
        patch.object(_p, "execute_exploit_artifacts",
                     side_effect=RuntimeError("sandbox exploded")),
        patch.object(_p, "_call_claude",          return_value=""),
        patch.object(_p, "obsidian_ingest",       return_value=None),
    ):
        report = _run(_p._run_pipeline_direct(deps))

    assert "3.6_execution" in report.stages_failed
    assert "4_report" in report.stages_completed


def test_run_pipeline_direct_38_only_runs_when_dynamically_confirmed(tmp_path):
    deps = _make_deps(tmp_path, skip_probe=False)
    confirmed_artifacts = _stub_artifacts(
        generated=True, executed=True, dynamically_confirmed=True
    )

    with (
        patch.object(_p, "fetch_advisory",        return_value=_stub_advisory()),
        patch.object(_p, "analyze_vulnerability", return_value=_stub_analysis()),
        patch.object(_p, "run_vuln_probe",        return_value=_stub_probe()),
        patch.object(_p, "generate_exploit_artifacts",
                     return_value=confirmed_artifacts),
        patch.object(_p, "execute_exploit_artifacts",
                     return_value=confirmed_artifacts),
        patch.object(_p, "refine_and_reexecute",
                     return_value=confirmed_artifacts),
        patch.object(_p, "generate_and_validate_patch",
                     return_value=confirmed_artifacts) as mock_patch,
        patch.object(_p, "_call_claude",          return_value=""),
        patch.object(_p, "obsidian_ingest",       return_value=None),
    ):
        _run(_p._run_pipeline_direct(deps))

    mock_patch.assert_called_once()


def test_run_pipeline_direct_38_skipped_when_not_confirmed(tmp_path):
    deps = _make_deps(tmp_path, skip_probe=False)
    unconfirmed = _stub_artifacts(
        generated=True, executed=True, dynamically_confirmed=False
    )

    with (
        patch.object(_p, "fetch_advisory",        return_value=_stub_advisory()),
        patch.object(_p, "analyze_vulnerability", return_value=_stub_analysis()),
        patch.object(_p, "run_vuln_probe",        return_value=_stub_probe()),
        patch.object(_p, "generate_exploit_artifacts",
                     return_value=unconfirmed),
        patch.object(_p, "execute_exploit_artifacts",
                     return_value=unconfirmed),
        patch.object(_p, "refine_and_reexecute",
                     return_value=unconfirmed),
        patch.object(_p, "generate_and_validate_patch") as mock_patch,
        patch.object(_p, "_call_claude",          return_value=""),
        patch.object(_p, "obsidian_ingest",       return_value=None),
    ):
        _run(_p._run_pipeline_direct(deps))

    mock_patch.assert_not_called()
