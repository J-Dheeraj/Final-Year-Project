"""Offline tests for cve_watcher.py: the background CVE-feed watcher.

Mocks cve_pipeline.run_pipeline (the async pipeline entry point) and the
feed fetchers, so every test runs with no real network/subprocess call -
focused on two bugs fixed this session: run_pipeline() crashing with an
AttributeError because the argparse.Namespace it built was missing
run_id, and poll_once() marking a failed CVE as "seen" unconditionally,
which silently blocked all future retries. Also covers the cve_id
path-traversal validation added alongside the run_id fix.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

import cve_watcher as watcher  # noqa: E402


class _FakeReport:
    def __init__(self, errors=None, stages_failed=None, overall_risk="HIGH"):
        self.errors = errors or []
        self.stages_failed = stages_failed or []
        self.overall_risk = overall_risk


def _patch_pipeline_run(monkeypatch, report=None, exc=None, capture_args=None):
    async def fake_run_pipeline(args):
        if capture_args is not None:
            capture_args.append(args)
        if exc is not None:
            raise exc
        return report or _FakeReport()
    monkeypatch.setattr(watcher._pipeline, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(watcher._pipeline, "render_text", lambda r: "report text")
    monkeypatch.setattr(watcher._pipeline, "render_json", lambda r: "{}")
    monkeypatch.setattr(watcher, "_PIPELINE_AVAILABLE", True)


def test_run_pipeline_builds_namespace_with_run_id(tmp_path, monkeypatch):
    """Regression test for the exact bug this session fixed: run_pipeline
    crashed with AttributeError because cve_pipeline.run_pipeline reads
    args.run_id and the Namespace built here never had that field."""
    monkeypatch.setattr(watcher, "REPORTS_DIR", tmp_path)
    captured = []
    _patch_pipeline_run(monkeypatch, capture_args=captured)

    ok = watcher.run_pipeline("CVE-2026-12345", "text", False)

    assert ok is True
    assert len(captured) == 1
    assert hasattr(captured[0], "run_id")
    assert captured[0].run_id == ""


def test_run_pipeline_returns_false_on_report_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(watcher, "REPORTS_DIR", tmp_path)
    _patch_pipeline_run(monkeypatch, report=_FakeReport(errors=["boom"]))

    ok = watcher.run_pipeline("CVE-2026-12345", "text", False)

    assert ok is False


def test_run_pipeline_returns_false_on_exception(tmp_path, monkeypatch):
    monkeypatch.setattr(watcher, "REPORTS_DIR", tmp_path)
    _patch_pipeline_run(monkeypatch, exc=RuntimeError("pipeline blew up"))

    ok = watcher.run_pipeline("CVE-2026-12345", "text", False)

    assert ok is False


def test_run_pipeline_rejects_path_traversal_cve_id(tmp_path, monkeypatch):
    """The path-traversal fix (commit ef2b168): an unsafe cve_id must be
    refused before it ever reaches a filesystem path or the pipeline."""
    monkeypatch.setattr(watcher, "REPORTS_DIR", tmp_path)
    called = {"n": 0}

    async def fake_run_pipeline(args):
        called["n"] += 1
        return _FakeReport()
    monkeypatch.setattr(watcher._pipeline, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(watcher, "_PIPELINE_AVAILABLE", True)

    ok = watcher.run_pipeline("../../../etc/passwd", "text", False)

    assert ok is False
    assert called["n"] == 0
    assert not list(tmp_path.glob("*"))  # nothing written outside reports dir


def test_run_pipeline_skips_when_pipeline_unavailable(monkeypatch):
    monkeypatch.setattr(watcher, "_PIPELINE_AVAILABLE", False)
    monkeypatch.setattr(watcher, "_PIPELINE_IMPORT_ERR", "simulated import failure",
                         raising=False)
    ok = watcher.run_pipeline("CVE-2026-12345", "text", False)
    assert ok is False


def _since():
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _disable_feeds(monkeypatch, nvd=(), ghsa=()):
    monkeypatch.setattr(watcher, "fetch_nvd", lambda since: iter(nvd))
    monkeypatch.setattr(watcher, "fetch_ghsa", lambda since: iter(ghsa))


def test_poll_once_sequential_marks_seen_only_on_success(tmp_path, monkeypatch):
    """The exact bug fixed this session: seen.add() used to fire
    unconditionally, permanently blocking retries for a failed CVE."""
    _disable_feeds(monkeypatch, nvd=["CVE-2026-0001", "CVE-2026-0002"])
    seen = watcher.SeenStore(tmp_path / "seen.json")

    def fake_run_pipeline(cve_id, fmt, no_probe, lab_url="x"):
        return cve_id == "CVE-2026-0001"
    monkeypatch.setattr(watcher, "run_pipeline", fake_run_pipeline)

    new_found, succeeded = watcher.poll_once(
        _since(), seen, "text", False, workers=1, provtrail_enabled=False)

    assert new_found == 2
    assert succeeded == 1
    assert "CVE-2026-0001" in seen
    assert "CVE-2026-0002" not in seen  # failed - must be retried next poll


def test_poll_once_parallel_marks_seen_only_on_success(tmp_path, monkeypatch):
    _disable_feeds(monkeypatch, nvd=["CVE-2026-0001", "CVE-2026-0002"])
    seen = watcher.SeenStore(tmp_path / "seen.json")

    def fake_run_pipeline(cve_id, fmt, no_probe, lab_url="x"):
        return cve_id == "CVE-2026-0001"
    monkeypatch.setattr(watcher, "run_pipeline", fake_run_pipeline)

    new_found, succeeded = watcher.poll_once(
        _since(), seen, "text", False, workers=2, provtrail_enabled=False)

    assert new_found == 2
    assert succeeded == 1
    assert "CVE-2026-0001" in seen
    assert "CVE-2026-0002" not in seen


def test_poll_once_parallel_exception_not_marked_seen(tmp_path, monkeypatch):
    """A worker that raises must degrade to a failed result, not crash
    the poll or get silently marked seen."""
    _disable_feeds(monkeypatch, nvd=["CVE-2026-0001"])
    seen = watcher.SeenStore(tmp_path / "seen.json")

    def fake_run_pipeline(cve_id, fmt, no_probe, lab_url="x"):
        raise RuntimeError("worker crashed")
    monkeypatch.setattr(watcher, "run_pipeline", fake_run_pipeline)

    new_found, succeeded = watcher.poll_once(
        _since(), seen, "text", False, workers=2, provtrail_enabled=False)

    assert new_found == 1
    assert succeeded == 0
    assert "CVE-2026-0001" not in seen


def test_poll_once_skips_already_seen(tmp_path, monkeypatch):
    _disable_feeds(monkeypatch, nvd=["CVE-2026-0001"])
    seen = watcher.SeenStore(tmp_path / "seen.json")
    seen.add("CVE-2026-0001")
    monkeypatch.setattr(watcher, "run_pipeline", lambda *a, **k: True)

    new_found, succeeded = watcher.poll_once(
        _since(), seen, "text", False, workers=1, provtrail_enabled=False)

    assert new_found == 0
    assert succeeded == 0


def test_poll_once_no_new_cves(tmp_path, monkeypatch):
    _disable_feeds(monkeypatch)
    seen = watcher.SeenStore(tmp_path / "seen.json")

    new_found, succeeded = watcher.poll_once(
        _since(), seen, "text", False, workers=1, provtrail_enabled=False)

    assert (new_found, succeeded) == (0, 0)


def test_seen_store_persists_across_instances(tmp_path):
    path = tmp_path / "seen.json"
    s1 = watcher.SeenStore(path)
    s1.add("CVE-2026-9999")
    s1._save()

    s2 = watcher.SeenStore(path)
    assert "CVE-2026-9999" in s2
