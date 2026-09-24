"""Offline tests for provtrail_bridge (no network, pipeline mocked).

Covers the linkage logic that is independent of the live pipeline: artifact
parsing across formats, dedup, the "auto by ecosystem" probe decision, the
feed fallback routing, and the combined-report shape.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

import provtrail_bridge as bridge  # noqa: E402
import package_labs  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "provtrail"
SARIF = FIXTURES / "latest-scan.sarif"
AI_TEXT = FIXTURES / "latest-scan.ai.txt"

# The 6 advisories the sample scan resolves to (3 vuln + 3 review).
EXPECTED_IDS = {
    "CVE-2018-15685", "CVE-2021-23369", "CVE-2022-41919",
    "CVE-2023-24807", "CVE-2024-48910", "CVE-2026-29057",
}


def _ids(path: Path) -> set[str]:
    findings, reason = bridge.load_scan(path)
    assert reason is None, reason
    return {a.advisory_id for a in bridge.dedupe(findings)}


def test_sarif_and_ai_text_agree():
    assert _ids(SARIF) == EXPECTED_IDS
    assert _ids(AI_TEXT) == EXPECTED_IDS


def test_missing_file_reports_reason():
    findings, reason = bridge.load_scan(FIXTURES / "does-not-exist.json")
    assert findings == []
    assert reason and "not found" in reason


def test_raw_scan_json_without_provtrail_asks_for_export():
    # A provtrail_scan_v* payload with no ProvTrail installed must not be
    # silently mis-parsed — it should ask for the SARIF/AI-text export.
    payload = FIXTURES / "raw_scan.json"
    payload.write_text('{"schema": "provtrail_scan_v5", "findings": []}', encoding="utf-8")
    try:
        findings, reason = bridge.load_scan(payload)
        if reason is None:  # ProvTrail happens to be importable in this env
            pytest.skip("ProvTrail importable — authoritative path exercised elsewhere")
        assert findings == []
        assert "SARIF" in reason or "AI-text" in reason
    finally:
        payload.unlink(missing_ok=True)


def test_advisory_id_prefers_cve_over_ghsa():
    assert bridge._pick_advisory_id(["GHSA-xxxx", "CVE-2020-1"]) == "CVE-2020-1"
    assert bridge._pick_advisory_id(["GHSA-bbbb", "GHSA-aaaa"]) == "GHSA-aaaa"
    assert bridge._pick_advisory_id([]) is None


def test_dedupe_merges_locations_and_worst_priority():
    findings = [
        bridge.Finding("CVE-1", ["CVE-1"], ["p:unknown"], "manual_review", "low",
                       bridge.Location("a.js", 1, 2)),
        bridge.Finding("CVE-1", ["CVE-1"], ["p:unknown"], "automatic_vulnerability", "high",
                       bridge.Location("b.js", 3, 4)),
    ]
    (adv,) = bridge.dedupe(findings)
    assert adv.priority == "automatic_vulnerability"   # worst wins
    assert adv.confidence == "high"                    # best wins
    assert len(adv.locations) == 2


def test_auto_by_ecosystem_probe_decision(monkeypatch):
    """Empty map -> all static; one mapping -> only advisories with that package probe."""
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="provtrail_test_"))
    seen: dict[str, bool] = {}

    def fake_run(advisory_id, *, probe, lab_url, fmt, no_cache):
        seen[advisory_id] = probe
        report = type("R", (), {"overall_risk": "HIGH", "ssrf_probe": None,
                                "exploit_artifacts": None, "stages_failed": [],
                                "errors": [], "elapsed_s": 0.0})()
        return report, tmp / f"{advisory_id}.txt"

    monkeypatch.setattr(bridge, "run_pipeline_for", fake_run)
    monkeypatch.setattr(bridge, "REPORTS_DIR", tmp)

    import argparse
    args = argparse.Namespace(scan=str(SARIF), source="auto", no_probe=False,
                              no_cache=True, format="text", lookback=24, limit=25)

    monkeypatch.setattr(package_labs, "PACKAGE_LABS", {})
    assert bridge.run(args) == 0
    assert not any(seen.values()), "empty lab map must run everything static"

    seen.clear()
    monkeypatch.setattr(package_labs, "PACKAGE_LABS", {"next": "http://127.0.0.1:8000"})
    assert bridge.run(args) == 0
    assert seen["CVE-2026-29057"] is True          # next -> has a lab
    assert seen["CVE-2022-41919"] is False         # fastify -> no lab


def test_source_provtrail_missing_scan_does_not_fall_back(monkeypatch):
    import argparse
    called = {"feeds": False}
    monkeypatch.setattr(bridge, "feed_advisories",
                        lambda *a, **k: called.__setitem__("feeds", True) or [])
    args = argparse.Namespace(scan=str(FIXTURES / "nope.json"), source="provtrail",
                              no_probe=True, no_cache=True, format="text",
                              lookback=24, limit=25)
    advisories, source, _ = bridge._resolve_advisories(args)
    assert advisories == []
    assert source == "provtrail"
    assert called["feeds"] is False, "--source provtrail must never hit the feeds"


def test_default_scan_auto_discovered_when_no_scan_given(monkeypatch):
    """ProvTrail is the REAL default source: with no --scan given at all,
    a scan file at the conventional .provtrail/latest-scan.* location is
    used automatically, before ever falling back to feeds."""
    import argparse
    called = {"feeds": False}
    monkeypatch.setattr(bridge, "feed_advisories",
                        lambda *a, **k: called.__setitem__("feeds", True) or [])
    monkeypatch.setattr(bridge, "_DEFAULT_SCAN_CANDIDATES", (SARIF,))
    args = argparse.Namespace(scan=None, source="auto", no_probe=True,
                              no_cache=True, format="text", lookback=24, limit=25)
    advisories, source, scan_str = bridge._resolve_advisories(args)
    assert source == "provtrail"
    assert scan_str == str(SARIF)
    assert {a.advisory_id for a in advisories} == EXPECTED_IDS
    assert called["feeds"] is False, "a discoverable default scan must never hit the feeds"


def test_source_feeds_skips_default_scan_discovery(monkeypatch):
    """--source feeds is the explicit escape hatch: skips ProvTrail
    auto-discovery entirely even when a default scan file is discoverable."""
    import argparse
    called = {"feeds": False}
    monkeypatch.setattr(bridge, "feed_advisories",
                        lambda *a, **k: called.__setitem__("feeds", True) or [])
    monkeypatch.setattr(bridge, "_DEFAULT_SCAN_CANDIDATES", (SARIF,))
    args = argparse.Namespace(scan=None, source="feeds", no_probe=True,
                              no_cache=True, format="text", lookback=24, limit=25)
    advisories, source, scan_str = bridge._resolve_advisories(args)
    assert source == "feeds"
    assert scan_str is None
    assert called["feeds"] is True
