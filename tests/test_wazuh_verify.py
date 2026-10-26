"""Offline tests for src/integrations/wazuh_verify.py.

Every test runs with no real network or Wazuh instance.  The WazuhClient is
either monkeypatched or never instantiated (dry-run path).  Tests cover:

  - load_pipeline_results: normal parse, null package_name, missing file, bad JSON
  - CrossRefRow.agreement: all four cases
  - build_crossref: client=None (dry-run), client present (success and failure)
  - print_table: output lines and summary counts
  - export_json: round-trip correctness
  - WazuhClient.get_vulnerabilities_for_cve: response parsing
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from src.integrations.wazuh_verify import (  # noqa: E402
    CrossRefRow,
    PipelineResult,
    WazuhClient,
    WazuhFinding,
    build_crossref,
    export_json,
    load_pipeline_results,
    print_table,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_report(tmp_path: Path, cve_id: str, **overrides) -> Path:
    """Write a minimal report.json and return its parent directory."""
    cve_dir = tmp_path / cve_id
    cve_dir.mkdir()
    base = {
        "cve_id": cve_id,
        "advisory": {
            "package_name": "somepkg",
            "affected_versions": ["< 1.2.3"],
        },
        "analysis": {"vulnerability_class": "SQL Injection"},
        "exploit_artifacts": {"dynamically_confirmed": True},
    }
    base.update(overrides)
    (cve_dir / "report.json").write_text(json.dumps(base), encoding="utf-8")
    return cve_dir


def _pipeline_result(**kwargs) -> PipelineResult:
    defaults = dict(
        cve_id="CVE-2026-00001",
        package_name="somepkg",
        vuln_class="SQL Injection",
        affected_versions=["< 1.0"],
        dynamically_confirmed=True,
    )
    defaults.update(kwargs)
    return PipelineResult(**defaults)


# ── load_pipeline_results ─────────────────────────────────────────────────────

def test_load_reads_basic_fields(tmp_path):
    _make_report(tmp_path, "CVE-2026-00001")
    results = load_pipeline_results(tmp_path)
    assert len(results) == 1
    r = results[0]
    assert r.cve_id == "CVE-2026-00001"
    assert r.package_name == "somepkg"
    assert r.vuln_class == "SQL Injection"
    assert r.dynamically_confirmed is True


def test_load_null_package_name_becomes_unknown(tmp_path):
    _make_report(tmp_path, "CVE-2026-00002",
                 advisory={"package_name": None, "affected_versions": []})
    results = load_pipeline_results(tmp_path)
    assert results[0].package_name == "unknown"


def test_load_missing_exploit_artifacts_gives_false(tmp_path):
    cve_dir = tmp_path / "CVE-2026-00003"
    cve_dir.mkdir()
    data = {
        "cve_id": "CVE-2026-00003",
        "advisory": {"package_name": "pkg", "affected_versions": []},
        "analysis": {"vulnerability_class": "XSS"},
    }
    (cve_dir / "report.json").write_text(json.dumps(data), encoding="utf-8")
    results = load_pipeline_results(tmp_path)
    assert results[0].dynamically_confirmed is False


def test_load_bad_json_is_skipped(tmp_path):
    cve_dir = tmp_path / "CVE-2026-00004"
    cve_dir.mkdir()
    (cve_dir / "report.json").write_text("not json", encoding="utf-8")
    results = load_pipeline_results(tmp_path)
    assert results == []


def test_load_empty_dir_returns_empty(tmp_path):
    assert load_pipeline_results(tmp_path) == []


def test_load_multiple_reports_sorted(tmp_path):
    for cve in ["CVE-2026-00003", "CVE-2026-00001", "CVE-2026-00002"]:
        _make_report(tmp_path, cve)
    results = load_pipeline_results(tmp_path)
    assert [r.cve_id for r in results] == [
        "CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003"
    ]


# ── CrossRefRow.agreement ─────────────────────────────────────────────────────

def test_agreement_both():
    row = CrossRefRow("CVE-X", "pkg", "SQLi", pipeline_confirmed=True, wazuh_detected=True)
    assert row.agreement == "BOTH"


def test_agreement_pipeline_only():
    row = CrossRefRow("CVE-X", "pkg", "SQLi", pipeline_confirmed=True, wazuh_detected=False)
    assert row.agreement == "pipeline only"


def test_agreement_wazuh_only():
    row = CrossRefRow("CVE-X", "pkg", "SQLi", pipeline_confirmed=False, wazuh_detected=True)
    assert row.agreement == "wazuh only"


def test_agreement_neither():
    row = CrossRefRow("CVE-X", "pkg", "SQLi", pipeline_confirmed=False, wazuh_detected=False)
    assert row.agreement == "neither"


# ── build_crossref ────────────────────────────────────────────────────────────

def test_build_crossref_no_client_no_wazuh_detection():
    prs = [_pipeline_result(dynamically_confirmed=True)]
    rows = build_crossref(prs, client=None)
    assert len(rows) == 1
    assert rows[0].wazuh_detected is False
    assert rows[0].pipeline_confirmed is True
    assert rows[0].agreement == "pipeline only"


def test_build_crossref_with_client_finding():
    finding = WazuhFinding(
        cve_id="CVE-2026-00001", package="somepkg",
        version="1.0.0", severity="High", agent_name="lab-host",
    )
    mock_client = MagicMock(spec=WazuhClient)
    mock_client.get_vulnerabilities_for_cve.return_value = [finding]

    rows = build_crossref([_pipeline_result(dynamically_confirmed=True)], client=mock_client)
    assert rows[0].wazuh_detected is True
    assert rows[0].agreement == "BOTH"
    assert rows[0].wazuh_details[0].agent_name == "lab-host"


def test_build_crossref_wazuh_query_failure_degrades_gracefully():
    mock_client = MagicMock(spec=WazuhClient)
    mock_client.get_vulnerabilities_for_cve.side_effect = ConnectionError("refused")

    rows = build_crossref([_pipeline_result(dynamically_confirmed=True)], client=mock_client)
    assert rows[0].wazuh_detected is False
    assert rows[0].pipeline_confirmed is True


def test_build_crossref_empty_wazuh_response():
    mock_client = MagicMock(spec=WazuhClient)
    mock_client.get_vulnerabilities_for_cve.return_value = []

    rows = build_crossref([_pipeline_result(dynamically_confirmed=False)], client=mock_client)
    assert rows[0].agreement == "neither"


# ── print_table ───────────────────────────────────────────────────────────────

def test_print_table_dry_run_shows_banner(capsys):
    rows = [
        CrossRefRow("CVE-2026-00001", "pkg", "SQLi", True, False),
        CrossRefRow("CVE-2026-00002", "pkg2", "XSS", False, False),
    ]
    print_table(rows, dry_run=True)
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "pipeline only" in out
    assert "neither" in out


def test_print_table_summary_counts(capsys):
    rows = [
        CrossRefRow("CVE-A", "p", "C", True, True),
        CrossRefRow("CVE-B", "p", "C", True, False),
        CrossRefRow("CVE-C", "p", "C", False, True),
        CrossRefRow("CVE-D", "p", "C", False, False),
    ]
    print_table(rows, dry_run=False)
    out = capsys.readouterr().out
    assert "1 both" in out
    assert "1 pipeline-only" in out
    assert "1 wazuh-only" in out
    assert "1 neither" in out


def test_print_table_wazuh_detail_lines(capsys):
    finding = WazuhFinding("CVE-A", "somepkg", "1.0.0", "Critical", "agent-01")
    rows = [CrossRefRow("CVE-A", "somepkg", "SQLi", True, True, wazuh_details=[finding])]
    print_table(rows, dry_run=False)
    out = capsys.readouterr().out
    assert "agent-01" in out
    assert "Critical" in out


# ── export_json ───────────────────────────────────────────────────────────────

def test_export_json_round_trip(tmp_path):
    finding = WazuhFinding("CVE-A", "pkg", "1.0", "High", "agent-01")
    rows = [CrossRefRow("CVE-A", "pkg", "SQLi", True, True, wazuh_details=[finding])]
    out_path = tmp_path / "out.json"
    export_json(rows, out_path)

    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-A"
    assert data[0]["pipeline_confirmed"] is True
    assert data[0]["wazuh_detected"] is True
    assert data[0]["agreement"] == "BOTH"
    assert data[0]["wazuh_details"][0]["agent"] == "agent-01"


def test_export_json_empty_details(tmp_path):
    rows = [CrossRefRow("CVE-B", "pkg", "XSS", False, False)]
    out_path = tmp_path / "out.json"
    export_json(rows, out_path)
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data[0]["wazuh_details"] == []


# ── WazuhClient.get_vulnerabilities_for_cve ───────────────────────────────────

def test_wazuh_client_parses_findings():
    api_response = {
        "data": {
            "affected_items": [
                {
                    "agent": {"name": "lab-host"},
                    "vulnerabilities": [
                        {
                            "cve": "CVE-2026-00001",
                            "name": "somepkg",
                            "version": "1.0.0",
                            "severity": "High",
                        },
                        {
                            # different CVE — must be filtered out
                            "cve": "CVE-2026-99999",
                            "name": "otherpkg",
                            "version": "2.0.0",
                            "severity": "Low",
                        },
                    ],
                }
            ]
        }
    }
    client = WazuhClient("https://localhost:55000", "user", "pass")
    client._token = "fake-token"

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(api_response).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("src.integrations.wazuh_verify.urllib.request.urlopen", return_value=mock_resp):
        findings = client.get_vulnerabilities_for_cve("CVE-2026-00001")

    assert len(findings) == 1
    f = findings[0]
    assert f.cve_id == "CVE-2026-00001"
    assert f.package == "somepkg"
    assert f.version == "1.0.0"
    assert f.severity == "High"
    assert f.agent_name == "lab-host"


def test_wazuh_client_filters_other_cves():
    """Only findings matching the queried CVE ID are returned."""
    api_response = {
        "data": {
            "affected_items": [
                {
                    "agent": {"name": "agent-01"},
                    "vulnerabilities": [
                        {"cve": "CVE-2026-99999", "name": "pkg", "version": "1.0", "severity": "Low"},
                    ],
                }
            ]
        }
    }
    client = WazuhClient("https://localhost:55000", "user", "pass")
    client._token = "fake-token"

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(api_response).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("src.integrations.wazuh_verify.urllib.request.urlopen", return_value=mock_resp):
        findings = client.get_vulnerabilities_for_cve("CVE-2026-00001")

    assert findings == []


def test_wazuh_client_empty_response():
    api_response = {"data": {"affected_items": []}}
    client = WazuhClient("https://localhost:55000", "user", "pass")
    client._token = "fake-token"

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(api_response).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("src.integrations.wazuh_verify.urllib.request.urlopen", return_value=mock_resp):
        findings = client.get_vulnerabilities_for_cve("CVE-2026-00001")

    assert findings == []
