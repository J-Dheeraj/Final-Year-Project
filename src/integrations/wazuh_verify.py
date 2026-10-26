"""Cross-reference pipeline CVE results against Wazuh's vulnerability detector.

Usage:
    python -m src.integrations.wazuh_verify [--wazuh-url URL] [--reports-dir DIR]

Wazuh's vulnerability detector scans installed packages against NVD/OVAL and
stores findings in its alerts index. This module queries that index for the
same CVE IDs the pipeline already confirmed and produces a two-source
agreement table:

    pipeline dynamically_confirmed  +  Wazuh detected present
    ──────────────────────────────────────────────────────────
    Both agree (True/True)  → strongest evidence (two independent sources)
    Pipeline only           → exploitability confirmed, Wazuh pkg not installed
    Wazuh only              → presence confirmed, exploit not attempted
    Neither                 → not found by either source

When Wazuh is unreachable, the script prints a dry-run table showing what it
would query and exits cleanly — it never fails hard.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("cve_pipeline.wazuh")

_DEFAULT_REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"
_DEFAULT_WAZUH_URL = os.environ.get("WAZUH_URL", "https://localhost:55000")
_DEFAULT_WAZUH_USER = os.environ.get("WAZUH_USER", "wazuh-wui")
_DEFAULT_WAZUH_PASS = os.environ.get("WAZUH_PASS", "")


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PipelineResult:
    cve_id: str
    package_name: str
    vuln_class: str
    affected_versions: list[str]
    dynamically_confirmed: bool


@dataclass(frozen=True)
class WazuhFinding:
    cve_id: str
    package: str
    version: str
    severity: str
    agent_name: str


@dataclass
class CrossRefRow:
    cve_id: str
    package_name: str
    vuln_class: str
    pipeline_confirmed: bool
    wazuh_detected: bool
    wazuh_details: list[WazuhFinding] = field(default_factory=list)

    @property
    def agreement(self) -> str:
        if self.pipeline_confirmed and self.wazuh_detected:
            return "BOTH"
        if self.pipeline_confirmed:
            return "pipeline only"
        if self.wazuh_detected:
            return "wazuh only"
        return "neither"


# ── Load pipeline results ─────────────────────────────────────────────────────

def load_pipeline_results(reports_dir: Path) -> list[PipelineResult]:
    results: list[PipelineResult] = []
    for report_path in sorted(reports_dir.glob("*/report.json")):
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            advisory = data.get("advisory", {})
            analysis = data.get("analysis", {})
            artifacts = data.get("exploit_artifacts", {})
            results.append(PipelineResult(
                cve_id=data.get("cve_id", report_path.parent.name),
                package_name=advisory.get("package_name") or "unknown",
                vuln_class=analysis.get("vulnerability_class") or "unknown",
                affected_versions=advisory.get("affected_versions") or [],
                dynamically_confirmed=bool(artifacts.get("dynamically_confirmed", False)),
            ))
        except Exception as exc:
            log.warning("Could not parse %s: %s", report_path, exc)
    return results


# ── Wazuh API client ──────────────────────────────────────────────────────────

def _no_verify_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class WazuhClient:
    def __init__(self, base_url: str, user: str, password: str) -> None:
        self._base = base_url.rstrip("/")
        self._user = user
        self._password = password
        self._token: Optional[str] = None

    def _get_token(self) -> str:
        """POST /security/user/authenticate → JWT token."""
        credentials = f"{self._user}:{self._password}"
        encoded = b64encode(credentials.encode()).decode()
        url = f"{self._base}/security/user/authenticate"
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"Authorization": f"Basic {encoded}"},
        )
        with urllib.request.urlopen(req, context=_no_verify_ctx(), timeout=10) as resp:
            body = json.loads(resp.read())
        return body["data"]["token"]

    def _auth_headers(self) -> dict[str, str]:
        if not self._token:
            self._token = self._get_token()
        return {"Authorization": f"Bearer {self._token}"}

    def get_vulnerabilities_for_cve(self, cve_id: str) -> list[WazuhFinding]:
        """Query /vulnerability/agents for findings matching cve_id."""
        url = (
            f"{self._base}/vulnerability/agents"
            f"?cve={urllib.parse.quote(cve_id)}&limit=100"
        )
        req = urllib.request.Request(url, headers=self._auth_headers())
        with urllib.request.urlopen(req, context=_no_verify_ctx(), timeout=10) as resp:
            body = json.loads(resp.read())
        findings: list[WazuhFinding] = []
        for item in body.get("data", {}).get("affected_items", []):
            for vuln in item.get("vulnerabilities", []):
                if vuln.get("cve") == cve_id:
                    findings.append(WazuhFinding(
                        cve_id=cve_id,
                        package=vuln.get("name", ""),
                        version=vuln.get("version", ""),
                        severity=vuln.get("severity", ""),
                        agent_name=item.get("agent", {}).get("name", ""),
                    ))
        return findings


# ── Cross-reference logic ─────────────────────────────────────────────────────

def build_crossref(
    pipeline_results: list[PipelineResult],
    client: Optional[WazuhClient],
) -> list[CrossRefRow]:
    rows: list[CrossRefRow] = []
    for pr in pipeline_results:
        findings: list[WazuhFinding] = []
        if client is not None:
            try:
                findings = client.get_vulnerabilities_for_cve(pr.cve_id)
            except Exception as exc:
                log.warning("Wazuh query failed for %s: %s", pr.cve_id, exc)
        rows.append(CrossRefRow(
            cve_id=pr.cve_id,
            package_name=pr.package_name,
            vuln_class=pr.vuln_class,
            pipeline_confirmed=pr.dynamically_confirmed,
            wazuh_detected=len(findings) > 0,
            wazuh_details=findings,
        ))
    return rows


# ── Output ────────────────────────────────────────────────────────────────────

def print_table(rows: list[CrossRefRow], dry_run: bool = False) -> None:
    if dry_run:
        print("\n[DRY RUN] Wazuh unreachable — showing pipeline results only\n")

    col_cve = 22
    col_pkg = 18
    col_cls = 28
    header = (
        f"{'CVE':<{col_cve}} {'Package':<{col_pkg}} {'Class':<{col_cls}}"
        f" {'Pipeline':>9} {'Wazuh':>6}  Agreement"
    )
    print(header)
    print("-" * len(header))
    for r in rows:
        pipeline_sym = "confirmed" if r.pipeline_confirmed else "failed"
        wazuh_sym = "detected" if r.wazuh_detected else ("?" if dry_run else "absent")
        print(
            f"{r.cve_id:<{col_cve}} {r.package_name:<{col_pkg}} {r.vuln_class:<{col_cls}}"
            f" {pipeline_sym:>9} {wazuh_sym:>6}  {r.agreement}"
        )
        for f in r.wazuh_details:
            print(f"  └─ agent={f.agent_name}  {f.package}@{f.version}  severity={f.severity}")

    both = sum(1 for r in rows if r.pipeline_confirmed and r.wazuh_detected)
    pipeline_only = sum(1 for r in rows if r.pipeline_confirmed and not r.wazuh_detected)
    wazuh_only = sum(1 for r in rows if not r.pipeline_confirmed and r.wazuh_detected)
    neither = sum(1 for r in rows if not r.pipeline_confirmed and not r.wazuh_detected)
    print(f"\nSummary: {both} both / {pipeline_only} pipeline-only / {wazuh_only} wazuh-only / {neither} neither")


def export_json(rows: list[CrossRefRow], out_path: Path) -> None:
    data = [
        {
            "cve_id": r.cve_id,
            "package_name": r.package_name,
            "vuln_class": r.vuln_class,
            "pipeline_confirmed": r.pipeline_confirmed,
            "wazuh_detected": r.wazuh_detected,
            "agreement": r.agreement,
            "wazuh_details": [
                {
                    "package": f.package,
                    "version": f.version,
                    "severity": f.severity,
                    "agent": f.agent_name,
                }
                for f in r.wazuh_details
            ],
        }
        for r in rows
    ]
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"JSON written → {out_path}")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(
        description="Cross-reference pipeline CVE results against Wazuh vulnerability detector"
    )
    parser.add_argument(
        "--wazuh-url", default=_DEFAULT_WAZUH_URL,
        help="Wazuh manager API base URL (default: %(default)s)",
    )
    parser.add_argument("--wazuh-user", default=_DEFAULT_WAZUH_USER)
    parser.add_argument(
        "--wazuh-pass", default=_DEFAULT_WAZUH_PASS,
        help="Wazuh API password (or set WAZUH_PASS env var)",
    )
    parser.add_argument("--reports-dir", type=Path, default=_DEFAULT_REPORTS_DIR)
    parser.add_argument(
        "--out-json", type=Path, default=None,
        help="Optional path to write cross-reference JSON",
    )
    args = parser.parse_args()

    pipeline_results = load_pipeline_results(args.reports_dir)
    if not pipeline_results:
        print(f"No report.json files found under {args.reports_dir}")
        return

    # Try to connect; fall back to dry-run if Wazuh isn't available
    client: Optional[WazuhClient] = None
    dry_run = False
    if args.wazuh_pass:
        try:
            c = WazuhClient(args.wazuh_url, args.wazuh_user, args.wazuh_pass)
            c._get_token()
            client = c
        except Exception as exc:
            log.warning(
                "Cannot reach Wazuh at %s: %s — running in dry-run mode",
                args.wazuh_url, exc,
            )
            dry_run = True
    else:
        print("No WAZUH_PASS set — running in dry-run mode (pipeline results only)")
        dry_run = True

    rows = build_crossref(pipeline_results, client)
    print_table(rows, dry_run=dry_run)

    if args.out_json:
        export_json(rows, args.out_json)


if __name__ == "__main__":
    main()
