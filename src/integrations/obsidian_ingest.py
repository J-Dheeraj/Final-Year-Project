"""Best-effort auto-ingest of a completed CVE report into the Obsidian wiki.

Extracted from cve_pipeline.py as part of the repo's src/ refactor. Uses
its own logger (rather than importing cve_pipeline's `log`) so this
module has no import-time dependency on cve_pipeline at all - it only
needs a PipelineReport-shaped object, never the module itself.
"""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("cve_pipeline.obsidian")

# ── Obsidian vault auto-ingest ────────────────────────────────────────────────

_VAULT_PATH = Path(os.environ.get(
    "OBSIDIAN_VAULT",
    r"C:\Users\dheer\obsidian-vault"
))
_CVE_WIKI = _VAULT_PATH / "wiki" / "domains" / "cve-automation"


def obsidian_ingest(cve_id: str, report: "PipelineReport", vault_path: Path | None = None) -> None:
    """
    After a CVE pipeline run, append a row to the processed-cves wiki page
    and create/update a dedicated wiki page for the CVE.

    Silent on any error — the pipeline must not fail because of wiki I/O.
    """
    try:
        vp = vault_path or _VAULT_PATH
        cve_wiki = vp / "wiki" / "domains" / "cve-automation"
        cve_wiki.mkdir(parents=True, exist_ok=True)

        # ── 1. Append row to processed-cves.md ───────────────────────────────
        processed_path = cve_wiki / "processed-cves.md"
        adv = report.advisory
        ana = report.analysis
        prb = report.ssrf_probe

        severity = adv.severity or "N/A" if adv else "N/A"
        cvss     = str(adv.cvss_score) if adv and adv.cvss_score else "N/A"
        vuln_cls = ana.vulnerability_class if ana else "UNKNOWN"
        risk     = report.overall_risk or "N/A"
        desc     = (adv.root_cause or "")[:80].replace("|", "/").replace("\n", " ") if adv else "N/A"

        row = f"| {cve_id} | {severity} | {cvss} | {vuln_cls} | {risk} | {desc} |\n"

        if processed_path.exists():
            content = processed_path.read_text(encoding="utf-8")
            # Avoid duplicate rows
            if cve_id not in content:
                # Insert row after the header separator line of the table
                lines = content.splitlines(keepends=True)
                # Find the line starting with "| CVE-" or after the "| ---" separator
                insert_at = len(lines)
                for i, line in enumerate(lines):
                    if line.startswith("| ---") or line.startswith("|---"):
                        insert_at = i + 1
                        break
                lines.insert(insert_at, row)
                processed_path.write_text("".join(lines), encoding="utf-8")
        else:
            # Create minimal file if missing
            processed_path.write_text(
                "---\ntype: log\ntitle: Processed CVEs\nupdated: " +
                datetime.now(timezone.utc).strftime("%Y-%m-%d") + "\n---\n\n" +
                "# Processed CVEs\n\n" +
                "| CVE ID | Severity | CVSS | Vuln Class | Risk | Summary |\n" +
                "| ------ | -------- | ---- | ---------- | ---- | ------- |\n" +
                row,
                encoding="utf-8"
            )

        # ── 2. Write a dedicated wiki page for this CVE ───────────────────────
        cve_page = cve_wiki / f"{cve_id}.md"
        probe_section = ""
        if prb and prb.ran:
            probe_section = (
                f"\n## Probe Results\n\n"
                f"- Vulnerable mode: {prb.vulnerable_verdict or '—'}\n"
                f"- Patched mode: {prb.patched_verdict or '—'}\n"
                f"- SSRF confirmed: {prb.ssrf_confirmed}\n"
            )
            if prb.bypass_results:
                probe_section += "\n### Bypass Results\n\n"
                probe_section += "| Technique | Verdict |\n|---|---|\n"
                for br in prb.bypass_results:
                    probe_section += f"| {br.get('technique','?')} | {br.get('verdict','?')} |\n"
            if prb.curl_commands:
                probe_section += "\n### Curl Commands\n\n```bash\n"
                probe_section += "\n".join(prb.curl_commands[:5])
                probe_section += "\n```\n"

        recs_section = ""
        if report.recommendations:
            recs_section = "\n## Recommendations\n\n" + "\n".join(
                f"- {r}" for r in report.recommendations
            ) + "\n"

        page_content = (
            f"---\n"
            f"type: cve-report\n"
            f"cve_id: {cve_id}\n"
            f"severity: {severity}\n"
            f"cvss: {cvss}\n"
            f"vuln_class: {vuln_cls}\n"
            f"overall_risk: {risk}\n"
            f"generated: {report.generated_at}\n"
            f"status: auto-ingested\n"
            f"related:\n"
            f"  - \"[[processed-cves]]\"\n"
            f"  - \"[[pipeline-architecture]]\"\n"
            f"---\n\n"
            f"# {cve_id}\n\n"
            f"**Severity**: {severity} | **CVSS**: {cvss} | **Class**: {vuln_cls} | **Risk**: {risk}\n\n"
        )
        if adv and adv.root_cause:
            page_content += f"## Root Cause\n\n{adv.root_cause}\n\n"
        if ana and getattr(ana, "exploit_scenario", None):
            page_content += f"## Exploit Scenario\n\n{ana.exploit_scenario}\n\n"
        if ana and getattr(ana, "fix_summary", None):
            page_content += f"## Fix Summary\n\n{ana.fix_summary}\n\n"
        page_content += probe_section + recs_section

        if report.summary:
            page_content += f"\n## Summary\n\n{report.summary}\n"

        cve_page.write_text(page_content, encoding="utf-8")

        # ── 3. Update hot.md with one-liner ───────────────────────────────────
        hot_path = vp / "wiki" / "hot.md"
        if hot_path.exists():
            hot = hot_path.read_text(encoding="utf-8")
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            oneliner = (
                f"\n{today}: {cve_id} ingested — {severity} {cvss} {vuln_cls} "
                f"risk={risk}. {desc[:60]}\n"
            )
            # Insert after "## Last Updated" header
            hot = hot.replace("## Last Updated\n", "## Last Updated\n" + oneliner, 1)
            hot_path.write_text(hot, encoding="utf-8")

        log.info("[obsidian] %s filed → %s", cve_id, cve_page.name)

    except Exception as exc:
        log.debug("[obsidian] ingest skipped for %s: %s", cve_id, exc)

