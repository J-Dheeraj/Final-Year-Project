"""Text/JSON report rendering for the final PipelineReport.

Extracted from cve_pipeline.py as part of the repo's src/ refactor.
`_extract_target_port` is imported lazily inside render_text (not at
module scope) to avoid a circular import: cve_pipeline.py imports
render_text/render_json from here. `from __future__ import annotations`
defers the `report: PipelineReport` type hint so this module doesn't
need to import PipelineReport just to satisfy the annotation.
"""
from __future__ import annotations

from pathlib import Path

def render_text(report: PipelineReport) -> str:
    import textwrap
    sep  = "=" * 70
    sep2 = "-" * 70
    W    = 68

    def wrap(text: str, indent: int = 4) -> str:
        return textwrap.fill(text or "(none)", width=W,
                             initial_indent=" " * indent,
                             subsequent_indent=" " * indent)

    lines = [
        sep,
        "  CVE PIPELINE REPORT",
        sep,
        f"  Pipeline ID  : {report.pipeline_id}",
        f"  CVE          : {report.cve_id}",
        f"  Generated    : {report.generated_at}",
        f"  Stages done  : {', '.join(report.stages_completed)}",
        f"  Stages failed: {', '.join(report.stages_failed) or 'none'}",
        "",
        sep2,
        "  ADVISORY",
        sep2,
    ]
    if report.advisory:
        a = report.advisory
        lines += [
            f"    GHSA ID    : {a.ghsa_id}",
            f"    CVE ID     : {a.cve_id}",
            f"    Package    : {a.package_name} ({a.ecosystem})",
            f"    Severity   : {a.severity}  CVSS {a.cvss_score}",
            f"    Affected   : {', '.join(a.affected_versions) or '(see advisory)'}",
            f"    Patched    : {', '.join(a.patched_versions)  or 'none listed'}",
        ]
        if a.file_locations:
            lines.append("    Files      :")
            for fl in a.file_locations[:5]:
                loc = fl.get("file", "")
                if "line_start" in fl:
                    loc += f"  lines {fl['line_start']}"
                    if "line_end" in fl:
                        loc += f"–{fl['line_end']}"
                lines.append(f"      {loc}")
        if a.root_cause:
            lines.append("    Root cause :")
            lines.append(wrap(a.root_cause[:400], indent=6))

    lines += [
        "",
        sep2,
        "  VULNERABILITY ANALYSIS",
        sep2,
    ]
    if report.analysis:
        an = report.analysis
        lines += [
            f"    Class      : {an.vulnerability_class}",
            f"    CWE        : {an.cwe}",
            f"    Confidence : {an.confidence}",
        ]
        if an.unsafe_patterns:
            lines.append("    Unsafe patterns:")
            for p in an.unsafe_patterns[:3]:
                lines += [
                    f"      [{p.get('function_name','?')} line {p.get('lineno','?')}]",
                    f"      {p.get('code','')[:90]}",
                ]
        if an.fix_summary:
            lines.append("    Fix :")
            lines.append(wrap(an.fix_summary, indent=6))
        if an.trigger_conditions:
            lines.append("    Trigger :")
            lines.append(wrap(an.trigger_conditions, indent=6))

    lines += ["", sep2, f"  VULNERABILITY PROBE — {report.ssrf_probe.probe_type if report.ssrf_probe else 'N/A'}", sep2]
    if report.ssrf_probe:
        sp = report.ssrf_probe
        if sp.ran:
            def verd_icon(v):
                return "✓" if v and "PASS" in v else ("✗" if v and ("FAIL" in v or "EXPLOIT" in v) else "?")
            lines += [
                f"    Probe type         : {sp.probe_type}",
                f"    Vulnerable mode    : {verd_icon(sp.vulnerable_verdict)} {sp.vulnerable_verdict}",
                f"      {sp.vulnerable_detail or ''}",
                f"    Patched mode       : {verd_icon(sp.patched_verdict)} {sp.patched_verdict}",
                f"      {sp.patched_detail or ''}",
                f"    PoC payload        : {sp.poc_payload}",
                f"    Probe elapsed      : {sp.elapsed_s}s",
            ]
        else:
            lines.append(f"    Skipped — {sp.skip_reason}")

        # ── CURL TEST COMMANDS ────────────────────────────────────────────────
        if sp.curl_commands:
            lines += ["", sep2, "  CURL TEST COMMANDS", sep2]
            for line in sp.curl_commands:
                lines.append(f"    {line}")

        # ── BYPASS ANALYSIS ───────────────────────────────────────────────────
        if sp.bypass_results:
            lines += ["", sep2, "  BYPASS ANALYSIS vs PATCHED MODE", sep2]
            for i, b in enumerate(sp.bypass_results, 1):
                tested_tag = "(live test)" if b.get("tested") else "(theoretical)"
                lines += [
                    f"",
                    f"  [{i}] {b.get('name','?')}  {tested_tag}",
                    f"    Technique : {b.get('technique','')}",
                    f"    Payload   : {b.get('payload', b.get('url',''))}",
                    f"    curl      : {b.get('curl','')}",
                    f"    Result    : {b.get('verdict','')}",
                ]

    lines += ["", sep2, "  FINAL REPORT", sep2]
    lines.append(f"  Overall risk : {report.overall_risk}")
    lines.append("")
    lines.append("  Summary:")
    lines.append(wrap(report.summary, indent=4))
    lines.append("")
    lines.append("  Recommendations:")
    for i, rec in enumerate(report.recommendations, 1):
        lines.append(wrap(f"{i}. {rec}", indent=4))

    # ── Exploit artifacts (Stage 3.5) ─────────────────────────────────────────
    art = report.exploit_artifacts
    if art:
        lines += ["", sep2, "  EXPLOIT ARTIFACTS", sep2]
        if art.generated:
            lines += [
                f"  Status      : GENERATED (iter 1, v0)",
                f"  Generation  : {art.generation_outcome or 'n/a'}"
                + (f" [{art.generation_backend}:{art.generation_model}]"
                   if art.generation_backend and art.generation_backend != 'none' else ''),
                f"  PoC         : {art.poc_path}",
                f"  Target app  : {art.target_app_path}",
                f"  Summary     : {art.poc_summary}",
            ]
            if art.executed:
                lines += [
                    "",
                    f"  Executed              : True",
                    f"  Exit code              : {art.exit_code}",
                    f"  Dynamically confirmed  : {art.dynamically_confirmed}",
                ]
            elif art.execution_skip_reason:
                lines += ["", f"  Execution   : SKIPPED — {art.execution_skip_reason}"]

            if art.patch_attempted:
                lines += [
                    "",
                    f"  Patch (Stage 3.8)      : {art.patch_summary}",
                    f"  Patched target         : {art.patched_target_path}",
                    f"  Patch validated        : {art.patch_validated}",
                ]
                if not art.patch_validated:
                    lines.append(f"    {art.patch_validation_log[:300]}")
            elif art.patch_skip_reason:
                lines += ["", f"  Patch (Stage 3.8)      : SKIPPED — {art.patch_skip_reason}"]

            from cve_pipeline import _extract_target_port  # lazy: avoid circular import
            port = _extract_target_port(Path(art.target_app_path)) if art.target_app_path else 5000
            lines += [
                "",
                "  Manual re-run:",
                f"    # Terminal 1 — start vulnerable target",
                f"    python \"{art.target_app_path}\"",
                f"    # Terminal 2 — run exploit",
                f"    python \"{art.poc_path}\" 127.0.0.1:{port}",
            ]
        else:
            lines.append(f"  Status      : SKIPPED — {art.skip_reason}")

    if report.errors:
        lines += ["", sep2, "  ERRORS", sep2]
        for err in report.errors:
            lines.append(f"    ! {err}")

    lines.append(sep)
    return "\n".join(lines)


def render_json(report: PipelineReport) -> str:
    return report.model_dump_json(indent=2)

