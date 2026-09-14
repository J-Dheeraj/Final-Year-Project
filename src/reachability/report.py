"""Stage 6: report generation (JSON + Markdown)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .reachability import ReachabilityResult
from .testing import TestOutcome


@dataclass
class RunStats:
    reachability: ReachabilityResult
    triage_count: int
    flagged_count: int
    verified_count: int
    # A finding whose auto-generated exploit definitively did NOT reproduce
    # is held back from patch generation by default - see pipeline.py's
    # "come up with the fix only after you exploit" gate. These two counts
    # make that gate's effect visible in the report rather than a patch
    # silently missing from it with no explanation.
    exploit_confirmed_count: int = 0
    exploit_unconfirmed_count: int = 0
    timings_sec: dict[str, float] = field(default_factory=dict)


def to_json(stats: RunStats, outcomes: list[TestOutcome]) -> dict:
    return {
        "summary": {
            "total_functions_parsed": stats.reachability.total_functions,
            "reachable_functions": len(stats.reachability.reachable),
            "reduction_pct": round(stats.reachability.reduction_pct, 1),
            "missing_entrypoints": stats.reachability.missing_entrypoints,
            "units_triaged": stats.triage_count,
            "flagged_by_triage": stats.flagged_count,
            "confirmed_after_verification": stats.verified_count,
            "exploit_confirmed": stats.exploit_confirmed_count,
            "exploit_unconfirmed_patch_withheld": stats.exploit_unconfirmed_count,
            "timings_sec": {k: round(v, 3) for k, v in stats.timings_sec.items()},
        },
        "findings": [
            {
                "function": o.patch.finding.triage.function.name,
                "file": o.patch.finding.triage.function.file,
                "line": o.patch.finding.triage.function.start_line,
                "cwe": o.patch.finding.triage.cwe,
                "triage_confidence": o.patch.finding.triage.confidence,
                "verify_confidence": o.patch.finding.confidence,
                "rationale": o.patch.finding.rationale,
                "exploit_method": o.patch.exploit_method,
                "exploit_confirmed": o.patch.exploit_confirmed,
                "patch_method": o.patch.method,
                "diff": o.patch.diff,
                "compiler_available": o.compiler_available,
                "compiles": o.compiles,
                "poc_ran": o.poc_ran,
                "poc_passed": o.poc_passed,
                "original_compiles": o.original_compiles,
                "original_poc_crashed": o.original_poc_crashed,
                "fix_confirmed": o.fix_confirmed,
                "test_log": o.log[-2000:],
            }
            for o in outcomes
        ],
    }


def to_markdown(stats: RunStats, outcomes: list[TestOutcome]) -> str:
    r = stats.reachability
    lines = [
        "# reachcrs report",
        "",
        "## Reachability filtering",
        f"- {r.total_functions} functions parsed",
        f"- {len(r.reachable)} reachable from stated entry points "
        f"({r.reduction_pct:.1f}% reduction in analysis scope)",
    ]
    if r.missing_entrypoints:
        lines.append(f"- ⚠ entry points not found in source: {', '.join(r.missing_entrypoints)}")
    lines += [
        "",
        "## Triage",
        f"- {stats.triage_count} reachable units analyzed",
        f"- {stats.flagged_count} flagged as potentially vulnerable",
        f"- {stats.verified_count} survived adversarial verification",
        "",
        "## Exploit (proof-of-vulnerability, before any patch is generated)",
        f"- {stats.exploit_confirmed_count} confirmed by a generated exploit "
        f"that actually reproduced the bug",
        f"- {stats.exploit_unconfirmed_count} held back from patch generation: "
        f"the generated exploit compiled and ran but did NOT reproduce it",
        "",
        "## Findings",
    ]
    if not outcomes:
        lines.append("\nNo verified findings.")
    for o in outcomes:
        f = o.patch.finding.triage.function
        lines += [
            f"\n### `{f.name}` — {o.patch.finding.triage.cwe} ({f.file}:{f.start_line})",
            f"- verify confidence: {o.patch.finding.confidence:.2f}",
            f"- rationale: {o.patch.finding.rationale}",
            f"- exploit: {o.patch.exploit_method or 'not generated'} | "
            f"reproduced pre-patch: {o.patch.exploit_confirmed}",
            f"- patch method: `{o.patch.method}`",
            f"- compiler available: {o.compiler_available} | original compiles: "
            f"{o.original_compiles} | patched compiles: {o.compiles}",
            f"- PoC on original crashed: {o.original_poc_crashed} | "
            f"PoC on patched crashed: {None if o.poc_passed is None else not o.poc_passed}",
            f"- **fix confirmed (bug reproduced pre-patch AND gone post-patch): {o.fix_confirmed}**",
            "",
            "```diff",
            o.patch.diff,
            "```",
        ]
    if stats.timings_sec:
        lines += ["", "## Timing"]
        for stage, secs in stats.timings_sec.items():
            lines.append(f"- {stage}: {secs:.3f}s")
    return "\n".join(lines)


def write_report(stats: RunStats, outcomes: list[TestOutcome], out_path: Path) -> None:
    data = to_json(stats, outcomes)
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    md_path = out_path.with_suffix(".md")
    md_path.write_text(to_markdown(stats, outcomes), encoding="utf-8")
