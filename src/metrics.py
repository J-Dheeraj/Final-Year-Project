"""Experiment/metrics harness — scores reports/*/report.json the way
AIxCC/OSS-CRS report results: bugs confirmed, PoV rate, patch-validation
rate, wall-clock time, and an LLM-call count as a crude budget proxy.

Real, not aspirational: every number here is read directly off a
report.json already on disk, produced by a real pipeline run - nothing
here re-runs the pipeline or estimates anything the pipeline itself
didn't already record. Run as `python -m src.metrics` from the repo
root; writes reports/METRICS.md and prints a summary to stdout.
"""
from __future__ import annotations

import json
import statistics
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"


def _load_reports() -> list[dict]:
    reports = []
    for path in sorted(REPORTS_DIR.glob("CVE-*/report.json")):
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def _llm_call_estimate(report: dict) -> int:
    """Crude proxy for LLM-call budget: count refinement attempts whose
    source is 'llm' (Stage 3.7), plus 1 if a patch was attempted (Stage
    3.8 makes exactly one call per attempt). Stage 2's own classification
    call and Stage 3.5's generation call aren't separately logged on the
    report today, so this under-counts real usage - stated here rather
    than silently presented as exact."""
    art = report.get("exploit_artifacts") or {}
    calls = sum(1 for e in art.get("refinement_history", []) if e.get("source") == "llm")
    if art.get("patch_attempted"):
        calls += 1
    return calls


def compute_metrics() -> dict:
    reports = _load_reports()
    n = len(reports)
    if n == 0:
        return {"n_cves": 0}

    confirmed = [r for r in reports if (r.get("exploit_artifacts") or {}).get("dynamically_confirmed")]
    executed  = [r for r in reports if (r.get("exploit_artifacts") or {}).get("executed")]
    patch_attempted = [r for r in reports if (r.get("exploit_artifacts") or {}).get("patch_attempted")]
    patch_validated = [r for r in patch_attempted if (r.get("exploit_artifacts") or {}).get("patch_validated")]
    refined = [r for r in reports if (r.get("exploit_artifacts") or {}).get("refinement_history")]

    by_class: dict[str, dict] = {}
    for r in reports:
        cls = (r.get("analysis") or {}).get("vulnerability_class", "UNKNOWN")
        slot = by_class.setdefault(cls, {"attempted": 0, "confirmed": 0})
        slot["attempted"] += 1
        if (r.get("exploit_artifacts") or {}).get("dynamically_confirmed"):
            slot["confirmed"] += 1

    elapsed = [r.get("elapsed_s", 0.0) for r in reports if r.get("elapsed_s")]
    llm_calls = [_llm_call_estimate(r) for r in reports]

    # Real (not estimated) totals from the live-LLM Gate-1/2 instrumentation
    # (total_llm_* on PipelineReport). None-safe and reported separately from
    # the llm_calls_*_estimate above rather than merged with it: older
    # reports predate this field and simply don't contribute, which is
    # honest under-reporting, not backfilled or guessed.
    llm_duration = [r["total_llm_duration_s"] for r in reports if r.get("total_llm_duration_s") is not None]
    llm_in_tok   = [r["total_llm_input_tokens"] for r in reports if r.get("total_llm_input_tokens") is not None]
    llm_out_tok  = [r["total_llm_output_tokens"] for r in reports if r.get("total_llm_output_tokens") is not None]
    llm_cost     = [r["total_llm_cost_usd"] for r in reports if r.get("total_llm_cost_usd") is not None]
    n_with_real_llm_metrics = len(llm_duration)

    return {
        "n_cves": n,
        "n_confirmed": len(confirmed),
        "pov_confirmation_rate": round(len(confirmed) / n, 3),
        "n_executed": len(executed),
        "n_self_improved": len(refined),
        "n_patch_attempted": len(patch_attempted),
        "n_patch_validated": len(patch_validated),
        "patch_validation_rate": (
            round(len(patch_validated) / len(patch_attempted), 3) if patch_attempted else None
        ),
        "by_vuln_class": by_class,
        "elapsed_s_mean": round(statistics.mean(elapsed), 2) if elapsed else None,
        "elapsed_s_median": round(statistics.median(elapsed), 2) if elapsed else None,
        "llm_calls_total_estimate": sum(llm_calls),
        "llm_calls_mean_estimate": round(statistics.mean(llm_calls), 2) if llm_calls else 0,
        "n_with_real_llm_metrics": n_with_real_llm_metrics,
        "llm_duration_s_total": round(sum(llm_duration), 2) if llm_duration else None,
        "llm_input_tokens_total": sum(llm_in_tok) if llm_in_tok else None,
        "llm_output_tokens_total": sum(llm_out_tok) if llm_out_tok else None,
        "llm_cost_usd_total": round(sum(llm_cost), 4) if llm_cost else None,
    }


def render_markdown(m: dict) -> str:
    if m.get("n_cves", 0) == 0:
        return "# Metrics\n\nNo reports found under reports/CVE-*/report.json.\n"

    lines = [
        "# Pipeline metrics",
        "",
        "Computed by `python -m src.metrics` directly from `reports/*/report.json` "
        "already on disk — no re-run, no estimation beyond what's noted.",
        "",
        f"- CVEs in catalog: **{m['n_cves']}**",
        f"- Dynamically confirmed (PoV rate): **{m['n_confirmed']}/{m['n_cves']} "
        f"({m['pov_confirmation_rate']:.0%})**",
        f"- Self-improvement (Stage 3.7) invoked: **{m['n_self_improved']}**",
        f"- Patch attempted (Stage 3.8): **{m['n_patch_attempted']}**",
        f"- Patch validated: **{m['n_patch_validated']}"
        + (f"/{m['n_patch_attempted']} ({m['patch_validation_rate']:.0%})**"
           if m['patch_validation_rate'] is not None else " (none attempted)**"),
        (f"- Wall-clock per CVE: mean **{m['elapsed_s_mean']}s**, "
         f"median **{m['elapsed_s_median']}s**"
         if m['elapsed_s_mean'] is not None else
         "- Wall-clock per CVE: not available (older reports predate `elapsed_s`)"),
        f"- LLM calls per CVE (estimate, undercounts Stage 2/3.5): "
        f"mean **{m['llm_calls_mean_estimate']}**, total **{m['llm_calls_total_estimate']}**",
        (f"- Real live-model cost, {m['n_with_real_llm_metrics']}/{m['n_cves']} CVEs with "
         f"the new instrumentation: **{m['llm_duration_s_total']}s** total run time, "
         f"**{m['llm_input_tokens_total']}** input / **{m['llm_output_tokens_total']}** "
         f"output tokens, **${m['llm_cost_usd_total']}** total cost"
         if m['n_with_real_llm_metrics'] else
         "- Real live-model cost: not available (no report yet carries total_llm_* — "
         "run with the live-LLM Gate 1/2 instrumentation to populate this)"),
        "",
        "## By vulnerability class",
        "",
        "| Class | Confirmed | Attempted | Rate |",
        "|---|---|---|---|",
    ]
    for cls, slot in sorted(m["by_vuln_class"].items()):
        rate = slot["confirmed"] / slot["attempted"] if slot["attempted"] else 0
        lines.append(f"| {cls} | {slot['confirmed']} | {slot['attempted']} | {rate:.0%} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    m = compute_metrics()
    md = render_markdown(m)
    out = REPORTS_DIR / "METRICS.md"
    out.write_text(md, encoding="utf-8")
    print(md)
    print(f"Written to {out}")


if __name__ == "__main__":
    main()
