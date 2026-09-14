#!/usr/bin/env python3
"""Offline free5GC case study: reachability -> triage -> verify -> patch
against the vendored real free5GC/udr source (examples/free5gc_case_study/,
fetched verbatim from github.com/free5gc/udr at the commit before and the
commit of the real fix for CVE-2026-40248, both verified against the
GitHub API). No network access needed - the source is already local.

For the deeper, network-requiring check (patches applied to a live clone
of the real module, confirmed to compile against its actual dependency
graph), see verify_against_real_upstream.py instead.

Run: python -m src.reachability.run_free5gc_case_study
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.reachability.pipeline import PipelineConfig, run_pipeline
from src.reachability.report import write_report

CASE_DIR = Path(__file__).parent / "examples" / "free5gc_case_study"
VULNERABLE = CASE_DIR / "api_datarepository_vulnerable.go"
ENTRYPOINTS = [
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdPut",
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet",
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete",
    "HandleApplicationDataInfluenceDataSubsToNotifyGet",
]
OUT = Path(__file__).resolve().parents[2] / "reports" / "reachability" / "free5gc_case_study.json"


def main() -> None:
    cfg = PipelineConfig(target=VULNERABLE, entrypoints=ENTRYPOINTS,
                          provider="mock", cache_dir=None, skip_testing=True)
    stats, outcomes = run_pipeline(cfg)

    print(f"Parsed {stats.reachability.total_functions} functions from "
          f"{VULNERABLE.name} (a real ~86KB free5GC UDR source file)")
    print(f"Reachable from {len(ENTRYPOINTS)} real HTTP entry points: "
          f"{len(stats.reachability.reachable)} functions "
          f"({stats.reachability.reduction_pct:.1f}% reduction)")
    print(f"Flagged by triage: {stats.flagged_count} | "
          f"survived verification: {stats.verified_count}")
    for o in outcomes:
        f = o.patch.finding.triage.function
        print(f"  - {f.name} ({o.patch.finding.triage.cwe}) "
              f"confidence={o.patch.finding.confidence:.2f} "
              f"patch_method={o.patch.method}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    write_report(stats, outcomes, OUT)
    print(f"\nWritten to {OUT} and {OUT.with_suffix('.md')}")
    print("\nFor the deeper check (patches applied to a live clone of the "
          "real module, confirmed to compile against its actual dependency "
          "graph): python -m src.reachability.verify_against_real_upstream")


if __name__ == "__main__":
    main()
