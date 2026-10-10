"""Build a derived, provenance-aware free5GC evidence ledger.

Raw sweep JSON files remain immutable historical evidence. This report makes
the model-generated versus deterministic parts of each result explicit and is
the source used for public headline tables.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports" / "reachability"


def classify(entry: dict, backend: str) -> dict:
    comp = entry.get("compile") or {}
    runtime = entry.get("runtime") or {}
    verdict = runtime.get("overall_verdict")
    compile_passed = bool(comp.get("compiles"))
    confirmed = verdict == "confirmed_fix_all_four_handlers"
    return {
        "model": entry.get("model"),
        "run": entry.get("run", 1),
        "backend": backend,
        "handlers_total": 4,
        "handlers_model_generated": 1,
        "handlers_deterministically_materialized": 3,
        "compile_passed": compile_passed,
        "runtime_confirmed_all_four_handlers": confirmed,
        "benign_path_passed": bool(runtime.get("benign_path_preserved_patched")) if runtime else False,
        "pipeline_validation_verdict": verdict or ("compile_failed" if not compile_passed else "runtime_not_reached"),
        "historical_confirmed_fix_all_four_handlers": confirmed,
        "artifact_dir": entry.get("artifact_dir"),
        "failure_class": (
            "environment" if entry.get("build_ok") is False else
            "generation_or_compile" if not compile_passed else
            None
        ),
    }


def main() -> None:
    rows = []
    sources = []
    for path in sorted(REPORTS.glob("free5gc_sweep_patch_*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("backend") not in {"openai", "ollama", "claude", "aixtech", "codex"}:
            continue
        sources.append(str(path.relative_to(ROOT)))
        for entry in data.get("models", []):
            row = classify(entry, data.get("backend"))
            row["source_report"] = str(path.relative_to(ROOT))
            rows.append(row)
    report = {
        "schema": "free5gc-derived-evidence-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "interpretation": (
            "confirmed_fix_all_four_handlers is retained as a historical full-pipeline "
            "verdict; it does not mean the model generated four independent handler patches."
        ),
        "rows": rows,
        "source_reports": sources,
    }
    out = REPORTS / "free5gc_derived_evidence_ledger.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
