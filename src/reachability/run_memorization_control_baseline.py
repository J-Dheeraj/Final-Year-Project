#!/usr/bin/env python3
"""Same-session, same-model-set baseline for run_memorization_control.py.

run_free5gc_llm_patch.py already proved one model (qwen2.5-coder:7b) can
produce a compiling LLM patch for the REAL CVE-2026-40248 handler
(HandleApplicationDataInfluenceDataSubsToNotifyGet). But that model - and
every other model in the 8-model sweeps - is no longer pulled on this
machine (see run_memorization_control.py's MODELS note), so comparing
the memorization control's result against those old numbers would be
comparing different model populations, not a controlled comparison.

This script re-runs the exact same compile-verification methodology as
run_free5gc_llm_patch.py, against the exact same real CVE target, but
looped over whichever models are ACTUALLY available right now (the same
set run_memorization_control.py uses) - so both arms of the memorization
control are run against identical models in the same session.

Run: python -m src.reachability.run_memorization_control_baseline
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.reachability.patch import generate_patch
from src.reachability.pipeline import PipelineConfig, run_pipeline
from src.reachability.providers import OllamaProvider
from src.reachability.run_memorization_control import MODELS, _go_build

REPO_URL = "https://github.com/free5gc/udr.git"
FIX_COMMIT = "86686276a7e226183ee786e3dd6714ec56c78fda"
VULN_COMMIT = f"{FIX_COMMIT}^"
REL_FILE = Path("internal/sbi/api_datarepository.go")

CASE_DIR = Path(__file__).parent / "examples" / "free5gc_case_study"
ENTRYPOINTS = [
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdPut",
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet",
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete",
    "HandleApplicationDataInfluenceDataSubsToNotifyGet",
]
LLM_TARGET = "HandleApplicationDataInfluenceDataSubsToNotifyGet"

OUT_DIR = Path(__file__).resolve().parents[2] / "reports" / "reachability"


def main() -> int:
    if shutil.which("git") is None or shutil.which("go") is None:
        print("Needs both `git` and `go` on PATH; aborting.")
        return 1

    cfg = PipelineConfig(
        target=CASE_DIR / "api_datarepository_vulnerable.go",
        entrypoints=ENTRYPOINTS, provider="mock", cache_dir=None, skip_testing=True,
    )
    _, outcomes = run_pipeline(cfg)
    patches_by_name = {o.patch.finding.triage.function.name: o.patch for o in outcomes}
    if LLM_TARGET not in patches_by_name:
        print(f"{LLM_TARGET} was not flagged/verified by the mock run - aborting.")
        return 1
    finding = patches_by_name[LLM_TARGET].finding
    rule_based_patches = {k: v for k, v in patches_by_name.items() if k != LLM_TARGET}

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []

    def persist() -> None:
        report = {
            "experiment": "memorization_control_baseline",
            "note": "same compile-verification methodology and model set as "
                     "run_memorization_control.py, applied to the REAL "
                     "CVE-2026-40248 handler instead of the synthetic one - "
                     "the matched comparison arm.",
            "target_function": LLM_TARGET,
            "vulnerable_commit": VULN_COMMIT,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "models": results,
        }
        (OUT_DIR / "free5gc_memorization_control_baseline.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")
        lines = ["# free5GC memorization control: REAL CVE baseline (matched models)", "",
                 f"Target: `{LLM_TARGET}` (the real, disclosed CVE-2026-40248 handler).", "",
                 "| Model | Compiles (fixes the real CVE) |", "|---|---|"]
        for e in results:
            compiles = "yes" if e["compiles"] else f"NO ({e['error']})"
            lines.append(f"| `{e['model']}` | {compiles} |")
        (OUT_DIR / "free5gc_memorization_control_baseline.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8")

    for model in MODELS:
        print(f"\n{'='*70}\n{model}\n{'='*70}")
        entry = {"model": model, "compiles": False, "error": None, "diff": None}
        try:
            provider = OllamaProvider(model)
            llm_patch = generate_patch(finding, provider, exploit_outcome=None)
            entry["diff"] = llm_patch.diff

            with tempfile.TemporaryDirectory(prefix="free5gc_udr_memcontrol_baseline_") as tmp:
                module_dir = Path(tmp) / "udr"
                subprocess.run(["git", "clone", "--quiet", REPO_URL, str(module_dir)], check=True)
                subprocess.run(["git", "checkout", "--quiet", VULN_COMMIT],
                                cwd=str(module_dir), check=True)
                real_file = module_dir / REL_FILE
                real_text = real_file.read_text(encoding="utf-8")

                applied, skipped = [], []
                for name in ENTRYPOINTS:
                    p = llm_patch if name == LLM_TARGET else rule_based_patches.get(name)
                    if p is None or p.original not in real_text:
                        skipped.append(name)
                        continue
                    real_text = real_text.replace(p.original, p.patched, 1)
                    applied.append(name)
                real_file.write_text(real_text, encoding="utf-8")

                if skipped:
                    entry["error"] = f"skipped (no match): {skipped}"
                ok, log = _go_build(module_dir, f"{model} patch applied")
                entry["compiles"] = ok
                if not ok:
                    entry["error"] = log[-500:]
        except Exception as e:
            print(f"[{model}] UNEXPECTED ERROR: {type(e).__name__}: {e}")
            entry["error"] = f"{type(e).__name__}: {e}"

        results.append(entry)
        persist()

    persist()
    n_ok = sum(1 for e in results if e["compiles"])
    print(f"\n\n=== BASELINE SUMMARY ===")
    print(f"{n_ok}/{len(results)} models produced a compiling fix for the REAL CVE handler.")
    print(f"Full report: {OUT_DIR / 'free5gc_memorization_control_baseline.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
