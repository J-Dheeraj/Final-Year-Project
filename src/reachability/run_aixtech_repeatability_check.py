#!/usr/bin/env python3
"""Repeatability check for the AIxTech gateway track (--backend aixtech).

The original aixtech runs (free5gc_memorization_control_baseline_aixtech.json
etc.) are each a SINGLE attempt per model - they show what happened once,
not whether that result is stable. This reuses the exact same real-CVE
patch-gen-and-compile methodology as run_memorization_control_baseline.py
(same repo, same commit, same target handler, same provider/patch/build
helpers - imported, not duplicated), but runs each of the 4 models that
actually resolve on this gateway key N times each, and writes every run
to its own entry in a dedicated report rather than overwriting the
single-run report.

Run: python -m src.reachability.run_aixtech_repeatability_check
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
from src.reachability.claude_backend import AIXTECH_MODELS, provider_for  # noqa: E402 - import first
from src.reachability.patch import generate_patch  # noqa: E402
from src.reachability.pipeline import PipelineConfig, run_pipeline  # noqa: E402
from src.reachability.run_memorization_control import MODELS, _go_build  # noqa: E402
from src.reachability.run_memorization_control_baseline import (  # noqa: E402
    CASE_DIR, ENTRYPOINTS, LLM_TARGET, REL_FILE, REPO_URL, VULN_COMMIT,
)

# Only the 4 models verified reachable on this gateway key (see
# docs/METHODOLOGY_PITFALLS.md #15 / AIXTECH_MODELS's own comment) -
# repeating the 6 that 403 on every attempt would just confirm the same
# denial 3x, adding nothing.
REPEAT_MODELS = [m for m in AIXTECH_MODELS if m in (
    "claude-haiku-4-5-20251001", "claude-haiku-5-5",
    "claude-sonnet-4-6", "claude-sonnet-5",
)]
RUNS_PER_MODEL = 3

OUT_DIR = Path(__file__).resolve().parents[2] / "reports" / "reachability"
OUT_STEM = "free5gc_aixtech_repeatability"


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
    results: list[dict] = []

    def persist() -> None:
        report = {
            "experiment": "aixtech_repeatability_check",
            "backend": "aixtech",
            "note": "Each of the 4 gateway-reachable models run "
                     f"{RUNS_PER_MODEL}x against the same real CVE-2026-40248 "
                     "handler, same methodology as "
                     "run_memorization_control_baseline.py - checks whether a "
                     "single-run result is stable, not a one-shot fluke.",
            "target_function": LLM_TARGET,
            "vulnerable_commit": VULN_COMMIT,
            "runs_per_model": RUNS_PER_MODEL,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results": results,
        }
        (OUT_DIR / f"{OUT_STEM}.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")

    for model in REPEAT_MODELS:
        print(f"\n{'='*70}\n{model}\n{'='*70}")
        for run_idx in range(1, RUNS_PER_MODEL + 1):
            entry = {
                "model": model, "run": run_idx, "compiles": False, "error": None,
                "diff": None, "usage": None, "duration_s": None,
            }
            try:
                provider = provider_for("aixtech", model)
                llm_patch = generate_patch(finding, provider, exploit_outcome=None)
                entry["usage"] = getattr(provider, "last_usage", None)
                entry["duration_s"] = getattr(provider, "last_duration_s", None)
                entry["diff"] = llm_patch.diff

                with tempfile.TemporaryDirectory(prefix="free5gc_udr_aixtech_repeat_") as tmp:
                    module_dir = Path(tmp) / "udr"
                    subprocess.run(["git", "clone", "--quiet", REPO_URL, str(module_dir)], check=True)
                    subprocess.run(["git", "checkout", "--quiet", VULN_COMMIT],
                                    cwd=str(module_dir), check=True)
                    real_file = module_dir / REL_FILE
                    real_text = real_file.read_text(encoding="utf-8")

                    skipped = []
                    for name in ENTRYPOINTS:
                        p = llm_patch if name == LLM_TARGET else rule_based_patches.get(name)
                        if p is None or p.original not in real_text:
                            skipped.append(name)
                            continue
                        real_text = real_text.replace(p.original, p.patched, 1)
                    real_file.write_text(real_text, encoding="utf-8")

                    if skipped:
                        entry["error"] = f"skipped (no match): {skipped}"
                    ok, log = _go_build(module_dir, f"{model} run {run_idx}")
                    entry["compiles"] = ok
                    if not ok:
                        entry["error"] = log[-500:]
            except Exception as e:
                print(f"[{model} run {run_idx}] UNEXPECTED ERROR: {type(e).__name__}: {e}")
                entry["error"] = f"{type(e).__name__}: {e}"
                prov = locals().get("provider")
                if prov is not None:
                    entry["usage"] = getattr(prov, "last_usage", None)
                    entry["duration_s"] = getattr(prov, "last_duration_s", None)

            results.append(entry)
            persist()

    persist()
    print("\n\n=== REPEATABILITY SUMMARY ===")
    for model in REPEAT_MODELS:
        model_runs = [e for e in results if e["model"] == model]
        n_ok = sum(1 for e in model_runs if e["compiles"])
        print(f"{model}: {n_ok}/{len(model_runs)} runs compiled")
    print(f"Full report: {OUT_DIR / f'{OUT_STEM}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
