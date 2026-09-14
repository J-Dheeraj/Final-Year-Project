#!/usr/bin/env python3
"""Optional, network-requiring verification: clone the REAL free5GC/udr
repo at the real pre-fix commit, apply this pipeline's auto-generated
patches directly to the actual module (not a scratch single-file copy),
and confirm `go build ./...` still succeeds against the module's real,
full dependency graph.

This is NOT part of the offline case study (run_free5gc_case_study.py) -
that one works with no network access, using the vendored snapshot in
examples/free5gc_case_study/. This script is the deeper, optional check:
proof the generated patch is compile-compatible with the actual upstream
project, not just with an isolated copy of one file. Needs `git` and `go`
on PATH, and network access to github.com + the Go module proxy.

Run: python -m src.reachability.verify_against_real_upstream
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.reachability.pipeline import PipelineConfig, run_pipeline

REPO_URL = "https://github.com/free5gc/udr.git"
# The real, disclosed fix commit for CVE-2026-40248 (CWE-285: validation
# response written but handler falls through and processes the request
# anyway) - same commit examples/free5gc_case_study/*.go were fetched
# from, verified against the GitHub API.
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


def _go_build(module_dir: Path, label: str) -> bool:
    proc = subprocess.run(["go", "build", "./..."], cwd=str(module_dir),
                           capture_output=True, text=True, timeout=240)
    ok = proc.returncode == 0
    print(f"  [{label}] go build ./... -> {'OK' if ok else 'FAILED'}")
    if not ok:
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:])
    return ok


def main() -> int:
    if shutil.which("git") is None or shutil.which("go") is None:
        print("Needs both `git` and `go` on PATH; skipping.")
        return 1

    with tempfile.TemporaryDirectory(prefix="free5gc_udr_verify_") as tmp:
        module_dir = Path(tmp) / "udr"
        print(f"Cloning {REPO_URL} @ {VULN_COMMIT} (real pre-fix commit) ...")
        subprocess.run(["git", "clone", "--quiet", REPO_URL, str(module_dir)], check=True)
        subprocess.run(["git", "checkout", "--quiet", VULN_COMMIT],
                        cwd=str(module_dir), check=True)

        print("\n=== Baseline: real vulnerable commit, unmodified ===")
        if not _go_build(module_dir, "baseline (unpatched)"):
            print("Baseline doesn't build - can't trust a patched result. Aborting.")
            return 1

        cfg = PipelineConfig(
            target=CASE_DIR / "api_datarepository_vulnerable.go",
            entrypoints=ENTRYPOINTS, provider="mock", cache_dir=None, skip_testing=True,
        )
        _, outcomes = run_pipeline(cfg)
        patches_by_name = {o.patch.finding.triage.function.name: o.patch for o in outcomes}

        real_file = module_dir / REL_FILE
        real_text = real_file.read_text(encoding="utf-8")
        applied, skipped = [], []
        for name in ENTRYPOINTS:
            p = patches_by_name.get(name)
            if p is None:
                skipped.append((name, "no patch generated"))
                continue
            if p.original not in real_text:
                skipped.append((name, "function body doesn't byte-match the vendored snapshot"))
                continue
            real_text = real_text.replace(p.original, p.patched, 1)
            applied.append(name)
        real_file.write_text(real_text, encoding="utf-8")

        print(f"\nApplied {len(applied)}/{len(ENTRYPOINTS)} patches: {applied}")
        if skipped:
            print(f"Skipped: {skipped}")

        print("\n=== After applying auto-generated patches to the REAL module ===")
        ok = _go_build(module_dir, "patched (real module)")
        verdict = "COMPILES" if ok else "FAILS TO COMPILE"
        print(f"\nRESULT: real free5GC/udr @ {VULN_COMMIT[:12]} with the pipeline's "
              f"auto-generated patches applied {verdict}")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
