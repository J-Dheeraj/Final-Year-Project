#!/usr/bin/env python3
"""Level 2 of docs/FREE5GC_LLM_PATCH_SCOPE.md: generate a real LLM patch
(via local Ollama, free/no-API-key) for the ONE free5GC handler where the
rule-based patcher is known to produce only a partial fix
(`HandleApplicationDataInfluenceDataSubsToNotifyGet` - see
docs/REACHABILITY.md), then compile-verify it against a live clone of the
real upstream module, exactly like verify_against_real_upstream.py does
for the rule-based patches.

Deliberately does NOT touch Docker / the full-deployment runtime harness -
that half of Level 2 (swapping this patch into
free5gc_full_deployment/udr_build/Dockerfile and re-running
run_full_deployment_harness.py) is a separate step, blocked on Docker
Desktop being reachable on this machine (see docs/PROJECT_STATUS.md).

Run: python -m src.reachability.run_free5gc_llm_patch
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.reachability.patch import generate_patch
from src.reachability.pipeline import PipelineConfig, run_pipeline
from src.reachability.providers import OllamaProvider

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
OLLAMA_MODEL = "qwen2.5-coder:7b"

OUT_DIR = Path(__file__).resolve().parents[2] / "reports" / "reachability"


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
        print("Needs both `git` and `go` on PATH; aborting.")
        return 1

    print(f"Requesting a real LLM patch for {LLM_TARGET} via local Ollama "
          f"({OLLAMA_MODEL}) ...")
    try:
        provider = OllamaProvider(OLLAMA_MODEL)
    except RuntimeError as e:
        print(f"Ollama not reachable: {e}")
        return 1

    # Deterministic mock run first - this reuses the exact, already-verified
    # reachability/triage/verify output for all 4 handlers (same as
    # verify_against_real_upstream.py), so only the PATCH stage differs.
    cfg = PipelineConfig(
        target=CASE_DIR / "api_datarepository_vulnerable.go",
        entrypoints=ENTRYPOINTS, provider="mock", cache_dir=None, skip_testing=True,
    )
    _, outcomes = run_pipeline(cfg)
    patches_by_name = {o.patch.finding.triage.function.name: o.patch for o in outcomes}

    if LLM_TARGET not in patches_by_name:
        print(f"{LLM_TARGET} was not flagged/verified by the mock run - aborting.")
        return 1

    llm_target_finding = patches_by_name[LLM_TARGET].finding
    llm_patch = generate_patch(llm_target_finding, provider, exploit_outcome=None)
    print(f"\nLLM patch method recorded as: {llm_patch.method}")
    print("\n--- LLM-generated diff for", LLM_TARGET, "---")
    print(llm_patch.diff)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    diff_path = OUT_DIR / "free5gc_llm_patch_get_handler.diff"
    diff_path.write_text(llm_patch.diff + "\n", encoding="utf-8")
    print(f"\nDiff written to {diff_path}")

    with tempfile.TemporaryDirectory(prefix="free5gc_udr_llm_verify_") as tmp:
        module_dir = Path(tmp) / "udr"
        print(f"\nCloning {REPO_URL} @ {VULN_COMMIT} (real pre-fix commit) ...")
        subprocess.run(["git", "clone", "--quiet", REPO_URL, str(module_dir)], check=True)
        subprocess.run(["git", "checkout", "--quiet", VULN_COMMIT],
                        cwd=str(module_dir), check=True)

        print("\n=== Baseline: real vulnerable commit, unmodified ===")
        if not _go_build(module_dir, "baseline (unpatched)"):
            print("Baseline doesn't build - can't trust a patched result. Aborting.")
            return 1

        real_file = module_dir / REL_FILE
        real_text = real_file.read_text(encoding="utf-8")
        applied, skipped = [], []
        for name in ENTRYPOINTS:
            # The other 3 handlers keep the already-verified, already
            # runtime-confirmed rule-based patch; only LLM_TARGET gets the
            # LLM-generated one. This isolates what changed in this test to
            # exactly the one handler the LLM was asked to fix.
            p = llm_patch if name == LLM_TARGET else patches_by_name.get(name)
            if p is None:
                skipped.append((name, "no patch generated"))
                continue
            if p.original not in real_text:
                skipped.append((name, "function body doesn't byte-match the vendored snapshot"))
                continue
            real_text = real_text.replace(p.original, p.patched, 1)
            applied.append((name, p.method))
        real_file.write_text(real_text, encoding="utf-8")

        print(f"\nApplied {len(applied)}/{len(ENTRYPOINTS)} patches: {applied}")
        if skipped:
            print(f"Skipped: {skipped}")

        print("\n=== After applying patches (LLM for the GET handler, "
              "rule-based for the other 3) to the REAL module ===")
        ok = _go_build(module_dir, "patched (real module, LLM-for-GET)")
        verdict = "COMPILES" if ok else "FAILS TO COMPILE"
        print(f"\nRESULT: real free5GC/udr @ {VULN_COMMIT[:12]} with an "
              f"Ollama({OLLAMA_MODEL})-generated patch for {LLM_TARGET} "
              f"(plus the existing rule-based patches for the other 3 "
              f"handlers) applied {verdict}")
        print("\nNote: this is compile verification only, same tier as "
              "verify_against_real_upstream.py. Runtime confirmation "
              "(swapping this patch into the Docker full-deployment "
              "harness) is a separate, not-yet-done step - see "
              "docs/FREE5GC_LLM_PATCH_SCOPE.md.")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
