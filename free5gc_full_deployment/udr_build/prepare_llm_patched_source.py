#!/usr/bin/env python3
"""Materializes the LLM-patched `internal/sbi/api_datarepository.go` to
disk (udr_build/api_datarepository_llm_patched.go) so Dockerfile.llm can
COPY it into the build, instead of regenerating it inside the Docker
build context (which has no Ollama access and shouldn't call an LLM
during `docker build` anyway).

Reuses the exact same patch-generation path as
src/reachability/run_free5gc_llm_patch.py: rule-based patches for the 3
already-correct handlers, a fresh Ollama(qwen2.5-coder:7b) patch for
HandleApplicationDataInfluenceDataSubsToNotifyGet, spliced into a live
clone of the real upstream module at the real vulnerable commit.

Run: python free5gc_full_deployment/udr_build/prepare_llm_patched_source.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.reachability.patch import generate_patch
from src.reachability.pipeline import PipelineConfig, run_pipeline
from src.reachability.providers import OllamaProvider

REPO_URL = "https://github.com/free5gc/udr.git"
FIX_COMMIT = "86686276a7e226183ee786e3dd6714ec56c78fda"
VULN_COMMIT = f"{FIX_COMMIT}^"
REL_FILE = Path("internal/sbi/api_datarepository.go")

CASE_DIR = ROOT / "src" / "reachability" / "examples" / "free5gc_case_study"
ENTRYPOINTS = [
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdPut",
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet",
    "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete",
    "HandleApplicationDataInfluenceDataSubsToNotifyGet",
]
LLM_TARGET = "HandleApplicationDataInfluenceDataSubsToNotifyGet"
OLLAMA_MODEL = "qwen2.5-coder:7b"

OUT_FILE = Path(__file__).parent / "api_datarepository_llm_patched.go"


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

    try:
        provider = OllamaProvider(OLLAMA_MODEL)
    except RuntimeError as e:
        print(f"Ollama not reachable: {e}")
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

    llm_patch = generate_patch(patches_by_name[LLM_TARGET].finding, provider, exploit_outcome=None)
    print(f"LLM patch method: {llm_patch.method}")

    with tempfile.TemporaryDirectory(prefix="free5gc_udr_llm_prepare_") as tmp:
        module_dir = Path(tmp) / "udr"
        print(f"Cloning {REPO_URL} @ {VULN_COMMIT} ...")
        subprocess.run(["git", "clone", "--quiet", REPO_URL, str(module_dir)], check=True)
        subprocess.run(["git", "checkout", "--quiet", VULN_COMMIT],
                        cwd=str(module_dir), check=True)

        if not _go_build(module_dir, "baseline (unpatched)"):
            print("Baseline doesn't build - aborting.")
            return 1

        real_file = module_dir / REL_FILE
        real_text = real_file.read_text(encoding="utf-8")
        applied, skipped = [], []
        for name in ENTRYPOINTS:
            p = llm_patch if name == LLM_TARGET else patches_by_name.get(name)
            if p is None:
                skipped.append((name, "no patch generated"))
                continue
            if p.original not in real_text:
                skipped.append((name, "function body doesn't byte-match"))
                continue
            real_text = real_text.replace(p.original, p.patched, 1)
            applied.append((name, p.method))
        real_file.write_text(real_text, encoding="utf-8")

        print(f"Applied {len(applied)}/{len(ENTRYPOINTS)}: {applied}")
        if skipped:
            print(f"Skipped: {skipped}")
            return 1

        if not _go_build(module_dir, "patched (LLM for GET handler)"):
            print("Patched source doesn't build - refusing to materialize it.")
            return 1

        OUT_FILE.write_text(real_text, encoding="utf-8")
        print(f"\nMaterialized compile-verified, LLM-patched source to {OUT_FILE}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
