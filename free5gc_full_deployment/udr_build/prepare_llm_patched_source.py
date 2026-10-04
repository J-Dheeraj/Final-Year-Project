#!/usr/bin/env python3
"""Materializes the LLM-patched `internal/sbi/api_datarepository.go` to
disk (udr_build/api_datarepository_llm_patched*.go) so Dockerfile.llm can
COPY it into the build, instead of regenerating it inside the Docker
build context (which has no Ollama access and shouldn't call an LLM
during `docker build` anyway).

Reuses the exact same patch-generation path as
src/reachability/run_free5gc_llm_patch.py: rule-based patches for the 3
already-correct handlers, a fresh Ollama patch for
HandleApplicationDataInfluenceDataSubsToNotifyGet, spliced into a live
clone of the real upstream module at the real vulnerable commit.

Run (default model, default output file - backward compatible):
    python free5gc_full_deployment/udr_build/prepare_llm_patched_source.py
Run with a specific model (used by run_model_sweep.py):
    python free5gc_full_deployment/udr_build/prepare_llm_patched_source.py --model codellama:13b
"""
from __future__ import annotations

import argparse
import re
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
DEFAULT_MODEL = "qwen2.5-coder:7b"

UDR_BUILD_DIR = Path(__file__).parent


def output_file_for(model: str) -> Path:
    if model == DEFAULT_MODEL:
        # Keep the original, pre-sweep filename stable for the model the
        # single-model run/doc already reference.
        return UDR_BUILD_DIR / "api_datarepository_llm_patched.go"
    safe = re.sub(r"[^a-zA-Z0-9]+", "-", model).strip("-")
    return UDR_BUILD_DIR / f"api_datarepository_llm_patched_{safe}.go"


def _go_build(module_dir: Path, label: str) -> bool:
    proc = subprocess.run(["go", "build", "./..."], cwd=str(module_dir),
                           capture_output=True, text=True, timeout=240)
    ok = proc.returncode == 0
    print(f"  [{label}] go build ./... -> {'OK' if ok else 'FAILED'}")
    if not ok:
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:])
    return ok


def materialize_and_verify(model: str) -> dict:
    """Generates a patch for LLM_TARGET from `model`, splices it (plus the
    existing rule-based patches for the other 3 handlers) into a live
    clone of the real upstream module, compile-verifies it, and - only if
    it compiles - writes it to disk. Returns a result dict regardless of
    outcome (never raises for a model-specific failure)."""
    result = {"model": model, "patch_method": None, "applied": 0,
              "diff": None, "compiles": False, "output_file": None,
              "error": None}

    if shutil.which("git") is None or shutil.which("go") is None:
        result["error"] = "git/go not on PATH"
        return result

    try:
        provider = OllamaProvider(model)
    except RuntimeError as e:
        result["error"] = f"Ollama not reachable: {e}"
        return result

    cfg = PipelineConfig(
        target=CASE_DIR / "api_datarepository_vulnerable.go",
        entrypoints=ENTRYPOINTS, provider="mock", cache_dir=None, skip_testing=True,
    )
    _, outcomes = run_pipeline(cfg)
    patches_by_name = {o.patch.finding.triage.function.name: o.patch for o in outcomes}
    if LLM_TARGET not in patches_by_name:
        result["error"] = f"{LLM_TARGET} was not flagged/verified by the mock run"
        return result

    try:
        llm_patch = generate_patch(patches_by_name[LLM_TARGET].finding, provider, exploit_outcome=None)
    except Exception as e:
        # Broad on purpose: sweeping multiple models hits real network
        # timeouts (urllib.TimeoutError, not RuntimeError) on slower
        # models under CPU inference - one model's failure must not stop
        # the sweep from recording it and moving on to the next model.
        result["error"] = f"generate_patch failed: {type(e).__name__}: {e}"
        return result
    result["patch_method"] = llm_patch.method
    result["diff"] = llm_patch.diff

    with tempfile.TemporaryDirectory(prefix="free5gc_udr_llm_prepare_") as tmp:
        module_dir = Path(tmp) / "udr"
        print(f"[{model}] Cloning {REPO_URL} @ {VULN_COMMIT} ...")
        subprocess.run(["git", "clone", "--quiet", REPO_URL, str(module_dir)], check=True)
        subprocess.run(["git", "checkout", "--quiet", VULN_COMMIT],
                        cwd=str(module_dir), check=True)

        if not _go_build(module_dir, f"{model} baseline (unpatched)"):
            result["error"] = "baseline doesn't build"
            return result

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
        result["applied"] = len(applied)

        print(f"[{model}] Applied {len(applied)}/{len(ENTRYPOINTS)}: {applied}")
        if skipped:
            print(f"[{model}] Skipped: {skipped}")
            result["error"] = f"skipped: {skipped}"
            return result

        if not _go_build(module_dir, f"{model} patched"):
            result["error"] = "patched source doesn't build"
            return result

        result["compiles"] = True
        out_file = output_file_for(model)
        out_file.write_text(real_text, encoding="utf-8")
        result["output_file"] = str(out_file)
        print(f"[{model}] Materialized compile-verified source to {out_file}")
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=DEFAULT_MODEL)
    args = parser.parse_args()
    r = materialize_and_verify(args.model)
    if r["error"] or not r["compiles"]:
        print(f"FAILED for {args.model}: {r['error']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
