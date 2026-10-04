"""Runs EVERY locally-pulled Ollama model (not just qwen2.5-coder:7b)
against the same free5GC target (HandleApplicationDataInfluenceDataSubs
ToNotifyGet, CWE-285) and collects compile-verification + runtime-
confirmation results for each, into one consolidated comparison report.

Extends docs/FREE5GC_LLM_PATCH_RESULTS.md's single-model result, which
explicitly flagged "single model, single run" as a limitation.

For each model:
  1. Generate a patch (rule-based for the other 3 handlers, this model
     for the target handler), splice into a live clone of the real
     upstream module, compile-verify (prepare_llm_patched_source.py).
  2. If it compiles: build a Docker image from it and runtime-confirm
     against the real MongoDB + free5GC NRF stack, same four-handler
     test sequence as run_full_deployment_harness.py.
  3. Record pass/fail at each stage - a model that fails to compile
     never reaches the runtime stage, and that's recorded, not hidden.

Requires: Docker Desktop running, all models in MODELS already pulled
(`ollama list`), NO_PAID_BACKEND is irrelevant here (Ollama is always
free) but set anyway for consistency with the rest of this project.

Run: python free5gc_full_deployment/run_model_sweep.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

os.environ["NO_PAID_BACKEND"] = "1"

HERE = Path(__file__).parent.resolve()
UDR_BUILD_DIR = HERE / "udr_build"
sys.path.insert(0, str(UDR_BUILD_DIR))

import run_full_deployment_harness as base  # noqa: E402
import prepare_llm_patched_source as prep  # noqa: E402

MODELS = [
    "deepseek-coder-v2:16b",
    "codellama:13b",
    "gemma2:9b",
    "mistral:7b",
    "llama3.1:8b",
    "qwen2.5-coder:7b",
    "qwen2.5-coder:3b",
    "qwen2.5-coder:1.5b",
]


def safe_tag(model: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", model).strip("-").lower()


def docker_build(patched_file: Path, image_tag: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["docker", "build", "-f", "Dockerfile.llm",
         "--build-arg", f"UDR_COMMIT={base.VULN_COMMIT}",
         "--build-arg", f"PATCHED_FILE={patched_file.name}",
         "-t", f"free5gc-udr-custom:{image_tag}", "."],
        cwd=str(UDR_BUILD_DIR), capture_output=True, text=True, timeout=600,
    )
    return proc.returncode == 0, (proc.stdout[-1500:] + proc.stderr[-1500:])


def verdict_from(vuln_result: dict, patched_result: dict) -> dict:
    v = {
        "collection_get_leak_confirmed_vulnerable": vuln_result["collection_get_leaked_data"],
        "collection_get_leak_fixed": not patched_result["collection_get_leaked_data"],
        "single_get_leak_confirmed_vulnerable": vuln_result["single_get_leaked_data"],
        "single_get_leak_fixed": not patched_result["single_get_leaked_data"],
        "single_put_unauthorized_write_confirmed_vulnerable": vuln_result["single_put_unauthorized_write"],
        "single_put_unauthorized_write_fixed": not patched_result["single_put_unauthorized_write"],
        "single_delete_confirmed_exploit_vulnerable": vuln_result["single_delete_confirmed_exploit"],
        "single_delete_fixed": not patched_result["single_delete_confirmed_exploit"],
        "benign_path_preserved_vulnerable": vuln_result["benign_path_preserved"],
        "benign_path_preserved_patched": patched_result["benign_path_preserved"],
    }
    v["overall_verdict"] = (
        "confirmed_fix_all_four_handlers"
        if all(v.values()) else "partial_or_inconclusive"
    )
    return v


def main() -> None:
    (HERE / "evidence").mkdir(exist_ok=True)
    out_dir = HERE.parent / "reports" / "reachability"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Bringing up db + real NRF (idempotent if already up)...")
    base.compose("up", "-d", "db", "free5gc-nrf", env={"UDR_IMAGE_TAG": "vulnerable"})

    print("Establishing the vulnerable baseline once, shared across all models...")
    base.bring_up("vulnerable")
    vuln_result = base.run_case("vulnerable_sweep_baseline")
    base.save_container_log("vulnerable_sweep_baseline")

    def persist(sweep_results: list) -> list:
        report = {
            "cve_id": "CVE-2026-40248",
            "target_handler": "HandleApplicationDataInfluenceDataSubsToNotifyGet",
            "vulnerable_commit": base.VULN_COMMIT,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "vulnerable_baseline_run": vuln_result,
            "models": sweep_results,
        }
        (out_dir / "free5gc_llm_model_sweep.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")

        lines = ["# free5GC LLM model sweep: comparison", "",
                 "| Model | Compiles | Applied/4 | Runtime verdict |",
                 "|---|---|---|---|"]
        for e in sweep_results:
            compiles = "yes" if e["compile"]["compiles"] else f"NO ({e['compile']['error']})"
            applied = e["compile"]["applied"]
            runtime = e["runtime"]["overall_verdict"] if e["runtime"] else (
                "not reached (build failed)" if e.get("build_ok") is False else "not reached (compile failed)")
            lines.append(f"| `{e['model']}` | {compiles} | {applied}/4 | {runtime} |")
        (out_dir / "free5gc_llm_model_sweep.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return lines

    sweep_results = []
    for model in MODELS:
        print(f"\n{'='*70}\n{model}\n{'='*70}")
        entry = {"model": model, "compile": None, "runtime": None}
        try:
            compile_result = prep.materialize_and_verify(model)
            entry["compile"] = {
                "patch_method": compile_result["patch_method"],
                "applied": compile_result["applied"],
                "compiles": compile_result["compiles"],
                "error": compile_result["error"],
                "diff": compile_result["diff"],
            }

            if not compile_result["compiles"]:
                print(f"[{model}] did not compile - skipping runtime stage.")
            else:
                tag = f"llm-{safe_tag(model)}"
                patched_file = Path(compile_result["output_file"])
                build_ok, build_log = docker_build(patched_file, tag)
                entry["build_ok"] = build_ok
                if not build_ok:
                    print(f"[{model}] Docker build FAILED:\n{build_log}")
                else:
                    base.bring_up(tag)
                    patched_result = base.run_case(f"{tag}_sweep")
                    base.save_container_log(f"{tag}_sweep")
                    entry["runtime"] = verdict_from(vuln_result, patched_result)
                    print(f"[{model}] runtime verdict: {entry['runtime']['overall_verdict']}")
        except Exception as e:
            # One model's crash (network timeout, Docker hiccup, etc.)
            # must not lose every other model's already-completed result.
            print(f"[{model}] UNEXPECTED ERROR: {type(e).__name__}: {e}")
            if entry["compile"] is None:
                entry["compile"] = {"patch_method": None, "applied": 0,
                                     "compiles": False, "error": f"{type(e).__name__}: {e}",
                                     "diff": None}
            else:
                entry["compile"]["error"] = f"{entry['compile']['error']} | then: {type(e).__name__}: {e}"

        sweep_results.append(entry)
        persist(sweep_results)  # incremental - survives a crash on the NEXT model

    lines = persist(sweep_results)
    print("\n\n=== SWEEP SUMMARY ===")
    print("\n".join(lines))
    print(f"\nFull report: {out_dir / 'free5gc_llm_model_sweep.json'}")


if __name__ == "__main__":
    main()
