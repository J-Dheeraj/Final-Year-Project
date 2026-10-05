"""Same comparison as run_model_sweep.py, but for real Claude models via
the `claude` CLI's own authenticated session (ClaudeCLIProvider) instead
of local Ollama models. This is a PAID backend - every completion call
costs real money against the account the `claude` CLI is logged into.

IMPORTANT import-order note: src.reachability.providers.NO_PAID_BACKEND
is a module-level constant computed once, the first time providers.py is
imported, from the NO_PAID_BACKEND env var at that moment. This script
must explicitly set it to "0" BEFORE importing anything from
src.reachability (directly or via prepare_llm_patched_source), or
ClaudeCLIProvider's construction will unconditionally refuse. It is then
safe to import run_full_deployment_harness afterward even though that
module sets NO_PAID_BACKEND=1 itself - providers.py is already cached
in sys.modules by then and won't re-read the env var.

Run: python free5gc_full_deployment/run_claude_model_sweep.py
"""
from __future__ import annotations

import os

os.environ["NO_PAID_BACKEND"] = "0"  # MUST be first, before any reachability import

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent.resolve()
UDR_BUILD_DIR = HERE / "udr_build"
sys.path.insert(0, str(UDR_BUILD_DIR))

import prepare_llm_patched_source as prep  # noqa: E402 - triggers the providers.py import above
from src.reachability.providers import ClaudeCLIProvider  # noqa: E402

import run_full_deployment_harness as base  # noqa: E402 - sets NO_PAID_BACKEND=1 again, harmless now
from run_model_sweep import docker_build, safe_tag, verdict_from  # noqa: E402

CLAUDE_MODELS = [
    "claude-haiku-4-5-20251001",
    "claude-sonnet-5-5",
    "claude-opus-5-5",
]


def main() -> None:
    (HERE / "evidence").mkdir(exist_ok=True)
    out_dir = HERE.parent / "reports" / "reachability"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Bringing up db + real NRF (idempotent if already up)...")
    base.compose("up", "-d", "db", "free5gc-nrf", env={"UDR_IMAGE_TAG": "vulnerable"})

    print("Establishing the vulnerable baseline once, shared across all models...")
    base.bring_up("vulnerable")
    vuln_result = base.run_case("vulnerable_claude_sweep_baseline")
    base.save_container_log("vulnerable_claude_sweep_baseline")

    def persist(sweep_results: list) -> list:
        report = {
            "cve_id": "CVE-2026-40248",
            "target_handler": "HandleApplicationDataInfluenceDataSubsToNotifyGet",
            "vulnerable_commit": base.VULN_COMMIT,
            "backend": "claude-cli (paid)",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "vulnerable_baseline_run": vuln_result,
            "models": sweep_results,
        }
        (out_dir / "free5gc_llm_claude_sweep.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")

        lines = ["# free5GC LLM patch: Claude model comparison", "",
                 "| Model | Compiles | Applied/4 | Cost (USD) | Runtime verdict |",
                 "|---|---|---|---|---|"]
        for e in sweep_results:
            compiles = "yes" if e["compile"]["compiles"] else f"NO ({e['compile']['error']})"
            applied = e["compile"]["applied"]
            cost = e["compile"].get("cost_usd")
            cost_s = f"${cost:.4f}" if cost is not None else "n/a"
            runtime = e["runtime"]["overall_verdict"] if e["runtime"] else (
                "not reached (build failed)" if e.get("build_ok") is False else "not reached (compile failed)")
            lines.append(f"| `{e['model']}` | {compiles} | {applied}/4 | {cost_s} | {runtime} |")
        (out_dir / "free5gc_llm_claude_sweep.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return lines

    sweep_results = []
    total_cost = 0.0
    for model in CLAUDE_MODELS:
        print(f"\n{'='*70}\n{model} (PAID)\n{'='*70}")
        entry = {"model": model, "compile": None, "runtime": None}
        try:
            provider = ClaudeCLIProvider(model)
            compile_result = prep.materialize_and_verify(model, provider_factory=lambda m: provider)
            cost = getattr(provider, "last_cost_usd", None)
            if cost:
                total_cost += cost
            entry["compile"] = {
                "patch_method": compile_result["patch_method"],
                "applied": compile_result["applied"],
                "compiles": compile_result["compiles"],
                "error": compile_result["error"],
                "diff": compile_result["diff"],
                "cost_usd": cost,
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
                    patched_result = base.run_case(f"{tag}_claude_sweep")
                    base.save_container_log(f"{tag}_claude_sweep")
                    entry["runtime"] = verdict_from(vuln_result, patched_result)
                    print(f"[{model}] runtime verdict: {entry['runtime']['overall_verdict']}")
        except Exception as e:
            print(f"[{model}] UNEXPECTED ERROR: {type(e).__name__}: {e}")
            if entry["compile"] is None:
                entry["compile"] = {"patch_method": None, "applied": 0, "compiles": False,
                                     "error": f"{type(e).__name__}: {e}", "diff": None, "cost_usd": None}

        sweep_results.append(entry)
        persist(sweep_results)

    lines = persist(sweep_results)
    print("\n\n=== CLAUDE SWEEP SUMMARY ===")
    print("\n".join(lines))
    print(f"\nTotal measured cost: ${total_cost:.4f}")
    print(f"Full report: {out_dir / 'free5gc_llm_claude_sweep.json'}")


if __name__ == "__main__":
    main()
