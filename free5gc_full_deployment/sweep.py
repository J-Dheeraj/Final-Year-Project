"""Unified CLI for free5GC CVE-2026-40248 LLM experiments.

Consolidates 5 near-duplicate scripts that grew incrementally over
several sessions - run_model_sweep.py, run_claude_model_sweep.py,
run_claude_sweep_extended.py, run_bypass_probe_sweep.py,
run_claude_bypass_probe_sweep.py (869 lines total, each one a copy of
the last with a different model list or provider swapped in) - into one
parameterized tool, so a new experiment (a new model list, a multi-run
variance study) doesn't need a 6th copy-pasted script. The 5 originals
are left in place, unmodified: they're the exact, citable invocation
each already-published doc/report points to, and this file imports
several of their functions directly (docker_build, safe_tag,
verdict_from, probe_one_model) rather than redefining them.

Usage:
    python sweep.py --task patch  --backend ollama
    python sweep.py --task patch  --backend claude --models claude-haiku-4-5-20251001,claude-opus-5-5
    python sweep.py --task bypass --backend ollama
    python sweep.py --task bypass --backend claude
    python sweep.py --task patch  --backend ollama --runs 5   # multi-run variance

Output: reports/reachability/free5gc_sweep_<task>_<backend>.json/.md -
new, consistently-named files that do not overwrite any prior sweep's
report (those stay as the historical record existing docs cite).

Requires: Docker Desktop running, free5gc-udr-custom:vulnerable (and,
for --task bypass, :patched) already built - see SETUP.md.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil

os.environ["NO_PAID_BACKEND"] = "0"  # see src/reachability/providers.py's import-order note

import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(HERE / "udr_build"))
sys.path.insert(0, str(HERE.parent))

import prepare_llm_patched_source as prep  # noqa: E402 - bakes NO_PAID_BACKEND into providers.py
from src.reachability.providers import OllamaProvider, ClaudeCLIProvider, CodexCLIProvider, OpenAIProvider  # noqa: E402
from src.reachability.claude_backend import OPENAI_MODELS  # noqa: E402

import run_full_deployment_harness as base  # noqa: E402 - safe: providers.py already cached by now
from run_model_sweep import docker_build, safe_tag, verdict_from  # noqa: E402
from run_bypass_probe_sweep import probe_one_model, SEEDED_SUB_ID, SEEDED_DNN  # noqa: E402

DEFAULT_MODELS = {
    ("patch", "codex"): [
        "gpt-6-astra", "gpt-6.1-sol", "gpt-6-sol", "gpt-6-luna",
        "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
        "gpt-5", "gpt-4.1", "gpt-4o", "o3", "o4-mini",
    ],
    ("patch", "ollama"): [
        "deepseek-coder-v2:16b", "codellama:13b", "gemma2:9b", "mistral:7b",
        "llama3.1:8b", "qwen2.5-coder:7b", "qwen2.5-coder:3b", "qwen2.5-coder:1.5b",
    ],
    ("patch", "claude"): [
        # Union of run_claude_model_sweep.py (3) + run_claude_sweep_extended.py
        # (5) - 8 distinct models total, per the arithmetic correction made to
        # docs/SCOPE_AND_LIMITATIONS.md Limitation 6.
        "claude-haiku-4-5-20251001", "claude-sonnet-4-6", "claude-sonnet-5",
        "claude-sonnet-5-5", "claude-opus-4-6", "claude-opus-4-7",
        "claude-opus-4-8", "claude-opus-5-5",
    ],
    ("bypass", "ollama"): [
        "deepseek-coder-v2:16b", "codellama:13b", "gemma2:9b", "mistral:7b",
        "llama3.1:8b", "qwen2.5-coder:7b", "qwen2.5-coder:3b", "qwen2.5-coder:1.5b",
    ],
    ("bypass", "claude"): [
        "claude-haiku-4-5-20251001", "claude-sonnet-4-5", "claude-sonnet-4-6",
        "claude-sonnet-5", "claude-sonnet-5-5", "claude-opus-4-6",
        "claude-opus-4-7", "claude-opus-4-8", "claude-opus-4-9",
        "claude-opus-5", "claude-opus-5-5",
    ],
    ("bypass", "codex"): [
        "gpt-6-astra", "gpt-6.1-sol", "gpt-6-sol", "gpt-6-luna",
        "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
        "gpt-5", "gpt-4.1", "gpt-4o", "o3", "o4-mini",
    ],
    ("patch", "openai"): OPENAI_MODELS,
    ("bypass", "openai"): OPENAI_MODELS,
}


def provider_factory_for(backend: str):
    if backend == "codex":
        return CodexCLIProvider
    if backend == "openai":
        return OpenAIProvider
    return ClaudeCLIProvider if backend == "claude" else OllamaProvider


def run_patch_one(model: str, backend: str, run_idx: int, vuln_result: dict,
                  artifact_root: Path | None = None,
                  experiment_id: str | None = None,
                  temperature: float | None = None,
                  seed: int | None = None) -> dict:
    entry = {"model": model, "run": run_idx, "compile": None, "runtime": None,
             "build_ok": None, "generation_outcome": "llm_live_failed"}
    if artifact_root is not None:
        artifact_root.mkdir(parents=True, exist_ok=True)
        entry["artifact_dir"] = str(artifact_root)

    def persist_artifact() -> None:
        if artifact_root is not None:
            (artifact_root / "manifest.json").write_text(
                json.dumps(entry, indent=2), encoding="utf-8")

    try:
        if backend == "claude":
            provider = ClaudeCLIProvider(model)
            compile_result = prep.materialize_and_verify(model, provider_factory=lambda m: provider)
            cost = getattr(provider, "last_cost_usd", None)
        elif backend == "codex":
            provider = CodexCLIProvider(model)
            compile_result = prep.materialize_and_verify(model, provider_factory=lambda m: provider)
            cost = getattr(provider, "last_cost_usd", None)
        elif backend == "openai":
            provider = OpenAIProvider(model, temperature=temperature, seed=seed)
            compile_result = prep.materialize_and_verify(model, provider_factory=lambda m: provider)
            cost = getattr(provider, "last_cost_usd", None)
        else:
            compile_result = prep.materialize_and_verify(model)
            cost = None
        entry["compile"] = {
            "patch_method": compile_result["patch_method"],
            "applied": compile_result["applied"],
            "compiles": compile_result["compiles"],
            "error": compile_result["error"],
            "diff": compile_result["diff"],
            "cost_usd": cost,
            "duration_s": compile_result.get("duration_s"),
            "usage": compile_result.get("usage"),
            "thread_id": compile_result.get("thread_id"),
            "billing_basis": compile_result.get("billing_basis"),
            "raw_usage_events": compile_result.get("raw_usage_events"),
            "request_parameters": {
                "temperature": temperature,
                "seed": seed,
                "sampling_fallback_reason": getattr(provider, "sampling_fallback_reason", None),
            } if backend == "openai" else None,
        }
        if compile_result.get("patch_method"):
            entry["generation_outcome"] = "llm_live_success"
        elif compile_result.get("error"):
            entry["generation_outcome"] = "llm_live_failed"
        if not compile_result["compiles"]:
            persist_artifact()
            return entry

        tag_prefix = safe_tag(experiment_id) if experiment_id else "sweep"
        tag = f"{tag_prefix}-{safe_tag(model)}-r{run_idx}"
        patched_file = Path(compile_result["output_file"])
        if artifact_root is not None:
            # Preserve the generated source even when the subsequent Docker
            # build or runtime stage fails.
            shutil.copy2(patched_file, artifact_root / patched_file.name)
            persist_artifact()
        build_ok, build_log = docker_build(patched_file, tag)
        entry["build_ok"] = build_ok
        if not build_ok:
            entry["build_log_tail"] = build_log[-1000:]
            persist_artifact()
            return entry

        base.bring_up(tag)
        patched_result = base.run_case(f"{tag}_sweep")
        base.save_container_log(f"{tag}_sweep")
        entry["runtime"] = verdict_from(vuln_result, patched_result)
        persist_artifact()
    except Exception as e:
        # One model/run's crash must not lose every other already-completed result.
        print(f"[{model} run {run_idx}] UNEXPECTED ERROR: {type(e).__name__}: {e}")
        if entry["compile"] is None:
            entry["compile"] = {"patch_method": None, "applied": 0, "compiles": False,
                                 "error": f"{type(e).__name__}: {e}", "diff": None, "cost_usd": None}
        entry["generation_outcome"] = "llm_live_failed"
        if artifact_root is not None:
            persist_artifact()
    return entry


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--task", choices=["patch", "bypass"], required=True)
    ap.add_argument("--backend", choices=["ollama", "claude", "codex", "openai"], required=True)
    ap.add_argument("--models", default=None,
                     help="comma-separated override; default is the task/backend's established list")
    ap.add_argument("--runs", type=int, default=1,
                     help="repeat each model N times to measure confirmation-rate variance (default 1)")
    ap.add_argument("--run-id", default=None,
                    help="unique label for this experiment; isolates reports and artifacts")
    ap.add_argument("--temperature", type=float, default=None,
                    help="OpenAI sampling temperature for controlled repeats")
    ap.add_argument("--seed", type=int, default=None,
                    help="OpenAI seed for controlled repeats where supported")
    args = ap.parse_args()

    models = args.models.split(",") if args.models else DEFAULT_MODELS[(args.task, args.backend)]
    out_dir = HERE.parent / "reports" / "reachability"
    out_dir.mkdir(parents=True, exist_ok=True)
    (HERE / "evidence").mkdir(exist_ok=True)
    if args.runs < 1:
        ap.error("--runs must be at least 1")
    run_suffix = f"_{safe_tag(args.run_id)}" if args.run_id else ""
    report_stem = f"free5gc_sweep_{args.task}_{args.backend}{run_suffix}"
    artifact_base = out_dir / (args.run_id or report_stem)

    vuln_result = None
    print("Bringing up db + real NRF (idempotent if already up)...")
    if args.task == "patch":
        base.compose("up", "-d", "db", "free5gc-nrf", env={"UDR_IMAGE_TAG": "vulnerable"})
        print("Establishing the vulnerable baseline once, shared across all models/runs...")
        base.bring_up("vulnerable")
        vuln_result = base.run_case(f"{report_stem}_vulnerable_baseline")
        base.save_container_log(f"{report_stem}_vulnerable_baseline")
    else:
        base.compose("up", "-d", "db", "free5gc-nrf", env={"UDR_IMAGE_TAG": "patched"})
        print("Bringing up the REAL upstream-fix UDR build (free5gc-udr-custom:patched)...")
        base.bring_up("patched")
        base.save_container_log(f"{report_stem}_patched_build")
        print(f"Seeding a known record (influenceId=subs-to-notify, subId={SEEDED_SUB_ID})...")
        seed_resp = base.seed(SEEDED_SUB_ID, SEEDED_DNN)
        print(f"  seed -> {seed_resp.status_code}")

    results: list = []
    total_cost = 0.0

    def persist() -> None:
        report = {
            "task": args.task, "backend": args.backend, "experiment_id": args.run_id or report_stem,
            "runs_per_model": args.runs,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "models": results,
        }
        if vuln_result is not None:
            report["vulnerable_baseline_run"] = vuln_result
        (out_dir / f"{report_stem}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

        lines = [f"# free5GC {args.task} sweep: {args.backend} ({args.runs} run(s)/model)", ""]
        if args.runs == 1:
            if args.task == "patch":
                lines += ["| Model | Compiles | Applied/4 | Cost (USD) | Runtime verdict |",
                           "|---|---|---|---|---|"]
                for e in results:
                    compiles = "yes" if e["compile"]["compiles"] else f"NO ({e['compile']['error']})"
                    cost = e["compile"].get("cost_usd")
                    cost_s = f"${cost:.4f}" if cost else "n/a"
                    runtime = e["runtime"]["overall_verdict"] if e["runtime"] else (
                        "not reached (build failed)" if e.get("build_ok") is False
                        else "not reached (compile failed)")
                    lines.append(f"| `{e['model']}` | {compiles} | {e['compile']['applied']}/4 | {cost_s} | {runtime} |")
            else:
                lines += ["| Model | Proposal parsed | Request executed | Bypass confirmed |",
                           "|---|---|---|---|"]
                for e in results:
                    parsed = "yes" if e.get("proposal") else f"NO ({e.get('error')})"
                    executed = "yes" if e.get("executed_request") else "no"
                    bypass = "**YES**" if e.get("bypass_confirmed") else "no (fix held)"
                    lines.append(f"| `{e['model']}` | {parsed} | {executed} | {bypass} |")
        else:
            by_model = defaultdict(list)
            for e in results:
                by_model[e["model"]].append(e)
            lines += ["| Model | Confirmation rate | Runs |", "|---|---|---|"]
            for model, entries in by_model.items():
                if args.task == "patch":
                    hits = sum(1 for e in entries
                               if e.get("runtime") and e["runtime"]["overall_verdict"] == "confirmed_fix_all_four_handlers")
                else:
                    hits = sum(1 for e in entries if e.get("bypass_confirmed"))
                lines.append(f"| `{model}` | {hits}/{len(entries)} | {len(entries)} |")
        (out_dir / f"{report_stem}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    for model in models:
        for run_idx in range(1, args.runs + 1):
            label = f"{model} (run {run_idx}/{args.runs})" if args.runs > 1 else model
            print(f"\n{'='*70}\n{label}\n{'='*70}")
            if args.task == "patch":
                artifact_root = artifact_base / safe_tag(model) / f"run-{run_idx}"
                entry = run_patch_one(model, args.backend, run_idx, vuln_result,
                                      artifact_root=artifact_root,
                                      experiment_id=args.run_id or report_stem,
                                      temperature=args.temperature,
                                      seed=args.seed)
                cost = entry["compile"].get("cost_usd") if entry.get("compile") else None
            else:
                entry = probe_one_model(model, provider_factory=provider_factory_for(args.backend))
                entry["run"] = run_idx
                cost = entry.get("cost_usd")
            if cost:
                total_cost += cost
            results.append(entry)
            persist()

    persist()
    if args.backend == "claude":
        print(f"\n\nDone. Total measured cost: ${total_cost:.4f}")
    elif args.backend == "codex":
        print("\n\nDone (Codex CLI; token usage recorded, no direct API charge returned).")
    else:
        print("\n\nDone (free backend).")
    print(f"Report: {out_dir / f'{report_stem}.json'}")


if __name__ == "__main__":
    main()
