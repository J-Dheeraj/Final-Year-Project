#!/usr/bin/env python3
"""Memorization control for the free5GC LLM-patch results.

Every prior free5GC LLM-patch result (docs/FREE5GC_LLM_PATCH_RESULTS.md,
docs/FREE5GC_LLM_MODEL_SWEEP_RESULTS.md, the Claude sweeps) carries the
same stated limitation: a model fixing CVE-2026-40248 (fix commit
86686276, public since this project started) might be pattern-matching a
memorized copy of the real upstream commit rather than genuinely
reasoning about the code in front of it. There was no way to tell the
two apart from those results alone.

This experiment builds a control for that. `HandleCreateAuthenticationStatus`
(same file, same real vendored free5GC/udr source as the CVE handlers,
but NOT one of the four CVE-2026-40248 entrypoints) has the identical bug
*shape* the heuristic looks for (CWE-285: an early-exit validation block
writes a Gin HTTP response but has no `return`, so the function falls
through to privileged logic afterward) but, in the real, unmodified
source, is written CORRECTLY - it has the `return`. This script
synthetically deletes that one `return` to create a bug that:

  1. Is the same bug CLASS as the real CVE (verified by running the
     exact same `find_missing_return_after_response` heuristic against
     both the original and the injected function, confirming the
     original is clean and the injected copy is flagged).
  2. Has never existed in any public commit of free5gc/udr - it is
     created fresh by this script, in this function, which was never
     buggy in real life. No training corpus can contain its "fix"
     because its vulnerable form never existed before this run.

If a model's success rate here is comparable to its success rate on the
real CVE handler, that's evidence for genuine derivation (it can fix a
bug it has never seen before, in code it has never seen before). If the
rate drops sharply, that's an honest, equally reportable finding that
memorization likely inflated the real-CVE numbers - either outcome is
recorded as-is, not steered toward the more flattering one.

Deliberately scoped to the SAME evidence tier as this project's first
free5GC proof point (compile-verification against a live clone of the
real upstream module), not the full Docker runtime harness - this
handler's own data path (UE authentication-status storage) was never
wired into free5gc_full_deployment/'s MongoDB seeding, and standing that
up is out of scope for this one control experiment. Said explicitly in
the output rather than left implicit.

Run: python -m src.reachability.run_memorization_control
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.reachability.claude_backend import CLAUDE_MODELS, provider_for  # noqa: E402 - import first, bakes NO_PAID_BACKEND
from src.reachability.heuristics import find_missing_return_after_response  # noqa: E402
from src.reachability.patch import generate_patch  # noqa: E402
from src.reachability.pipeline import PipelineConfig, run_pipeline  # noqa: E402

REPO_URL = "https://github.com/free5gc/udr.git"
FIX_COMMIT = "86686276a7e226183ee786e3dd6714ec56c78fda"
VULN_COMMIT = f"{FIX_COMMIT}^"
REL_FILE = Path("internal/sbi/api_datarepository.go")

CASE_DIR = Path(__file__).parent / "examples" / "free5gc_case_study"
CONTROL_DIR = Path(__file__).parent / "examples" / "memorization_control"
TARGET = "HandleCreateAuthenticationStatus"

# NOTE: the 8 models used in every prior free5GC Ollama sweep
# (run_model_sweep.py / run_bypass_probe_sweep.py) are no longer pulled
# on this machine as of this run (`ollama list` returns 404 for all 8 -
# apparently removed between sessions, consistent with this project's
# repeated disk/OOM constraints). Re-pulling 8 multi-GB models was judged
# not worth the time/disk cost for one control experiment, so this uses
# whatever chat-capable models are ACTUALLY present right now. This means
# the model set differs from prior sweeps - said explicitly in the
# report rather than silently treated as the same population. To make
# the comparison meaningful anyway, run_memorization_control_baseline.py
# re-runs these SAME models against the REAL CVE handler in the same
# session, so the two arms are at least matched to each other.
MODELS = ["llama3.2:1b", "llama3.2:3b", "qwen3:8b", "deepseek-r1:14b"]

OUT_DIR = Path(__file__).resolve().parents[2] / "reports" / "reachability"

_ORIGINAL_GUARD = (
    '\t\tc.JSON(http.StatusBadRequest, rsp)\n'
    '\t\treturn\n'
    '\t}\n'
)
_INJECTED_GUARD = (
    '\t\tc.JSON(http.StatusBadRequest, rsp)\n'
    '\t}\n'
)


def _extract_function(source: str, name: str) -> str:
    m = re.search(rf"\nfunc \(s \*Server\) {re.escape(name)}\(c \*gin\.Context\) \{{", source)
    if not m:
        raise ValueError(f"{name} not found in source")
    start = m.start() + 1
    depth = 0
    i = source.index("{", m.start())
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise ValueError(f"unterminated function body for {name}")


def _inject_bug(original_func: str) -> str:
    if original_func.count(_ORIGINAL_GUARD) != 1:
        raise ValueError(
            f"expected exactly one occurrence of the 'Malformed request syntax' "
            f"guard in {TARGET}, found {original_func.count(_ORIGINAL_GUARD)} - "
            f"vendored source may have drifted; aborting rather than guessing."
        )
    return original_func.replace(_ORIGINAL_GUARD, _INJECTED_GUARD, 1)


def _go_build(module_dir: Path, label: str) -> tuple[bool, str]:
    proc = subprocess.run(["go", "build", "./..."], cwd=str(module_dir),
                           capture_output=True, text=True, timeout=240)
    ok = proc.returncode == 0
    print(f"  [{label}] go build ./... -> {'OK' if ok else 'FAILED'}")
    return ok, (proc.stdout[-1500:] + proc.stderr[-1500:])


def build_synthetic_case_file() -> tuple[Path, str, str]:
    """Returns (path to the synthetic whole-file case study, original
    function text, injected function text)."""
    vulnerable_path = CASE_DIR / "api_datarepository_vulnerable.go"
    full_source = vulnerable_path.read_text(encoding="utf-8")
    original_func = _extract_function(full_source, TARGET)
    injected_func = _inject_bug(original_func)

    clean_finding = find_missing_return_after_response(original_func)
    injected_finding = find_missing_return_after_response(injected_func)
    if clean_finding is not None:
        raise RuntimeError(
            f"{TARGET} is unexpectedly already flagged in the real, unmodified "
            f"source - this control is only valid against a currently-correct "
            f"function. Aborting rather than reporting a bogus control."
        )
    if injected_finding is None:
        raise RuntimeError(
            f"Injection into {TARGET} did not produce a heuristic-detectable "
            f"finding - the injection didn't create the intended bug shape."
        )

    assert full_source.count(original_func) == 1, (
        f"{TARGET}'s body text is not unique in the vendored file - "
        f"refusing to splice to avoid touching the wrong occurrence."
    )
    synthetic_source = full_source.replace(original_func, injected_func, 1)

    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CONTROL_DIR / "api_datarepository_synthetic_vulnerable.go"
    # newline="\n" forces real \n bytes on disk - without it, Windows'
    # default text-mode write translates \n -> \r\n, so tree-sitter's
    # byte-level read of this file back in the pipeline stage produces
    # \r\n-containing function bodies that don't byte-match the \n-only
    # strings held in memory here (original_func/injected_func), which
    # made `patch.original not in vulnerable_text` fail downstream even
    # though the actual content was identical modulo line endings.
    out_path.write_text(synthetic_source, encoding="utf-8", newline="\n")
    return out_path, original_func, injected_func


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["ollama", "claude"], default="ollama")
    args = ap.parse_args()
    backend = args.backend
    models = CLAUDE_MODELS if backend == "claude" else MODELS

    if shutil.which("git") is None or shutil.which("go") is None:
        print("Needs both `git` and `go` on PATH; aborting.")
        return 1

    print(f"Building synthetic vulnerable case file (injecting a never-"
          f"publicly-disclosed CWE-285 bug into {TARGET})...")
    synthetic_path, original_func, injected_func = build_synthetic_case_file()
    print(f"  Sanity check passed: real {TARGET} is clean; injected copy is "
          f"flagged by the same heuristic used for the real CVE.")
    print(f"  Synthetic case file written to {synthetic_path}")

    cfg = PipelineConfig(
        target=synthetic_path, entrypoints=[TARGET], provider="mock",
        cache_dir=None, skip_testing=True,
    )
    _, outcomes = run_pipeline(cfg)
    patches_by_name = {o.patch.finding.triage.function.name: o.patch for o in outcomes}
    if TARGET not in patches_by_name:
        print(f"{TARGET} was not flagged/verified by the mock run against the "
              f"synthetic case file - aborting.")
        return 1
    finding = patches_by_name[TARGET].finding

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sweep_results = []
    total_cost = 0.0
    stem = f"free5gc_memorization_control_{backend}" if backend == "claude" else "free5gc_memorization_control"

    def persist(results: list) -> None:
        report = {
            "experiment": "memorization_control", "backend": backend,
            "target_function": TARGET,
            "injection": "synthetic - deleted the real, correctly-present "
                         "`return` from the 'Malformed request syntax' guard; "
                         "this exact vulnerable function text has never "
                         "existed in any public free5gc/udr commit",
            "vulnerable_commit_used_for_compile_verification": VULN_COMMIT,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "models": results,
            "scope_note": "compile-verification only (same tier as "
                           "run_free5gc_llm_patch.py's first result), not "
                           "runtime-confirmed - this handler's data path was "
                           "never wired into the Docker full-deployment harness",
        }
        (OUT_DIR / f"{stem}.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")
        lines = [f"# free5GC memorization control ({backend}): synthetic, never-disclosed bug", "",
                 f"Target: `{TARGET}` (NOT one of the four real CVE-2026-40248 "
                 f"handlers) - same bug class, injected fresh by this experiment.", "",
                 "| Model | Compiles (fixes the synthetic bug) | Cost (USD) |",
                 "|---|---|---|"]
        for e in results:
            compiles = "yes" if e["compiles"] else f"NO ({e['error']})"
            cost = e.get("cost_usd")
            cost_s = f"${cost:.4f}" if cost else "n/a"
            lines.append(f"| `{e['model']}` | {compiles} | {cost_s} |")
        (OUT_DIR / f"{stem}.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8")

    for model in models:
        print(f"\n{'='*70}\n{model}\n{'='*70}")
        entry = {"model": model, "compiles": False, "error": None, "diff": None, "cost_usd": None}
        try:
            provider = provider_for(backend, model)
            patch = generate_patch(finding, provider, exploit_outcome=None)
            entry["cost_usd"] = getattr(provider, "last_cost_usd", None)
            if entry["cost_usd"]:
                total_cost += entry["cost_usd"]
            entry["diff"] = patch.diff

            with tempfile.TemporaryDirectory(prefix="free5gc_udr_memcontrol_") as tmp:
                module_dir = Path(tmp) / "udr"
                subprocess.run(["git", "clone", "--quiet", REPO_URL, str(module_dir)], check=True)
                subprocess.run(["git", "checkout", "--quiet", VULN_COMMIT],
                                cwd=str(module_dir), check=True)
                real_file = module_dir / REL_FILE
                real_text = real_file.read_text(encoding="utf-8")

                if original_func not in real_text:
                    entry["error"] = "function body doesn't byte-match the vendored snapshot"
                    sweep_results.append(entry)
                    persist(sweep_results)
                    continue

                # Step 1: inject the synthetic bug into the real module, same
                # as the real CVE's vulnerable baseline, and confirm it still
                # builds (deleting a `return` is syntactically valid Go).
                vulnerable_text = real_text.replace(original_func, injected_func, 1)
                real_file.write_text(vulnerable_text, encoding="utf-8")
                vuln_ok, vuln_log = _go_build(module_dir, "injected-vulnerable baseline")
                if not vuln_ok:
                    entry["error"] = f"injected-vulnerable baseline itself failed to build: {vuln_log[-500:]}"
                    sweep_results.append(entry)
                    persist(sweep_results)
                    continue

                # Step 2: apply the model's patch on top, and build again.
                if patch.original not in vulnerable_text:
                    entry["error"] = "model's patch 'original' text doesn't match the injected function"
                    sweep_results.append(entry)
                    persist(sweep_results)
                    continue
                patched_text = vulnerable_text.replace(patch.original, patch.patched, 1)
                real_file.write_text(patched_text, encoding="utf-8")
                ok, log = _go_build(module_dir, f"{model} patch applied")
                entry["compiles"] = ok
                if not ok:
                    entry["error"] = log[-500:]
        except Exception as e:
            print(f"[{model}] UNEXPECTED ERROR: {type(e).__name__}: {e}")
            entry["error"] = f"{type(e).__name__}: {e}"

        sweep_results.append(entry)
        persist(sweep_results)

    persist(sweep_results)
    n_ok = sum(1 for e in sweep_results if e["compiles"])
    print(f"\n\n=== MEMORIZATION CONTROL SUMMARY ===")
    print(f"{n_ok}/{len(sweep_results)} models produced a compiling fix for the "
          f"synthetic, never-publicly-disclosed bug.")
    if backend == "claude":
        print(f"Total measured cost: ${total_cost:.4f}")
    print(f"Full report: {OUT_DIR / f'{stem}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
