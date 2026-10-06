#!/usr/bin/env python3
"""Patch-quality scoring beyond pass/fail, for the free5GC LLM patches.

Every prior free5GC LLM-patch result reported a single binary outcome
per model: compiles + runtime-confirmed, or not. docs/SCOPE_AND_LIMITATIONS.md
names this explicitly as an unmeasured "correct patch" tier - a patch
that compiles and passes the runtime check could still look nothing
like the real fix, or could be needlessly complex/fragile in ways
pass/fail never surfaces. This script adds two measurements pass/fail
doesn't give:

1. Diff-similarity to the real upstream fix (difflib SequenceMatcher
   ratio, line-based), computed on the SAME target function
   (`HandleApplicationDataInfluenceDataSubsToNotifyGet`) each already-
   generated model patch touched - not a new model call, pure analysis
   over files already on disk from this project's prior sessions.
2. Structural proxies: does the patch use the SAME minimal fix shape as
   the real one (a single added `return` after the existing validation
   block) or does it rewrite more of the function; line-count delta
   vs. the real fix's near-zero delta (the real fix adds exactly one line).

Does not call Docker or Ollama - every patch scored here was already
compiled/runtime-confirmed in earlier sessions; this is purely a
retrospective quality analysis over already-trusted outcomes.

Run: python -m src.reachability.score_patch_quality
"""
from __future__ import annotations

import difflib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parents[2]
UDR_BUILD_DIR = HERE / "free5gc_full_deployment" / "udr_build"
REAL_FIX_FILE = HERE / "src" / "reachability" / "examples" / "free5gc_case_study" / "api_datarepository_patched.go"
OUT_DIR = HERE / "reports" / "reachability"
TARGET_FUNC = "HandleApplicationDataInfluenceDataSubsToNotifyGet"

_FILENAME_TO_MODEL = {
    "api_datarepository_llm_patched.go": "qwen2.5-coder:7b (original single-model run)",
    "api_datarepository_llm_patched_claude-haiku-4-5-20251001.go": "claude-haiku-4-5-20251001",
    "api_datarepository_llm_patched_claude-opus-4-6.go": "claude-opus-4-6",
    "api_datarepository_llm_patched_claude-opus-4-7.go": "claude-opus-4-7",
    "api_datarepository_llm_patched_claude-opus-4-8.go": "claude-opus-4-8",
    "api_datarepository_llm_patched_claude-opus-5-5.go": "claude-opus-5-5",
    "api_datarepository_llm_patched_claude-sonnet-4-6.go": "claude-sonnet-4-6",
    "api_datarepository_llm_patched_claude-sonnet-5-5.go": "claude-sonnet-5-5",
    "api_datarepository_llm_patched_codellama-13b.go": "codellama:13b",
    "api_datarepository_llm_patched_gemma2-9b.go": "gemma2:9b",
    "api_datarepository_llm_patched_llama3-1-8b.go": "llama3.1:8b",
    "api_datarepository_llm_patched_mistral-7b.go": "mistral:7b",
    "api_datarepository_llm_patched_qwen2-5-coder-1-5b.go": "qwen2.5-coder:1.5b",
    "api_datarepository_llm_patched_qwen2-5-coder-3b.go": "qwen2.5-coder:3b",
}


def extract_function(source: str, name: str) -> str | None:
    m = re.search(rf"\nfunc \(s \*Server\) {re.escape(name)}\(c \*gin\.Context\) \{{", source)
    if not m:
        return None
    i = source.index("{", m.start())
    depth = 0
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[m.start() + 1:i + 1]
        i += 1
    return None


def score(model_func: str, real_func: str) -> dict:
    model_lines = model_func.splitlines()
    real_lines = real_func.splitlines()
    ratio = difflib.SequenceMatcher(a=real_lines, b=model_lines).ratio()

    diff = list(difflib.unified_diff(real_lines, model_lines, lineterm=""))
    added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))

    # The real fix's own shape: exactly one added `return` inside the
    # existing early-exit validation block, nothing else changed - a
    # near-minimal diff. A model patch that needed to add/remove many
    # more lines than that achieved the same runtime behavior through a
    # structurally different (more invasive) rewrite, which is a real,
    # measurable quality difference pass/fail alone can't see.
    minimal_shape = (added <= 2 and removed == 0)

    return {
        "diff_similarity_ratio": round(ratio, 4),
        "lines_added_vs_real_fix": added,
        "lines_removed_vs_real_fix": removed,
        "model_function_line_count": len(model_lines),
        "real_fix_function_line_count": len(real_lines),
        "minimal_fix_shape": minimal_shape,
    }


def main() -> int:
    real_source = REAL_FIX_FILE.read_text(encoding="utf-8")
    real_func = extract_function(real_source, TARGET_FUNC)
    if real_func is None:
        print(f"Could not extract {TARGET_FUNC} from the real-fix reference file.")
        return 1

    results = []
    for path in sorted(UDR_BUILD_DIR.glob("api_datarepository_llm_patched*.go")):
        model_name = _FILENAME_TO_MODEL.get(path.name, path.name)
        source = path.read_text(encoding="utf-8")
        model_func = extract_function(source, TARGET_FUNC)
        if model_func is None:
            results.append({"model": model_name, "file": path.name, "error": f"{TARGET_FUNC} not found"})
            continue
        entry = {"model": model_name, "file": path.name}
        entry.update(score(model_func, real_func))
        results.append(entry)

    results.sort(key=lambda e: e.get("diff_similarity_ratio", 0), reverse=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "experiment": "patch_quality_scoring",
        "target_function": TARGET_FUNC,
        "method": "difflib.SequenceMatcher ratio + line-based diff stats against "
                   "the real upstream fix's own version of the same function; "
                   "no new model calls - scores already-generated, already "
                   "compile/runtime-confirmed patches from prior sessions",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "models": results,
    }
    (OUT_DIR / "patch_quality_scoring.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = ["# free5GC LLM patch quality scoring (beyond pass/fail)", "",
             "| Model | Diff similarity to real fix | Lines added | Lines removed | Minimal fix shape |",
             "|---|---|---|---|---|"]
    for e in results:
        if "error" in e:
            lines.append(f"| `{e['model']}` | ERROR: {e['error']} | | | |")
            continue
        lines.append(f"| `{e['model']}` | {e['diff_similarity_ratio']:.4f} | "
                      f"{e['lines_added_vs_real_fix']} | {e['lines_removed_vs_real_fix']} | "
                      f"{e['minimal_fix_shape']} |")
    (OUT_DIR / "patch_quality_scoring.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    print(f"\nFull report: {OUT_DIR / 'patch_quality_scoring.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
