"""Measure prompt/cache sensitivity for Claude and AIxTech backends.

These backends do not expose a seed. Each variant is semantically identical
but carries a unique no-op marker, allowing gateway caching to be distinguished
from stability under an unchanged request protocol.
"""
from __future__ import annotations
import argparse, hashlib, json, time
from datetime import datetime, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.reachability.claude_backend import provider_for

BASE = "Return one concise patch plan for free5GC handler validation. The source is pinned and the task is unchanged."

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["claude", "aixtech"], required=True)
    ap.add_argument("--models", required=True)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--output", default=None)
    args = ap.parse_args()
    rows = []
    for model in args.models.split(","):
        for run in range(1, args.runs + 1):
            marker = f"CACHE_SENSITIVITY_RUN_{run}_{model}"
            user = BASE + f"\nNo-op audit marker: {marker}."
            started = time.perf_counter()
            provider = provider_for(args.backend, model)
            error = None
            try:
                text = provider.complete("You are an authorized security research assistant.", user)
            except Exception as exc:
                text = ""
                error = f"{type(exc).__name__}: {exc}"
            rows.append({
                "backend": args.backend, "model": model, "run": run,
                "prompt_variant": marker, "output_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "output_chars": len(text), "error": error,
                "duration_s": getattr(provider, "last_duration_s", time.perf_counter() - started),
                "usage": getattr(provider, "last_usage", None),
                "cost_usd": getattr(provider, "last_cost_usd", None),
                "billing_basis": getattr(provider, "billing_basis", "token counts only"),
            })
    out = Path(args.output or f"reports/reachability/free5gc_{args.backend}_prompt_cache_sensitivity.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"schema": "backend-prompt-cache-sensitivity-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "interpretation": "Identical outputs across unique prompt markers indicate stability under this gateway/request protocol, not intrinsic model determinism.",
        "rows": rows}, indent=2), encoding="utf-8")
    print(f"wrote {len(rows)} rows to {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
