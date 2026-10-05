"""Same adversarial bypass-probe as run_bypass_probe_sweep.py, but for
real Claude models via the `claude` CLI's own authenticated session
(ClaudeCLIProvider) instead of local Ollama models. PAID backend -
every completion call costs real money. This is an even more explicitly
"find an exploit bypass" framing than the patch-generation prompt used
in run_claude_model_sweep.py, so a given model may refuse here even if
it answered the patch-generation prompt fine (or vice versa) -
`claude-sonnet-5` is known to refuse the patch-generation prompt via
Anthropic's own real-time cyber safeguard (docs/
FREE5GC_LLM_CLAUDE_SWEEP_EXTENDED_RESULTS.md); whether it also refuses
THIS prompt is itself part of what this run finds out.

IMPORTANT import-order note: same as run_claude_model_sweep.py -
src.reachability.providers.NO_PAID_BACKEND is fixed at providers.py's
first import, so it must be set to "0" before any reachability import.

Run: python free5gc_full_deployment/run_claude_bypass_probe_sweep.py
"""
from __future__ import annotations

import os

os.environ["NO_PAID_BACKEND"] = "0"  # MUST be first, before any reachability import

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(HERE.parent))

from src.reachability.providers import ClaudeCLIProvider  # noqa: E402

import run_full_deployment_harness as base  # noqa: E402
from run_bypass_probe_sweep import SEEDED_SUB_ID, SEEDED_DNN, probe_one_model  # noqa: E402

CLAUDE_MODELS = [
    "claude-haiku-4-5-20251001",
    "claude-sonnet-4-5",
    "claude-sonnet-4-6",
    "claude-sonnet-5",
    "claude-sonnet-5-5",
    "claude-opus-4-6",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-opus-4-9",
    "claude-opus-5",
    "claude-opus-5-5",
]


def main() -> None:
    (HERE / "evidence").mkdir(exist_ok=True)
    out_dir = HERE.parent / "reports" / "reachability"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Bringing up db + real NRF (idempotent if already up)...")
    base.compose("up", "-d", "db", "free5gc-nrf", env={"UDR_IMAGE_TAG": "patched"})
    print("Bringing up the REAL upstream-fix UDR build (free5gc-udr-custom:patched)...")
    base.bring_up("patched")
    base.save_container_log("claude_bypass_probe_patched_build")

    print(f"Seeding a known record (influenceId=subs-to-notify, subId={SEEDED_SUB_ID})...")
    seed_resp = base.seed(SEEDED_SUB_ID, SEEDED_DNN)
    print(f"  seed -> {seed_resp.status_code}")

    def persist(results: list) -> list:
        report = {
            "cve_id": "CVE-2026-40248",
            "target": "free5gc-udr-custom:patched (real upstream fix commit)",
            "backend": "claude-cli (paid)",
            "seeded_resource": f"subs-to-notify/{SEEDED_SUB_ID}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "models": results,
        }
        (out_dir / "free5gc_claude_bypass_probe_sweep.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")
        lines = ["# free5GC bypass-probe sweep: Claude models vs. the real fix", "",
                 "| Model | Proposal parsed | Genuine trick | Cost (USD) | Bypass confirmed |",
                 "|---|---|---|---|---|"]
        for e in results:
            parsed = "yes" if e.get("proposal") else f"NO ({e.get('error')})"
            if e.get("proposal") and e.get("executed_request"):
                genuine = "no" if "not a genuine trick" in (e.get("signal") or "") else "yes"
            else:
                genuine = "n/a"
            cost = e.get("cost_usd")
            cost_s = f"${cost:.4f}" if cost is not None else "n/a"
            bypass = "**YES**" if e.get("bypass_confirmed") else "no (fix held)"
            lines.append(f"| `{e['model']}` | {parsed} | {genuine} | {cost_s} | {bypass} |")
        (out_dir / "free5gc_claude_bypass_probe_sweep.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return lines

    results = []
    total_cost = 0.0
    for model in CLAUDE_MODELS:
        print(f"\n{'='*70}\n{model} (PAID)\n{'='*70}")
        entry = probe_one_model(model, provider_factory=ClaudeCLIProvider)
        cost = entry.get("cost_usd")
        if cost:
            total_cost += cost
        if entry.get("proposal"):
            print(f"  proposal: {entry['proposal'].get('method')} {entry['proposal'].get('path')}")
            print(f"  reasoning: {entry['proposal'].get('reasoning')}")
        if entry.get("raw_response") and not entry.get("proposal"):
            print(f"  (no parseable proposal) raw: {str(entry['raw_response'])[:300]}")
        if entry.get("error"):
            print(f"  error: {entry['error']}")
        if entry.get("executed_request"):
            print(f"  response status: {entry['raw_response']['status_code']}")
            print(f"  bypass_confirmed: {entry['bypass_confirmed']} ({entry.get('signal')})")
        print(f"  cost: ${cost:.4f}" if cost else "  cost: n/a")
        results.append(entry)
        persist(results)

    lines = persist(results)
    print("\n\n=== CLAUDE BYPASS PROBE SUMMARY ===")
    print("\n".join(lines))
    print(f"\nTotal measured cost: ${total_cost:.4f}")
    print(f"Full report: {out_dir / 'free5gc_claude_bypass_probe_sweep.json'}")


if __name__ == "__main__":
    main()
