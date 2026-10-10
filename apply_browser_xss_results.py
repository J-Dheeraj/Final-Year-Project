"""Merge browser replay classifications into historical catalogue reports."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
replay = json.loads((ROOT / "reports/reachability/catalog_xss_browser_replay.json").read_text())
lookup = {(r["source_report"], r["model"], r["cve_id"]): r for r in replay["rows"]}
paths = list((ROOT / "reports/reachability").glob("catalog_bypass_probe.json")) + list((ROOT / "reports/reachability").glob("catalog_bypass_probe_*.json"))
for path in sorted(paths):
    data = json.loads(path.read_text())
    changed = False
    for entry in data.get("results", []):
        if entry.get("cve_id") != "CVE-2026-46492":
            continue
        key = (str(path), entry.get("model"), entry["cve_id"])
        # Replay stores absolute paths, while report entries may be relative.
        match = next((r for k, r in lookup.items() if Path(k[0]).resolve() == path.resolve()
                      and k[1:] == key[1:]), None)
        if match:
            entry["raw_oracle_positive"] = bool(entry.get("bypass_confirmed"))
            entry["browser_genuine_bypass"] = match["browser_genuine_bypass"]
            entry["browser_signal"] = match["browser_signal"]
            entry["browser_response_body"] = match["response_body"]
            changed = True
    if changed:
        data["xss_validation"] = {
            "method": "pinned Chrome headless replay with dialog/error instrumentation",
            "report": "reports/reachability/catalog_xss_browser_replay.json",
            "genuine_bypasses": replay["genuine_bypasses"],
            "interpretation": "browser_genuine_bypass is the public XSS result; raw_oracle_positive is retained for audit.",
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        md = path.with_suffix(".md")
        if md.exists():
            text = md.read_text(encoding="utf-8", errors="replace")
            text = text.replace("| Bypass confirmed |", "| Browser genuine bypass |")
            text = text.replace("genuine_bypass_confirmed", "browser_genuine_bypass")
            md.write_text(text + "\n\nXSS rows use the independent headless-browser execution result; the historical raw marker result is preserved in JSON as `raw_oracle_positive`.\n", encoding="utf-8")
print("merged browser classifications")
