"""
Dry-run: call each pipeline stage function directly (no LLM or API key needed)
to verify the full data flow end-to-end.
"""
import io, json, pathlib, sys, tempfile
# stdout is left as-is at import time; cve_pipeline only fixes it inside main()
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import cve_pipeline as p

# ── Build deps ────────────────────────────────────────────────────────────────
cache = p.FileCache(pathlib.Path(tempfile.mkdtemp()), ttl_seconds=3600)
deps  = p.PipelineDeps(
    cve_id="CVE-2026-33626", pipeline_id="dryrun-01",
    cache=cache, lab_url="http://127.0.0.1:8000",
    skip_probe=False, no_cache=False,
)

# Minimal RunContext shim — our tools only ever access ctx.deps
class _Ctx:
    def __init__(self, d): self.deps = d

ctx = _Ctx(deps)

# ── Stage 1 ───────────────────────────────────────────────────────────────────
print("=== Stage 1: fetch_advisory ===")
advisory = p.fetch_advisory(ctx, "GHSA-6w67-hwm5-92mq")
print(f"  pkg      = {advisory.get('package_name')} ({advisory.get('ecosystem')})")
print(f"  severity = {advisory.get('severity')}  cvss={advisory.get('cvss_score')}")
print(f"  affected = {advisory.get('affected_versions')}")
print(f"  files    = {[f['file'] for f in advisory.get('file_locations', [])][:3]}")

# ── Stage 2 ───────────────────────────────────────────────────────────────────
print("\n=== Stage 2: analyze_vulnerability ===")
analysis = p.analyze_vulnerability(ctx, json.dumps(advisory))
print(f"  class       = {analysis.get('vulnerability_class')}")
print(f"  cwe         = {analysis.get('cwe')}  confidence={analysis.get('confidence')}")
print(f"  patterns    = {len(analysis.get('unsafe_patterns', []))} unsafe call(s)")
print(f"  fix summary = {str(analysis.get('fix_summary',''))[:90]}")

# ── Stage 3 ───────────────────────────────────────────────────────────────────
print("\n=== Stage 3: run_ssrf_probe ===")
probe = p.run_ssrf_probe(ctx)
if probe.get("ran"):
    print(f"  vulnerable = {probe.get('vulnerable_verdict')}")
    print(f"  patched    = {probe.get('patched_verdict')}")
    print(f"  confirmed  = {probe.get('ssrf_confirmed')}   elapsed={probe.get('elapsed_s')}s")
else:
    print(f"  skipped: {probe.get('skip_reason')}")

# ── Stage 4 ───────────────────────────────────────────────────────────────────
print("\n=== Stage 4: compile_report ===")
report_dict = p.compile_report(
    ctx,
    advisory_json   = json.dumps(advisory),
    analysis_json   = json.dumps(analysis),
    ssrf_probe_json = json.dumps(probe),
)
report = p.PipelineReport(**report_dict)
print(f"  risk    = {report.overall_risk}")
print(f"  summary = {report.summary[:110]}...")
print(f"  recs ({len(report.recommendations)}):")
for i, rec in enumerate(report.recommendations, 1):
    print(f"    {i}. {rec[:90]}")

# ── Final text render ─────────────────────────────────────────────────────────
print()
print(p.render_text(report))

# ── Verify cache was written ──────────────────────────────────────────────────
print("\n=== Cache files written ===")
for f in sorted(pathlib.Path(cache.root).rglob("*.json")):
    print(f"  {f.relative_to(cache.root)}  ({f.stat().st_size} bytes)")
