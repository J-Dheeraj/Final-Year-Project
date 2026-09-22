#!/usr/bin/env python3
"""
provtrail_bridge.py — feed ProvTrail scan findings into the CVE pipeline.

ProvTrail (ElsonNg/sc4079-fyp) statically finds code cloned from known-
vulnerable upstream functions and emits findings keyed by CVE/GHSA advisory ID
+ npm package + file:line. This bridge reads a ProvTrail scan artifact, and for
every advisory it flagged, runs THIS project's cve_pipeline (advisory fetch +
classification + optional live probe + patch validation), then writes a
combined report pairing ProvTrail's static locations with the pipeline verdicts.

Chain:  detect -> locate (ProvTrail)  ->  confirm -> patch (cve_pipeline)

Source with fallback:
  * Primary source is the ProvTrail artifact (--scan).
  * If that source does not work — file missing/unreadable, unparseable or
    unknown schema, or zero usable advisories after filtering — the bridge
    falls back to the existing NVD/GHSA feeds (reusing cve_watcher's fetchers),
    so the pipeline still gets fed. --source controls this.

Depth (auto by ecosystem):
  ProvTrail flags JS/npm advisories; this project's live labs are Python/Go.
  The live probe runs only when package_labs maps the finding's package to a
  real lab; otherwise the advisory runs static + patch analysis only. No
  dynamic confirmation is ever claimed without a real target.

Findings fed: automatic_vulnerability AND manual_review (patched-only matches
are never emitted by ProvTrail's exporter and are skipped here too).

Usage:
    python provtrail_bridge.py --scan latest-scan.json
    python provtrail_bridge.py --scan latest-scan.sarif --no-probe --format json
    python provtrail_bridge.py --scan missing.json        # auto-falls back to feeds
    python provtrail_bridge.py --source feeds --lookback 24
    python provtrail_bridge.py --source provtrail --scan latest-scan.json  # no fallback
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _fix_stdout() -> None:
    # Reconfigure in place rather than re-wrapping: a fresh TextIOWrapper would
    # orphan (and close) the original buffer, which then breaks cve_watcher's
    # own import-time stdout wrap in the feed-fallback path.
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("provtrail_bridge")

import package_labs

# The pipeline is imported lazily (see _load_pipeline): the artifact parsers and
# advisory routing do not need it, and importing cve_pipeline eagerly pulls in
# its heavy dependencies and import-time logging setup.
_pipeline = None


def _load_pipeline():
    """Import cve_pipeline on first use; cache it. Raises ImportError if missing."""
    global _pipeline
    if _pipeline is None:
        import cve_pipeline as pipeline  # same module cve_watcher drives
        _pipeline = pipeline
    return _pipeline

REPORTS_DIR = _HERE / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
CACHE_DIR = _HERE / ".pipeline_cache"
DEFAULT_LAB_URL = "http://127.0.0.1:8000"

ACTIVE_PRIORITIES = {"automatic_vulnerability", "manual_review"}
_SCHEMA_PREFIX = "provtrail_scan_v"


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Location:
    path: str
    start_line: int
    end_line: int

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "start_line": self.start_line, "end_line": self.end_line}


@dataclass
class Finding:
    """One ProvTrail finding (pre-dedup)."""
    advisory_id: str            # chosen id to feed the pipeline (CVE preferred)
    all_ids: list[str]
    packages: list[str]
    priority: str
    confidence: str | None
    location: Location | None


@dataclass
class Advisory:
    """A unique advisory to run through the pipeline, with merged provenance."""
    advisory_id: str
    all_ids: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    priority: str | None = None
    confidence: str | None = None
    locations: list[Location] = field(default_factory=list)
    source: str = "provtrail"


# ─────────────────────────────────────────────────────────────────────────────
# Advisory id selection + priority/confidence ordering
# ─────────────────────────────────────────────────────────────────────────────
def _pick_advisory_id(ids: list[str]) -> str | None:
    cves = [i for i in ids if i.upper().startswith("CVE-")]
    if cves:
        return sorted(cves)[0]
    ghsa = [i for i in ids if i.upper().startswith("GHSA-")]
    if ghsa:
        return sorted(ghsa)[0]
    return sorted(ids)[0] if ids else None


_PRIORITY_RANK = {"automatic_vulnerability": 2, "manual_review": 1}
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def _worst_priority(a: str | None, b: str | None) -> str | None:
    return max((p for p in (a, b) if p), key=lambda p: _PRIORITY_RANK.get(p, 0), default=None)


def _best_confidence(a: str | None, b: str | None) -> str | None:
    return max((c for c in (a, b) if c), key=lambda c: _CONFIDENCE_RANK.get(str(c).lower(), 0), default=None)


# ─────────────────────────────────────────────────────────────────────────────
# ProvTrail artifact parsers (json / sarif / ai-text)
# ─────────────────────────────────────────────────────────────────────────────
def load_scan(path: Path) -> tuple[list[Finding], str | None]:
    """Load a ProvTrail artifact. Returns (findings, reason_if_unusable)."""
    if not path.exists():
        return [], f"scan file not found: {path}"
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], f"could not read scan file: {exc}"

    suffix = path.suffix.lower()
    try:
        if suffix == ".sarif" or (suffix == ".json" and '"$schema"' in raw and "sarif" in raw):
            return _parse_sarif(json.loads(raw)), None
        if suffix == ".json":
            data = json.loads(raw)
            if str(data.get("schema", "")).startswith(_SCHEMA_PREFIX):
                return _parse_json_scan(data), None
            # A .json that is actually SARIF (no schema key we recognise)
            if "runs" in data:
                return _parse_sarif(data), None
            return [], f"unrecognised JSON schema: {data.get('schema')!r}"
        # .ai.txt / .txt
        return _parse_ai_text(raw), None
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return [], f"failed to parse {path.name}: {exc}"


def _parse_json_scan(data: dict[str, Any]) -> list[Finding]:
    """Parse the raw provtrail_scan_v* scan-state JSON.

    The primary-advisory selection lives in ProvTrail's own
    finding_exports.project_findings (it walks decision boundaries, not a flat
    field). Rather than re-implement that ranking — which would silently drift
    from another repo's internals — we delegate to ProvTrail when it is
    importable. When it is not, we ask for the SARIF / AI-text export, which are
    ProvTrail's stable downstream handoff formats and parse authoritatively here.
    """
    try:
        from provtrail.pipeline.controller.finding_exports import project_findings
    except Exception:  # noqa: BLE001 - any import failure means ProvTrail is unavailable
        raise ValueError(
            "raw ProvTrail scan JSON (provtrail_scan_v*) is ProvTrail's internal "
            "scan-state; authoritative parsing needs ProvTrail installed. Feed the "
            "SARIF (provtrail scan ... --sarif-output x.sarif) or AI-text "
            "(--ai-output x.ai.txt) export instead."
        )
    findings: list[Finding] = []
    for ef in project_findings(data):
        chosen = _pick_advisory_id(list(ef.advisory_ids))
        if not chosen:
            continue
        path = str(ef.path or "").replace("\\", "/").lstrip("/")
        findings.append(Finding(
            advisory_id=chosen, all_ids=sorted(ef.advisory_ids), packages=list(ef.packages),
            priority=ef.priority, confidence=ef.confidence,
            location=Location(path, ef.start_line, ef.end_line) if path else None,
        ))
    return findings


def _parse_sarif(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            prov = (res.get("properties") or {}).get("provtrail") or {}
            priority = prov.get("priority")
            if priority not in ACTIVE_PRIORITIES:
                continue
            ids = [str(i) for i in prov.get("advisoryIds") or []]
            chosen = _pick_advisory_id(ids)
            if not chosen:
                continue
            loc = None
            locations = res.get("locations") or []
            if locations:
                phys = locations[0].get("physicalLocation") or {}
                art = (phys.get("artifactLocation") or {}).get("uri") or ""
                region = phys.get("region") or {}
                if art:
                    loc = Location(
                        art, int(region.get("startLine") or 1),
                        int(region.get("endLine") or region.get("startLine") or 1),
                    )
            findings.append(Finding(
                advisory_id=chosen, all_ids=sorted(ids),
                packages=[str(p) for p in prov.get("packages") or []],
                priority=priority, confidence=prov.get("confidence"),
                location=loc,
            ))
    return findings


_AI_LINE = re.compile(
    r"^\s+(?P<file>\S+):(?P<start>\d+)-(?P<end>\d+)\s+(?P<status>VULN|REVIEW)\s+(?P<rest>.*)$"
)


def _parse_ai_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    directory = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not line.startswith(" ") and stripped.endswith("/"):
            directory = stripped.rstrip("/")
            continue
        m = _AI_LINE.match(line)
        if not m:
            continue
        rest = m.group("rest")
        ids = _kv(rest, "ids")
        chosen = _pick_advisory_id(ids)
        if not chosen:
            continue
        name = m.group("file")
        path = f"{directory}/{name}" if directory and directory != "." else name
        findings.append(Finding(
            advisory_id=chosen, all_ids=sorted(ids), packages=_kv(rest, "pkg"),
            priority="automatic_vulnerability" if m.group("status") == "VULN" else "manual_review",
            confidence=(_kv(rest, "confidence") or [None])[0],
            location=Location(path.replace("\\", "/").lstrip("/"),
                              int(m.group("start")), int(m.group("end"))),
        ))
    return findings


def _kv(rest: str, key: str) -> list[str]:
    """Pull a `key=a,b,c` token out of an AI-text line (stops at next ` key=`)."""
    m = re.search(rf"(?:^|\s){re.escape(key)}=(\S+)", rest)
    return m.group(1).split(",") if m else []


# ─────────────────────────────────────────────────────────────────────────────
# Dedupe: many findings share one advisory
# ─────────────────────────────────────────────────────────────────────────────
def dedupe(findings: list[Finding]) -> list[Advisory]:
    groups: dict[str, Advisory] = {}
    for f in findings:
        adv = groups.get(f.advisory_id)
        if adv is None:
            adv = Advisory(advisory_id=f.advisory_id)
            groups[f.advisory_id] = adv
        adv.all_ids = sorted(set(adv.all_ids) | set(f.all_ids))
        adv.packages = sorted(set(adv.packages) | set(f.packages))
        adv.priority = _worst_priority(adv.priority, f.priority)
        adv.confidence = _best_confidence(adv.confidence, f.confidence)
        if f.location:
            adv.locations.append(f.location)
    return sorted(groups.values(), key=lambda a: a.advisory_id)


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline invocation (mirrors cve_watcher.run_pipeline, but returns the report)
# ─────────────────────────────────────────────────────────────────────────────
def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def run_pipeline_for(advisory_id: str, *, probe: bool, lab_url: str | None,
                     fmt: str, no_cache: bool):
    """Run cve_pipeline for one advisory. Returns (report_or_None, artifact_path_or_None)."""
    ext = "json" if fmt == "json" else "txt"
    out_path = REPORTS_DIR / f"{_safe(advisory_id)}.{ext}"
    args = argparse.Namespace(
        cve_id=advisory_id,
        lab_url=lab_url or DEFAULT_LAB_URL,
        no_probe=not probe,
        no_cache=no_cache,
        cache_dir=str(CACHE_DIR),
        cache_ttl=86_400,
        format=fmt,
        out=str(out_path),
        verbose=False,
    )
    try:
        pipeline = _load_pipeline()
        report = asyncio.run(pipeline.run_pipeline(args))
    except Exception as exc:  # noqa: BLE001 - one bad advisory must not kill the batch
        log.warning(f"  [{advisory_id}] pipeline error: {exc}")
        return None, None
    output = pipeline.render_json(report) if fmt == "json" else pipeline.render_text(report)
    out_path.write_text(output, encoding="utf-8")
    return report, out_path


def summarise_verdict(report, *, probed: bool, lab_url: str | None) -> dict[str, Any]:
    """Flatten a PipelineReport into the combined-report row fields."""
    if report is None:
        return {"overall_risk": "ERROR", "probe_verdict": "pipeline error", "errors": ["pipeline raised"]}
    probe = getattr(report, "ssrf_probe", None)
    art = getattr(report, "exploit_artifacts", None)
    if not probed:
        verdict = "static+patch only (no matching lab)"
    elif probe is not None and getattr(probe, "ran", False):
        v = getattr(probe, "vulnerable_verdict", None) or (
            "confirmed" if getattr(probe, "ssrf_confirmed", False) else "inconclusive")
        verdict = f"probe:{v}"
    elif probe is not None and getattr(probe, "skip_reason", None):
        verdict = f"probe skipped: {probe.skip_reason}"
    else:
        verdict = "probe did not run"
    return {
        "overall_risk": getattr(report, "overall_risk", "UNKNOWN"),
        "probe_ran": bool(probe and getattr(probe, "ran", False)),
        "probe_verdict": verdict,
        "dynamically_confirmed": getattr(art, "dynamically_confirmed", None) if art else None,
        "patch_attempted": getattr(art, "patch_attempted", None) if art else None,
        "patch_validated": getattr(art, "patch_validated", None) if art else None,
        "stages_failed": list(getattr(report, "stages_failed", []) or []),
        "errors": list(getattr(report, "errors", []) or []),
        "elapsed_s": getattr(report, "elapsed_s", 0.0),
        "lab_url": lab_url if probed else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Feed fallback (reuses cve_watcher's fetchers — no pipeline logic duplicated)
# ─────────────────────────────────────────────────────────────────────────────
def feed_advisories(lookback_hours: int, limit: int) -> list[Advisory]:
    """Pull recent advisory IDs from NVD + GHSA via cve_watcher's fetchers."""
    import cve_watcher  # lazy: avoid its import-time side effects unless we fall back
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    ids: list[str] = []
    seen: set[str] = set()
    for fetch in (cve_watcher.fetch_nvd, cve_watcher.fetch_ghsa):
        try:
            for cve_id in fetch(since):
                if cve_id not in seen:
                    seen.add(cve_id)
                    ids.append(cve_id)
                    if len(ids) >= limit:
                        break
        except Exception as exc:  # noqa: BLE001 - a dead feed must not abort the run
            log.warning(f"feed {fetch.__name__} error: {exc}")
        if len(ids) >= limit:
            break
    return [Advisory(advisory_id=i, all_ids=[i], source="feeds") for i in ids[:limit]]


# ─────────────────────────────────────────────────────────────────────────────
# Combined report
# ─────────────────────────────────────────────────────────────────────────────
def write_combined_report(rows: list[dict[str, Any]], *, source: str,
                          scan_path: str | None) -> tuple[Path, Path]:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = REPORTS_DIR / f"provtrail_link_{stamp}"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "scan_path": scan_path,
        "advisory_count": len(rows),
        "results": rows,
    }
    json_path = base.with_suffix(".json")
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# ProvTrail -> CVE pipeline linkage report",
        "",
        f"- Generated: {payload['generated_at']}",
        f"- Advisory source: **{source}**" + (f" (`{scan_path}`)" if scan_path else ""),
        f"- Advisories run: **{len(rows)}**",
        "",
        "| Advisory | Source | ProvTrail | Location(s) | Pipeline risk | Probe verdict | Patch validated |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        p = r.get("pipeline", {})
        prov = (f"{r.get('priority') or '-'} / {r.get('confidence') or '-'}"
                if r["source"] == "provtrail" else "-")
        locs = "; ".join(f"{l['path']}:{l['start_line']}-{l['end_line']}"
                         for l in r.get("locations", [])) or "-"
        patch = p.get("patch_validated")
        patch_str = "-" if patch is None else ("yes" if patch else "no")
        lines.append(
            f"| {r['advisory_id']} | {r['source']} | {prov} | {locs} | "
            f"{p.get('overall_risk','-')} | {p.get('probe_verdict','-')} | {patch_str} |"
        )
    lines += ["", "> Advisories without a matching lab in `package_labs.py` are analysed",
              "> statically (advisory fetch + classification + patch diff) only — no",
              "> dynamic confirmation is claimed for them.", ""]
    md_path = base.with_suffix(".md")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path, json_path


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────────────
def _resolve_advisories(args) -> tuple[list[Advisory], str, str | None]:
    """Return (advisories, source_used, scan_path_str). Honours --source + fallback."""
    scan_str = str(args.scan) if args.scan else None
    want_provtrail = args.source in ("provtrail", "auto")
    if want_provtrail and args.scan:
        findings, reason = load_scan(Path(args.scan))
        if reason:
            log.warning(f"ProvTrail source unusable: {reason}")
        advisories = dedupe(findings)
        if advisories:
            log.info(f"ProvTrail: {len(findings)} finding(s) -> {len(advisories)} unique advisory(ies)")
            return advisories, "provtrail", scan_str
        if args.source == "provtrail":
            log.error("ProvTrail source yielded no advisories and --source provtrail forbids fallback.")
            return [], "provtrail", scan_str
        log.info("ProvTrail yielded no advisories — falling back to NVD/GHSA feeds.")
    elif args.source == "provtrail":
        log.error("--source provtrail requires --scan.")
        return [], "provtrail", scan_str

    advisories = feed_advisories(args.lookback, args.limit)
    log.info(f"Feeds: {len(advisories)} advisory(ies) from NVD/GHSA (lookback {args.lookback}h)")
    return advisories, "feeds", scan_str


def run(args) -> int:
    advisories, source, scan_str = _resolve_advisories(args)
    if not advisories:
        log.error("No advisories to run.")
        return 1

    rows: list[dict[str, Any]] = []
    for i, adv in enumerate(advisories, 1):
        lab_url = None if args.no_probe else package_labs.lab_for_packages(adv.packages)
        probe = bool(lab_url) and not args.no_probe
        log.info(f"[{i}/{len(advisories)}] {adv.advisory_id} "
                 f"({'probe @ ' + lab_url if probe else 'static+patch only'})")
        t0 = time.monotonic()
        report, artifact = run_pipeline_for(
            adv.advisory_id, probe=probe, lab_url=lab_url,
            fmt=args.format, no_cache=args.no_cache,
        )
        verdict = summarise_verdict(report, probed=probe, lab_url=lab_url)
        log.info(f"    -> risk={verdict.get('overall_risk')} "
                 f"{verdict.get('probe_verdict')} ({round(time.monotonic()-t0,1)}s)")
        rows.append({
            "advisory_id": adv.advisory_id,
            "all_ids": adv.all_ids,
            "packages": adv.packages,
            "source": adv.source if source == "provtrail" else "feeds",
            "priority": adv.priority,
            "confidence": adv.confidence,
            "locations": [l.as_dict() for l in adv.locations],
            "probed": probe,
            "artifact": str(artifact) if artifact else None,
            "pipeline": verdict,
        })

    md_path, json_path = write_combined_report(rows, source=source, scan_path=scan_str)
    log.info(f"\nCombined report: {md_path}")
    log.info(f"Combined report (JSON): {json_path}")
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="provtrail_bridge",
        description="Feed ProvTrail scan findings into the CVE pipeline (with NVD/GHSA fallback).",
    )
    p.add_argument("--scan", metavar="PATH",
                   help="ProvTrail artifact (.json / .sarif / .ai.txt). Primary advisory source.")
    p.add_argument("--source", choices=["auto", "provtrail", "feeds"], default="auto",
                   help="auto = ProvTrail then feed fallback (default); provtrail = no fallback; feeds = skip ProvTrail.")
    p.add_argument("--no-probe", action="store_true",
                   help="Never run the live probe; static + patch analysis only for every advisory.")
    p.add_argument("--no-cache", action="store_true", help="Bypass the pipeline stage cache.")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="Per-advisory artifact format written under reports/.")
    p.add_argument("--lookback", type=int, default=24, metavar="HOURS",
                   help="Feed fallback: how far back to pull advisories (default 24h).")
    p.add_argument("--limit", type=int, default=25, metavar="N",
                   help="Feed fallback: max advisories to pull (default 25).")
    return p.parse_args(argv)


def main() -> None:
    _fix_stdout()
    args = _parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
