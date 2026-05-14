"""
cve_watcher.py — Watches NVD and GitHub Advisory feeds for new CVEs
and automatically runs the analysis pipeline for each one.

Feeds polled:
    NVD  (services.nvd.nist.gov)   — broadest coverage
    GHSA (api.github.com/advisories) — open-source library CVEs

Integration:
    Imports cve_pipeline directly (no subprocess) for speed.
    Runs up to --workers CVEs concurrently via a thread pool.

Usage:
    python cve_watcher.py                        # poll every 60 min
    python cve_watcher.py --interval 30          # poll every 30 min
    python cve_watcher.py --format json          # save reports as JSON
    python cve_watcher.py --once                 # single pass then exit
    python cve_watcher.py --no-probe             # skip live SSRF probe
    python cve_watcher.py --lookback 6           # on first run, fetch last 6h
    python cve_watcher.py --workers 4            # process 4 CVEs in parallel

Outputs:
    reports/<CVE-ID>.txt     — one report per CVE
    seen_cves.json           — deduplication store
    watcher.log              — full run log
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import requests

# ── load .env if present (before anything reads os.environ) ──────────────────

def _load_dotenv(path: Path) -> None:
    """Minimal .env loader — no external dependency needed."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and val and key not in os.environ:   # don't overwrite shell env
            os.environ[key] = val

_load_dotenv(Path(__file__).parent / ".env")

# ── import pipeline directly (no subprocess) ──────────────────────────────────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

try:
    import cve_pipeline as _pipeline
    _PIPELINE_AVAILABLE = True
except ImportError as _e:
    _PIPELINE_AVAILABLE = False
    _PIPELINE_IMPORT_ERR = str(_e)

# ── UTF-8 stdout on Windows ───────────────────────────────────────────────────
if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
SEEN_FILE   = BASE_DIR / "seen_cves.json"
LOG_FILE    = BASE_DIR / "watcher.log"

REPORTS_DIR.mkdir(exist_ok=True)

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("cve_watcher")

# ── seen-CVE store ────────────────────────────────────────────────────────────

class SeenStore:
    """Persists a set of CVE IDs that have already been processed."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._ids: set[str] = self._load()

    def _load(self) -> set[str]:
        if self._path.exists():
            try:
                return set(json.loads(self._path.read_text(encoding="utf-8")))
            except Exception:
                pass
        return set()

    def _save(self) -> None:
        self._path.write_text(
            json.dumps(sorted(self._ids), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def __contains__(self, cve_id: str) -> bool:
        return cve_id in self._ids

    def add(self, cve_id: str) -> None:
        self._ids.add(cve_id)
        self._save()

    def __len__(self) -> int:
        return len(self._ids)


# ── NVD fetcher ───────────────────────────────────────────────────────────────

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_time(dt: datetime) -> str:
    """Format datetime for NVD API (ISO 8601 without microseconds)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_nvd(since: datetime) -> Iterator[str]:
    """
    Yield CVE IDs published on NVD since *since*.
    Handles pagination automatically.
    NVD free tier: 5 requests / 30 s — we add a 0.7 s sleep between pages.
    """
    now   = datetime.now(timezone.utc)
    start = _nvd_time(since)
    end   = _nvd_time(now)

    params: dict = {
        "pubStartDate": start,
        "pubEndDate":   end,
        "resultsPerPage": 2000,
        "startIndex":     0,
    }

    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}

    fetched = 0
    while True:
        try:
            resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            log.warning(f"NVD fetch error: {exc}")
            break

        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        for item in vulns:
            cve_id = item.get("cve", {}).get("id", "")
            if cve_id:
                yield cve_id

        fetched += len(vulns)
        if fetched >= total:
            break

        params["startIndex"] = fetched
        time.sleep(0.7)   # stay within NVD rate limit


# ── GitHub Advisory fetcher ───────────────────────────────────────────────────

GHSA_BASE = "https://api.github.com/advisories"


def fetch_ghsa(since: datetime) -> Iterator[str]:
    """
    Yield CVE IDs from GitHub Security Advisories published since *since*.
    Only advisories that carry a CVE ID are yielded.
    """
    headers: dict = {"Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"}
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    page = 1
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    while True:
        try:
            resp = requests.get(
                GHSA_BASE,
                params={
                    "per_page": 100,
                    "page":     page,
                    "type":     "reviewed",
                    "direction": "desc",
                    "sort":     "published",
                },
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            advisories = resp.json()
        except Exception as exc:
            log.warning(f"GHSA fetch error: {exc}")
            break

        if not advisories:
            break

        any_in_window = False
        for adv in advisories:
            pub = adv.get("published_at", "")
            cve = adv.get("cve_id") or ""
            if pub and pub >= since_str:
                any_in_window = True
                if cve.startswith("CVE-"):
                    yield cve
            # advisories are newest-first; once we pass our window, stop
            elif pub and pub < since_str:
                return

        if not any_in_window:
            break

        page += 1
        time.sleep(0.3)


# ── pipeline runner ───────────────────────────────────────────────────────────

def run_pipeline(cve_id: str, fmt: str, no_probe: bool,
                 lab_url: str = "http://127.0.0.1:8000") -> bool:
    """
    Run the analysis pipeline for *cve_id* in-process (no subprocess).
    Saves report to reports/<cve_id>.<ext>. Returns True on success.

    Uses cve_pipeline directly — same pipeline, no process overhead,
    supports both NVD and GHSA CVEs, fetches real code diffs from GitHub.
    """
    if not _PIPELINE_AVAILABLE:
        log.error(f"  cve_pipeline import failed: {_PIPELINE_IMPORT_ERR}")
        return False

    ext      = "json" if fmt == "json" else "txt"
    out_path = REPORTS_DIR / f"{cve_id}.{ext}"

    log.info(f"  [{cve_id}] Starting pipeline ...")
    t0 = time.monotonic()

    try:
        # Build an args namespace matching cve_pipeline's _parse_args() output
        args = argparse.Namespace(
            cve_id    = cve_id,
            lab_url   = lab_url,
            no_probe  = no_probe,
            no_cache  = False,
            cache_dir = str(_HERE / ".pipeline_cache"),
            cache_ttl = 86_400,
            format    = fmt,
            out       = str(out_path),
            verbose   = False,
        )

        # run_pipeline is async — run it in the current thread's event loop
        report = asyncio.run(_pipeline.run_pipeline(args))

        output = (
            _pipeline.render_json(report)
            if fmt == "json"
            else _pipeline.render_text(report)
        )
        out_path.write_text(output, encoding="utf-8")

        elapsed = round(time.monotonic() - t0, 1)
        has_errors = bool(report.errors) or bool(report.stages_failed)

        if has_errors:
            log.warning(
                f"  [{cve_id}] finished with errors in {elapsed}s "
                f"→ {out_path.name}  errors={report.errors[:1]}"
            )
        else:
            log.info(f"  [{cve_id}] ✓ done in {elapsed}s  risk={report.overall_risk}"
                     f"  → {out_path.name}")
        return not has_errors

    except Exception as exc:
        elapsed = round(time.monotonic() - t0, 1)
        log.warning(f"  [{cve_id}] ✗ pipeline error after {elapsed}s: {exc}")
        return False


# ── single poll pass ──────────────────────────────────────────────────────────

def poll_once(since: datetime, seen: SeenStore,
              fmt: str, no_probe: bool,
              workers: int = 1,
              lab_url: str = "http://127.0.0.1:8000") -> tuple[int, int]:
    """
    Fetch both feeds (NVD + GHSA), deduplicate, then run the pipeline
    for every new CVE. Up to *workers* CVEs are processed concurrently.
    Returns (new_found, succeeded).
    """
    new_ids: set[str] = set()

    log.info(f"Polling NVD since {since.isoformat()} ...")
    for cve_id in fetch_nvd(since):
        if cve_id not in seen:
            new_ids.add(cve_id)

    log.info(f"Polling GHSA since {since.isoformat()} ...")
    for cve_id in fetch_ghsa(since):
        if cve_id not in seen:
            new_ids.add(cve_id)

    if not new_ids:
        log.info("No new CVEs found.")
        return 0, 0

    sorted_ids = sorted(new_ids)
    log.info(f"Found {len(sorted_ids)} new CVE(s): {', '.join(sorted_ids)}")

    succeeded = 0

    if workers <= 1:
        # Sequential — simple, no thread overhead
        for cve_id in sorted_ids:
            ok = run_pipeline(cve_id, fmt, no_probe, lab_url)
            seen.add(cve_id)
            if ok:
                succeeded += 1
    else:
        # Parallel — process up to *workers* CVEs at the same time
        log.info(f"Running {len(sorted_ids)} CVEs with {workers} workers ...")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(run_pipeline, cve_id, fmt, no_probe, lab_url): cve_id
                for cve_id in sorted_ids
            }
            for future in as_completed(futures):
                cve_id = futures[future]
                try:
                    ok = future.result()
                except Exception as exc:
                    log.warning(f"  [{cve_id}] unexpected error: {exc}")
                    ok = False
                seen.add(cve_id)
                if ok:
                    succeeded += 1

    return len(new_ids), succeeded


# ── main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="CVE feed watcher → auto pipeline")
    parser.add_argument("--interval",  default=60,  type=int,
                        help="Poll interval in minutes (default: 60)")
    parser.add_argument("--lookback",  default=2,   type=int,
                        help="Hours to look back on first run (default: 2)")
    parser.add_argument("--format",    choices=["text", "json"], default="text",
                        help="Report format (default: text)")
    parser.add_argument("--no-probe",  action="store_true",
                        help="Skip live SSRF probe (no server needed)")
    parser.add_argument("--workers",   default=1,   type=int,
                        help="Parallel pipeline workers (default: 1)")
    parser.add_argument("--lab-url",   default="http://127.0.0.1:8000",
                        help="SSRF lab server URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--once",      action="store_true",
                        help="Run one poll pass then exit")
    args = parser.parse_args()

    if not _PIPELINE_AVAILABLE:
        sys.exit(f"[!] cve_pipeline could not be imported: {_PIPELINE_IMPORT_ERR}")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        log.info("AI backend : Anthropic SDK (pydantic-ai agent mode)")
    else:
        log.info("AI backend : claude CLI / text-only (no ANTHROPIC_API_KEY needed)")

    seen = SeenStore(SEEN_FILE)
    log.info(
        f"CVE Watcher started  |  interval={args.interval}m  "
        f"lookback={args.lookback}h  format={args.format}  "
        f"no_probe={args.no_probe}  workers={args.workers}  "
        f"seen={len(seen)} CVEs"
    )
    log.info(f"Pipeline : cve_pipeline (direct import — NVD + GHSA supported)")
    log.info(f"Reports  → {REPORTS_DIR.resolve()}")
    log.info(f"Log      → {LOG_FILE.resolve()}")

    # On the very first poll, look back N hours so we don't miss recent CVEs
    since = datetime.now(timezone.utc) - timedelta(hours=args.lookback)

    while True:
        poll_start = datetime.now(timezone.utc)
        log.info(f"{'='*60}")
        log.info(f"Poll started at {poll_start.isoformat()}")

        try:
            found, ok = poll_once(
                since, seen,
                fmt=args.format,
                no_probe=args.no_probe,
                workers=args.workers,
                lab_url=args.lab_url,
            )
            log.info(f"Poll complete — {found} new CVE(s), {ok} pipeline(s) succeeded")
        except Exception as exc:
            log.error(f"Unexpected error during poll: {exc}", exc_info=True)

        if args.once:
            log.info("--once flag set, exiting.")
            break

        # Next poll: start from when this poll began (no gaps, no overlaps)
        since = poll_start
        next_run = datetime.now(timezone.utc) + timedelta(minutes=args.interval)
        log.info(f"Next poll at {next_run.strftime('%H:%M:%S UTC')} "
                 f"(sleeping {args.interval}m)")
        time.sleep(args.interval * 60)


if __name__ == "__main__":
    main()
