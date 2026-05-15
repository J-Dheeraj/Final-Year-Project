#!/usr/bin/env python3
"""
ghsa_extractor.py — Defensive security tooling pipeline.

Extracts structured vulnerability fields from:
  - GitHub Advisory pages (https://github.com/advisories/GHSA-*)
  - NVD JSON exports (https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-*)
  - Local NVD JSON files

Usage:
    python ghsa_extractor.py <GHSA-URL | NVD-URL | local.json>
    python ghsa_extractor.py --ghsa GHSA-6w67-hwm5-92mq
    python ghsa_extractor.py --cve  CVE-2026-33626
    python ghsa_extractor.py nvd_export.json
"""

import argparse
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Force UTF-8 stdout on Windows — only when run directly, not when imported
def _fix_stdout_encoding() -> None:
    if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Optional dependencies — install with: pip install requests beautifulsoup4
# ---------------------------------------------------------------------------
try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit(
        "Missing dependencies. Run:\n  pip install requests beautifulsoup4"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GITHUB_ADVISORY_BASE = "https://github.com/advisories"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_GRAPHQL = "https://api.github.com/graphql"
GITHUB_REST_BASE = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"

HEADERS = {
    "User-Agent": "ghsa-extractor/1.0 (defensive-security-tooling)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Regex patterns
_RE_GHSA   = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
_RE_CVE    = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_RE_SEMVER = re.compile(r"[<>=!^~]+\s*[\d.*]+")
_RE_FILE   = re.compile(
    r"(?<![/\d])"             # not preceded by digit or slash (avoids IPs)
    r"([\w][\w/\\.-]+)"       # path: starts with word char, contains / or .
    r"\.(py|js|ts|java|go|rb|php|c|cpp|h|rs|cs|kt|swift|yaml|yml|json|toml)"
    r"(?::(\d+)(?:-(\d+))?)?" # optional :line or :line-line
    r"(?!\.\d)",               # not followed by .digit (avoids version strings)
    re.I,
)
_RE_LINES  = re.compile(r"[Ll]ines?\s+(\d+)(?:\s*[-–]\s*(\d+))?")
_RE_CVSS   = re.compile(r"(\d+\.\d+)\s*/\s*10|CVSS[:\s]+(\d+\.\d+)", re.I)

# Private IP CIDR descriptions used in fix recommendation detection
_PRIVATE_CIDR = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                 "192.168.0.0/16", "169.254.0.0/16"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, timeout: int = 15) -> requests.Response:
    resp = requests.get(url, headers=HEADERS, timeout=timeout)
    resp.raise_for_status()
    return resp


def _clean(text: str) -> str:
    return " ".join(text.split())


def _extract_identifiers(text: str) -> dict[str, list[str]]:
    return {
        "ghsa": _RE_GHSA.findall(text),
        "cve":  _RE_CVE.findall(text),
    }


def _extract_file_locations(text: str) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in _RE_FILE.finditer(text):
        path = match.group(1) + "." + match.group(2)
        # Skip obvious non-paths: pure version strings, IP-like, single-word stems
        if re.fullmatch(r"\d[\d.]*", path):
            continue
        if path.startswith(("http", "www.", "mozilla")):
            continue
        # Require at least one directory separator OR a recognisable stem (≥4 chars before ext)
        stem = path.rsplit(".", 1)[0]
        if "/" not in stem and "\\" not in stem and len(stem) < 4:
            continue
        # For short extensions easily confused with URL/attribute fragments (c, h, go, ts, rb)
        # require a directory separator so we don't match "parsed.hostname" → parsed.h
        if re.search(r"\.(c|h|go|ts|rb)$", path, re.I) and "/" not in stem and "\\" not in stem:
            continue
        loc: dict[str, Any] = {"file": path}
        # inline :line suffix
        if match.group(3):
            loc["line_start"] = int(match.group(3))
        if match.group(4):
            loc["line_end"] = int(match.group(4))
        # look for "lines N-M" in the 80 chars after the file mention
        if "line_start" not in loc:
            after = text[match.end():match.end() + 80]
            lm = _RE_LINES.search(after)
            if lm:
                loc["line_start"] = int(lm.group(1))
                if lm.group(2):
                    loc["line_end"] = int(lm.group(2))
        key = json.dumps(loc, sort_keys=True)
        if key not in seen:
            seen.add(key)
            locations.append(loc)
    return locations


def _extract_versions(text: str) -> dict[str, list[str]]:
    affected = []
    patched  = []
    for token in _RE_SEMVER.findall(text):
        token = token.strip()
        if token.startswith((">=", "^", "~")) or "patched" in text[: text.find(token)].lower()[-40:]:
            patched.append(token)
        else:
            affected.append(token)
    return {"affected": list(dict.fromkeys(affected)),
            "patched":  list(dict.fromkeys(patched))}


def _extract_cvss(text: str) -> float | None:
    m = _RE_CVSS.search(text)
    if m:
        raw = m.group(1) or m.group(2)
        return float(raw)
    return None


def _build_output(
    ghsa_id: str | None,
    cve_id:  str | None,
    package: str | None,
    ecosystem: str | None,
    severity: str | None,
    cvss_score: float | None,
    affected_versions: list[str],
    patched_versions: list[str],
    file_locations: list[dict],
    root_cause: str | None,
    fix_code: str | None,
    references: list[str],
    raw_description: str | None,
) -> dict[str, Any]:
    return {
        "advisory": {
            "ghsa_id":   ghsa_id,
            "cve_id":    cve_id,
            "severity":  severity,
            "cvss_score": cvss_score,
        },
        "package": {
            "name":      package,
            "ecosystem": ecosystem,
        },
        "versions": {
            "affected": affected_versions,
            "patched":  patched_versions,
        },
        "vulnerability": {
            "file_locations": file_locations,
            "root_cause":     root_cause,
        },
        "remediation": {
            "fix_code":   fix_code,
            "references": references,
        },
        "raw_description": raw_description,
    }


# ---------------------------------------------------------------------------
# GitHub Repository Security Advisories REST API
# Docs: https://docs.github.com/en/rest/security-advisories/repository-advisories
#
# Three entry points:
#   fetch_global_advisory(ghsa_id, token)          — no repo needed
#   fetch_repo_advisory(owner, repo, ghsa_id, token) — repo-level (draft access)
#   list_repo_advisories(owner, repo, token, ...)  — list all for a repo
# ---------------------------------------------------------------------------

def _rest_headers(token: str | None = None) -> dict:
    """Build standard headers for GitHub REST API calls."""
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "ghsa-extractor/1.0 (defensive-security-tooling)",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _parse_api_advisory(data: dict[str, Any]) -> dict[str, Any]:
    """
    Map a GitHub REST advisory JSON object (from either the global or repo
    endpoint) to our standard _build_output() schema.

    API fields used:
      ghsa_id, cve_id, summary, description, severity,
      cvss_severities.cvss_v3.score, cwes[].cwe_id,
      vulnerabilities[].package.{ecosystem,name},
      vulnerabilities[].vulnerable_version_range,
      vulnerabilities[].first_patched_version,
      references[]
    """
    ghsa_id = data.get("ghsa_id")
    cve_id  = data.get("cve_id")

    # Severity + CVSS — prefer cvss_v4, fall back to cvss_v3, then string severity
    cvss_v3 = (data.get("cvss_severities") or {}).get("cvss_v3") or {}
    cvss_v4 = (data.get("cvss_severities") or {}).get("cvss_v4") or {}
    # Legacy field for older API versions
    legacy_cvss = data.get("cvss") or {}

    cvss_score: float | None = (
        cvss_v4.get("score")
        or cvss_v3.get("score")
        or legacy_cvss.get("score")
    )
    severity: str | None = data.get("severity")
    if severity:
        severity = severity.capitalize()

    # Package — take the first vulnerability entry
    vulns     = data.get("vulnerabilities") or []
    package   = None
    ecosystem = None
    affected_versions: list[str] = []
    patched_versions:  list[str] = []

    for v in vulns:
        pkg = v.get("package") or {}
        package   = package   or pkg.get("name")
        ecosystem = ecosystem or pkg.get("ecosystem")
        vrange = v.get("vulnerable_version_range")
        if vrange:
            affected_versions.append(vrange.strip())
        patched = v.get("first_patched_version")
        if patched:
            patched_versions.append(f">= {patched}")

    # CWEs
    cwes = data.get("cwes") or []
    cwe_ids = [c.get("cwe_id", "") for c in cwes if c.get("cwe_id")]

    # Description (the advisory body, often richer than summary)
    description = data.get("description") or data.get("summary") or ""
    summary     = data.get("summary") or ""

    # Root cause — first 3 sentences of description that mention a vuln keyword
    cause_pattern = re.compile(
        r"ssrf|injection|overflow|traversal|deseri|xss|csrf|bypass|"
        r"without.valid|no.valid|arbitrary|path.travers", re.I
    )
    sentences  = re.split(r"(?<=[.!?])\s+", description)
    cause_parts = [s for s in sentences if cause_pattern.search(s)]
    root_cause  = " ".join(cause_parts[:3]) or summary or None

    # File locations — extracted from description text
    file_locations = _extract_file_locations(description)

    # References
    references = [r for r in (data.get("references") or []) if isinstance(r, str)]
    if not references:
        # Some API versions return reference objects
        for ref in (data.get("references") or []):
            if isinstance(ref, dict) and ref.get("url"):
                references.append(ref["url"])

    out = _build_output(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        package=package,
        ecosystem=ecosystem,
        severity=severity,
        cvss_score=float(cvss_score) if cvss_score is not None else None,
        affected_versions=list(dict.fromkeys(affected_versions)),
        patched_versions=list(dict.fromkeys(patched_versions)),
        file_locations=file_locations,
        root_cause=root_cause,
        fix_code=None,
        references=references[:20],
        raw_description=description[:1500],
    )

    # Attach extras not in the standard schema
    out["_api"] = {
        "source": "github_rest_api",
        "cwe_ids": cwe_ids,
        "cvss_v3": cvss_v3,
        "cvss_v4": cvss_v4,
        "state": data.get("state"),
        "published_at": data.get("published_at"),
    }
    return out


def fetch_global_advisory(ghsa_id: str,
                          token: str | None = None) -> dict[str, Any]:
    """
    Fetch a single public advisory from the GLOBAL advisory endpoint.
    No repo ownership needed — works for any published GHSA.

    GET /advisories/{ghsa_id}
    Scope: public (unauthenticated or token for higher rate limit)
    """
    url = f"{GITHUB_REST_BASE}/advisories/{ghsa_id}"
    print(f"[*] GitHub REST API (global): {url}", file=sys.stderr)
    resp = requests.get(url, headers=_rest_headers(token), timeout=15)
    resp.raise_for_status()
    return _parse_api_advisory(resp.json())


def fetch_repo_advisory(owner: str, repo: str, ghsa_id: str,
                        token: str | None = None) -> dict[str, Any]:
    """
    Fetch a single advisory from a specific repository.
    Requires token with repo scope for private/draft advisories.

    GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}
    """
    url = f"{GITHUB_REST_BASE}/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    print(f"[*] GitHub REST API (repo): {url}", file=sys.stderr)
    resp = requests.get(url, headers=_rest_headers(token), timeout=15)
    resp.raise_for_status()
    return _parse_api_advisory(resp.json())


def list_repo_advisories(
    owner: str,
    repo: str,
    token: str | None = None,
    state: str = "published",
    per_page: int = 100,
    max_pages: int = 10,
) -> list[dict[str, Any]]:
    """
    List all advisories for a specific repository.
    Returns parsed advisory dicts (same schema as fetch_repo_advisory).

    GET /repos/{owner}/{repo}/security-advisories
    Query params: state, direction, sort, per_page

    state: "published" | "draft" | "closed" | "withdrawn" | "triage"
           Pass "" to get all states.
    """
    url = f"{GITHUB_REST_BASE}/repos/{owner}/{repo}/security-advisories"
    params: dict[str, Any] = {
        "per_page":  per_page,
        "direction": "desc",
        "sort":      "published",
    }
    if state:
        params["state"] = state

    results: list[dict[str, Any]] = []
    page = 1

    while page <= max_pages:
        params["page"] = page
        print(f"[*] Listing {owner}/{repo} advisories (page {page}) …", file=sys.stderr)
        resp = requests.get(url, headers=_rest_headers(token),
                            params=params, timeout=15)
        if resp.status_code == 404:
            print(f"[!] Repo {owner}/{repo} not found or no advisory access.",
                  file=sys.stderr)
            break
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        for adv in batch:
            results.append(_parse_api_advisory(adv))
        if len(batch) < per_page:
            break
        page += 1

    return results


# ---------------------------------------------------------------------------
# GitHub Advisory HTML scraper
# ---------------------------------------------------------------------------

def parse_github_advisory(url: str) -> dict[str, Any]:
    print(f"[*] Fetching GitHub Advisory: {url}", file=sys.stderr)
    resp = _get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    full_text = soup.get_text(" ", strip=True)

    # --- IDs ---
    ids = _extract_identifiers(full_text)
    ghsa_id = ids["ghsa"][0] if ids["ghsa"] else _RE_GHSA.search(url) and _RE_GHSA.search(url).group()
    cve_id  = ids["cve"][0]  if ids["cve"]  else None

    # --- Package + ecosystem ---
    package   = None
    ecosystem = None

    # GitHub renders a sidebar table with "Affected packages"
    for row in soup.select("table tr, dl dt"):
        label = _clean(row.get_text())
        sibling = row.find_next_sibling()
        if not sibling:
            continue
        val = _clean(sibling.get_text())
        if "package" in label.lower():
            package = val.split()[0] if val else None
        if "ecosystem" in label.lower():
            ecosystem = val.lower()

    # Fallback: look for ecosystem keywords near the package name
    eco_keywords = ["pip", "npm", "maven", "nuget", "rubygems",
                    "cargo", "golang", "composer", "hex", "pub"]
    for kw in eco_keywords:
        if kw in full_text.lower():
            ecosystem = ecosystem or kw
            break

    # Try data in the structured sidebar (GitHub uses dl/dt/dd)
    for dt in soup.select("dt"):
        label = _clean(dt.get_text()).lower()
        dd = dt.find_next_sibling("dd")
        if not dd:
            continue
        val = _clean(dd.get_text())
        if "package" in label:
            package = package or val.split()[0]
        if "ecosystem" in label:
            ecosystem = ecosystem or val.lower()

    # Affected versions — GitHub shows a range string in the advisory body
    versions = _extract_versions(full_text)

    # Try to grab versions from structured HTML elements
    for el in soup.select(".affected-versions, .patched-versions, "
                          "[data-affected-versions], [data-patched-versions]"):
        txt = _clean(el.get_text())
        if "patch" in el.get("class", [""])[0]:
            versions["patched"].append(txt)
        else:
            versions["affected"].append(txt)

    # --- Severity ---
    severity = None
    for tag in ["critical", "high", "medium", "low"]:
        if tag in full_text.lower():
            severity = tag.capitalize()
            break

    # --- CVSS ---
    cvss_score = _extract_cvss(full_text)

    # --- Description (main advisory body) ---
    description_el = (
        soup.select_one(".markdown-body")
        or soup.select_one(".advisory-description")
        or soup.select_one("article")
    )
    raw_description = _clean(description_el.get_text()) if description_el else _clean(full_text[:2000])

    # --- File locations ---
    file_locations = _extract_file_locations(raw_description)

    # Fallback package name: top-level dir from the first code path
    # e.g. lmdeploy/vl/utils.py → lmdeploy
    if not package and file_locations:
        top = file_locations[0].get("file", "").split("/")[0].split("\\")[0]
        if top and "." not in top:
            package = top

    # --- Root cause (first paragraph that mentions the vulnerability mechanism) ---
    root_cause = None
    cause_keywords = ["ssrf", "injection", "overflow", "traversal", "deseri",
                      "xss", "csrf", "race condition", "null pointer",
                      "use-after-free", "arbitrary", "bypass", "validation",
                      "without validat", "no.*valid", "lack.*valid"]
    cause_pattern = re.compile("|".join(cause_keywords), re.I)
    sentences = re.split(r"(?<=[.!?])\s+", raw_description)
    cause_parts = [s for s in sentences if cause_pattern.search(s)]
    root_cause = " ".join(cause_parts[:3]) if cause_parts else None

    # --- Fix code / recommendation ---
    fix_code = None
    fix_keywords = re.compile(
        r"(implement|add|use|validate|block|deny|allow.?list|sanitize|check)",
        re.I,
    )
    fix_sentences = [s for s in sentences if fix_keywords.search(s)
                     and any(kw in s for kw in ["IP", "URL", "input", "request", "param", "cidr", "range", "block"])]
    if fix_sentences:
        fix_code = " ".join(fix_sentences[:3])

    # Code blocks in the advisory (if any)
    code_blocks = [_clean(c.get_text()) for c in soup.select("pre code") if c.get_text().strip()]
    if code_blocks and not fix_code:
        fix_code = code_blocks[0]

    # --- References — prefer CVE / NVD / commit / release / patch links ---
    _REF_GOOD = re.compile(
        r"(nvd\.nist\.gov|cve\.mitre|osv\.dev|snyk\.io"
        r"|/commit/|/releases/tag/|/pull/|/issues/"
        r"|/security/advisories/|/compare/|/blob/)",
        re.I,
    )
    references_sec: list[str] = []
    references_all: list[str] = []
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        if not href.startswith("http"):
            continue
        if _REF_GOOD.search(href):
            references_sec.append(href)
        references_all.append(href)
    references = list(dict.fromkeys(references_sec or references_all))[:20]

    return _build_output(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        package=package,
        ecosystem=ecosystem,
        severity=severity,
        cvss_score=cvss_score,
        affected_versions=versions["affected"],
        patched_versions=versions["patched"],
        file_locations=file_locations,
        root_cause=root_cause,
        fix_code=fix_code,
        references=references,
        raw_description=raw_description[:1500],
    )


# ---------------------------------------------------------------------------
# NVD JSON export parser (local file or API response)
# ---------------------------------------------------------------------------

def parse_nvd_json(source: str) -> dict[str, Any]:
    """Parse NVD CVE 2.0 JSON — from a local file path or a NVD API URL."""
    if source.startswith("http"):
        print(f"[*] Fetching NVD JSON: {source}", file=sys.stderr)
        data = _get(source).json()
    else:
        print(f"[*] Reading local NVD JSON: {source}", file=sys.stderr)
        data = json.loads(Path(source).read_text(encoding="utf-8"))

    # NVD CVE 2.0 structure: data["vulnerabilities"][0]["cve"]
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        sys.exit("No vulnerabilities found in NVD JSON.")

    cve_item = vulns[0].get("cve", vulns[0])

    cve_id  = cve_item.get("id") or cve_item.get("CVE_data_meta", {}).get("ID")
    ghsa_id = None

    # Description
    descs = cve_item.get("descriptions", cve_item.get("description", {}).get("description_data", []))
    raw_description = next(
        (d["value"] for d in descs if d.get("lang") == "en"), ""
    )

    # CVSS
    metrics  = cve_item.get("metrics", {})
    cvss_score = None
    severity   = None
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            severity   = m.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break

    # References
    references = [r["url"] for r in cve_item.get("references", []) if "url" in r]

    # Affected packages — NVD stores these in configurations/CPE nodes
    package   = None
    ecosystem = None
    affected_versions: list[str] = []
    patched_versions:  list[str] = []

    for config in cve_item.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                uri = cpe_match.get("criteria", "")
                # cpe:2.3:a:vendor:product:version:...
                parts = uri.split(":")
                if len(parts) >= 5:
                    package   = package   or parts[4]   # product
                    ecosystem = ecosystem or _infer_ecosystem(uri, references)
                start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                end   = cpe_match.get("versionEndIncluding")   or cpe_match.get("versionEndExcluding")
                if end:
                    op = "<=" if "Including" in (cpe_match.get("versionEndIncluding") or "") else "<"
                    affected_versions.append(f"{op} {end}")
                if start:
                    op = ">=" if "Including" in (cpe_match.get("versionStartIncluding") or "") else ">"
                    affected_versions.append(f"{op} {start}")

    # Fallback version extraction from description
    if not affected_versions:
        v = _extract_versions(raw_description)
        affected_versions = v["affected"]
        patched_versions  = v["patched"]

    ids = _extract_identifiers(raw_description)
    ghsa_id = ids["ghsa"][0] if ids["ghsa"] else None

    file_locations = _extract_file_locations(raw_description)
    sentences      = re.split(r"(?<=[.!?])\s+", raw_description)
    cause_pattern  = re.compile(r"ssrf|injection|overflow|traversal|bypass|without.valid|no.valid|arbitrary", re.I)
    root_cause     = " ".join(s for s in sentences if cause_pattern.search(s))[:600] or None

    return _build_output(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        package=package,
        ecosystem=ecosystem,
        severity=severity,
        cvss_score=cvss_score,
        affected_versions=list(dict.fromkeys(affected_versions)),
        patched_versions=list(dict.fromkeys(patched_versions)),
        file_locations=file_locations,
        root_cause=root_cause or None,
        fix_code=None,
        references=references,
        raw_description=raw_description[:1500],
    )


def _infer_ecosystem(cpe_uri: str, references: list[str]) -> str | None:
    """Guess ecosystem from CPE string and reference URLs."""
    ref_text = " ".join(references).lower()
    if "pypi.org" in ref_text or "pip" in ref_text:
        return "pip"
    if "npmjs.com" in ref_text or "node" in ref_text:
        return "npm"
    if "rubygems.org" in ref_text:
        return "rubygems"
    if "pkg.go.dev" in ref_text or "golang" in ref_text:
        return "golang"
    if "crates.io" in ref_text:
        return "cargo"
    if "packagist.org" in ref_text or "composer" in ref_text:
        return "composer"
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def resolve_source(arg: str,
                   token: str | None = None) -> tuple[str, str]:
    """
    Return (source_string, mode).

    Modes:
      'api_global'  — GitHub REST /advisories/{ghsa_id}          (preferred for GHSA)
      'api_repo'    — owner/repo#GHSA-xxxx-xxxx-xxxx             (repo-level)
      'github'      — HTML scrape fallback (no token or API fails)
      'nvd'         — NVD API
      'file'        — local JSON
    """
    # owner/repo#GHSA-... format → repo advisory API
    if "#GHSA-" in arg and "/" in arg.split("#")[0]:
        return arg, "api_repo"

    if arg.startswith("GHSA-"):
        # Prefer REST API (richer structured data, no HTML parsing)
        if token or os.environ.get("GITHUB_TOKEN"):
            return arg, "api_global"
        return f"{GITHUB_ADVISORY_BASE}/{arg}", "github"

    if arg.startswith("CVE-"):
        return f"{NVD_API_BASE}?cveId={arg}", "nvd"

    parsed = urlparse(arg)
    if parsed.scheme in ("http", "https"):
        if "github.com/advisories" in arg or "GHSA-" in arg:
            # Extract GHSA ID and use API if token available
            m = _RE_GHSA.search(arg)
            if m and (token or os.environ.get("GITHUB_TOKEN")):
                return m.group(), "api_global"
            return arg, "github"
        if "nvd.nist.gov" in arg:
            return arg, "nvd"
    return arg, "file"


def main() -> None:
    _fix_stdout_encoding()
    parser = argparse.ArgumentParser(
        description="Extract structured vulnerability data from GHSA or NVD sources."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ghsa",   metavar="GHSA-ID",
                       help="e.g. GHSA-6w67-hwm5-92mq")
    group.add_argument("--cve",    metavar="CVE-ID",
                       help="e.g. CVE-2026-33626")
    group.add_argument("--repo",   metavar="OWNER/REPO",
                       help="List all published advisories for a repository")
    parser.add_argument("source",  nargs="?",
                        help="URL, GHSA ID, owner/repo#GHSA-id, or local JSON")
    parser.add_argument("--indent", type=int, default=2,
                        help="JSON indent (default 2)")
    parser.add_argument("--state",  default="published",
                        help="Advisory state filter for --repo "
                             "(published|draft|closed|triage|'') default: published")
    parser.add_argument("--token",  default=None,
                        help="GitHub token (overrides GITHUB_TOKEN env var)")
    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")

    # ── --repo: list all advisories for a repository ──────────────────────────
    if args.repo:
        parts = args.repo.split("/", 1)
        if len(parts) != 2:
            sys.exit("--repo must be in owner/repo format, e.g. InternLM/lmdeploy")
        owner, repo = parts
        advisories = list_repo_advisories(owner, repo, token=token,
                                          state=args.state)
        print(json.dumps(advisories, indent=args.indent, ensure_ascii=False))
        return

    raw = args.ghsa or args.cve or args.source
    if not raw:
        parser.print_help()
        sys.exit(1)

    source, mode = resolve_source(raw, token=token)

    if mode == "api_global":
        ghsa_id = _RE_GHSA.search(source)
        if not ghsa_id:
            sys.exit(f"Could not extract GHSA ID from: {source}")
        result = fetch_global_advisory(ghsa_id.group(), token=token)
    elif mode == "api_repo":
        repo_part, ghsa_part = source.split("#", 1)
        owner, repo = repo_part.split("/", 1)
        result = fetch_repo_advisory(owner, repo, ghsa_part, token=token)
    elif mode == "github":
        result = parse_github_advisory(source)
    elif mode in ("nvd", "file"):
        result = parse_nvd_json(source)
    else:
        sys.exit(f"Cannot determine source type for: {raw}")

    print(json.dumps(result, indent=args.indent, ensure_ascii=False))


if __name__ == "__main__":
    main()
