# AI CVE Exploit Automation — Claude Code Context

## Project Overview

4-stage CVE analysis pipeline that watches NVD + GHSA feeds and auto-generates
exploit reports with live probe results, curl commands, and bypass analysis.

## Quick Start

```powershell
# Start background watcher (auto-starts on login via Startup folder)
.\start_watcher.ps1

# Check status
Get-Content watcher_stderr.log -Tail 30 -Wait
Get-Content watcher.pid

# View a report
cat reports\CVE-2026-6145.txt
```

## Key Files

| File | Role |
|------|------|
| `cve_pipeline.py` | 4-stage pipeline (advisory → analysis → probe → report) |
| `cve_watcher.py` | NVD + GHSA feed poller, dispatches pipeline per CVE |
| `start_watcher.ps1` | Background launcher (hidden process, transcript logging) |
| `run_watcher_silent.vbs` | VBScript → PowerShell bridge for Windows Startup folder |
| `ssrf_lab/server.py` | Flask SSRF lab (localhost:8000), patched/vulnerable mode toggle |
| `reports/*.txt` | One report per CVE |
| `.env` | NVD_API_KEY, ANTHROPIC_API_KEY (optional), GITHUB_TOKEN (optional) |

## Pipeline Stages

1. **Advisory** — fetch from NVD v2 API or GHSA
2. **Analysis** — classify vuln (SSRF/SQLi/CMDi/XSS/PathTraversal/Deserialization/MemorySafety/UNKNOWN)
3. **Probe** — SSRF and Memory Safety get real dynamic confirmation (live lab / compile+run harness); the other four classes are static regex pattern matching against the diff, not live exploitation - see README "Honest gap" note
3.5. **Exploit artifacts** — writes poc.py + target_app.py for any class (template or Claude-generated)
3.6. **Exploit execution** — actually runs the Stage 3.5 artifact and records the real exit code as `dynamically_confirmed`, instead of leaving it on disk unexecuted
3.7. **Self-improvement** — when 3.6 genuinely ran and genuinely failed, checks `.pipeline_lessons.json` (fixes learned on past CVEs of the same class) → falls back to an LLM revision when available → falls back to a small built-in rule library; re-runs and persists a newly-successful fix. Bounded (max 3 iterations), never guesses past a signature with no known fix - see `reports/CVE_CATALOG.md`'s "Self-improvement" section for a concrete worked example (CMDi template fixed automatically, then reused on a second run)
4. **Report** — text/JSON with curl commands and bypass results

## AI Backend

No API key required. Auto-detects:
1. `ANTHROPIC_API_KEY` + pydantic_ai → agent mode
2. `claude` CLI available → `claude -p` (uses Claude Code auth)
3. Neither → text-only heuristic extraction

## Environment

- `NVD_API_KEY`: stored in `~/.claude/settings.json` env section and `.env`
- Watcher polls every 60 min, 2 parallel workers
- Reports saved to `reports/`, deduplication via `seen_cves.json`

## Wiki Knowledge Base

Path: `C:\Users\dheer\obsidian-vault`

When you need project context not already visible in this conversation:
1. Read `wiki/hot.md` first (recent context summary, ~500 words)
2. If not enough, read `wiki/index.md`
3. For CVE pipeline specifics: read `wiki/domains/cve-automation/_index.md`
4. For architecture details: `wiki/domains/cve-automation/pipeline-architecture.md`
5. For bypass techniques: `wiki/domains/cve-automation/bypass-techniques.md`
6. For processed CVE log: `wiki/domains/cve-automation/processed-cves.md`
7. Raw sources: `.raw/cve-pipeline-architecture.md`, `.raw/cve-bypass-techniques.md`, `.raw/cve-session-history.md`

Do NOT read the wiki for general coding questions or things already visible here.

## GitHub

https://github.com/J-Dheeraj/AI-exploit-CVE
