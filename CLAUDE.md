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
3.8. **Patch generation & validation** (`src/pipeline/patch.py`) — when an exploit is dynamically confirmed, asks an LLM to patch the vulnerable handler, then trusts it only if the original exploit now fails AND `/health` still passes against the patched target. No AI backend → no patch attempt, stated honestly via `patch_skip_reason`.
4. **Report** — text/JSON with curl commands and bypass results

## Repo layout

`cve_pipeline.py` holds the pydantic-ai Tool 1-4 registrations and CLI
orchestration; `src/` holds extracted, self-contained modules (exploit
templates, self-improvement, patch generation, rendering, Obsidian
ingest, metrics, reachability). See `docs/CRS_MAPPING.md` for how these
stages map onto DARPA AIxCC / OSS-CRS cyber-reasoning-system concepts,
`docs/REACHABILITY.md` for `src/reachability/` (ported from this FYP's
earlier reachcrs prototype) against a real free5GC CVE, and
`docs/FREE5GC_LAB.md` for the free5GC-adjacent dynamic exploit lab.

## Git remotes — read before any push

`origin` (github.com/J-Dheeraj/AI-exploit-CVE) is deliberately frozen at
commit `88844d2` (the pre-refactor, video-included version) per the
user's explicit instruction — do not push there. `fyp`
(github.com/J-Dheeraj/Final-Year-Project) is the only remote that
receives new commits: `git push fyp main:main`. Never `git push origin
main`. This local checkout stays ahead of `origin` indefinitely — that's
expected, not a problem to fix.

## Multi-session coordination — mandatory, read before starting work

This repo is regularly worked on from more than one Claude Code session at
once (e.g. different local clones/paths on the same machine, or a review
session running in parallel with a dev session). Native Claude Code
auto-memory does NOT cover this: it's scoped per working-directory hash,
so two sessions in two different clone paths have entirely separate,
invisible-to-each-other memory stores. `docs/PROJECT_STATUS.md`'s session
log is the one thing both sessions actually share (it's committed and
pushed to the real GitHub repo), which makes it the de facto coordination
mechanism — but only if every session actually uses it. This is not
hypothetical: on 2026-09-23/24, two independent sessions each rediscovered
and fixed the same Stage 3.7 bug, and one built real capability (multi-
payload patch validation) the other never knew existed, purely because
neither read the other's state before starting. **Concrete rule:**

1. **Before starting any work**, `git fetch`/`git pull` and read
   `docs/PROJECT_STATUS.md`'s session log — at minimum the newest 2-3
   entries — so you know what another session may have already done,
   in-flight, or found. If `main` has moved since your last known
   commit, say so before proceeding, don't silently work from stale state.
2. **Before ending a work session**, append a new dated entry to
   `docs/PROJECT_STATUS.md`'s session log (newest-first, matching its
   existing format) describing what was attempted and whether exit
   criteria were met — even if the work isn't finished. An in-progress
   or partially-done session still needs an entry; that's what lets the
   next session (yours or another one) pick up accurately.
3. **If you discover mid-session that another session is likely active
   on this same repo right now** (e.g. `main` has commits you didn't
   expect, a branch you're using already has unfamiliar commits), use
   cross-session messaging (`ListAgents`/`SendMessage`, when available)
   to flag it directly rather than silently reconciling or silently
   proceeding — a live message is faster and more precise than either
   session guessing from git state alone.

## Project framing (read before writing anything FYP-facing)

This project's original pitch ("fuzzing LLMs to secure OSS") has been
deliberately dropped - confirmed OK with the professor - because nothing
in this pipeline does actual fuzzing (coverage-guided mutation), and
saying otherwise would be indefensible in a viva. The honest, current
framing: **LLM-assisted exploit confirmation and patch validation for
known CVEs** (the main `cve_pipeline.py` flow) **plus real reachability-
filtered static analysis on real upstream source** (`src/reachability/`).
Don't reintroduce "fuzzing" language into docs/reports/commit messages
for this project without the user explicitly asking.

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
