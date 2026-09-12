# AI CVE Exploit Automation

An end-to-end pipeline that watches NVD and GitHub Advisory feeds for new CVEs,
classifies the vulnerability, runs live exploit probes, generates bypass analysis,
and writes runnable PoC exploit scripts — all without requiring an Anthropic API key.

---

## How it works

```
NVD / GHSA feed
      │
      ▼
Stage 1 — Advisory Fetch
  Pull structured metadata: CVSS, CWE, affected versions,
  root cause, file locations, patch diff links.
      │
      ▼
Stage 2 — Vulnerability Analysis
  Classify: SSRF / SQL Injection / OS Command Injection /
  XSS / Path Traversal / Deserialization / UNKNOWN.
  Identify unsafe code patterns and fix description.
      │
      ▼
Stage 3 — Live Probe
  Route to a class-specific probe. Test against the local
  SSRF lab in vulnerable mode, then patched mode.
  Produce curl commands and EXPLOITED / BLOCKED verdicts.
      │
      ▼
Stage 3.5 — Exploit Artifact Generation
  Write poc.iter1.v0.py + target_app.iter1.v0.py for every CVE.
  AI-generated when claude CLI is available; class-specific
  template fallback otherwise.
      │
      ▼
Stage 4 — Report
  Compile everything into a structured TEXT or JSON report.
  Auto-ingest into Obsidian wiki if OBSIDIAN_VAULT is set.
```

---

## Features

- **No API key required.** Uses Claude Code's own auth via `claude -p` when
  available, falls back to text-only heuristic extraction.
- **6 vuln classes** with dedicated probes and bypass analysis: SSRF, SQL Injection,
  OS Command Injection, XSS, Path Traversal, Deserialization.
- **5 bypass techniques per class** tested against the patched lab, each returning
  EXPLOITED / BLOCKED / THEORETICAL.
- **Ready-to-run PoC artifacts** per CVE: `poc.iter1.v0.py` + `target_app.iter1.v0.py`
  following the 4-phase exploit pattern (health → exploit → verify → exit code).
- **Persistent cache** — each pipeline stage is cached to `.pipeline_cache/<CVE-ID>/`
  with a 24-hour TTL. Re-runs are instant.
- **Background watcher** — polls NVD + GHSA every 60 minutes and processes new CVEs
  automatically. Runs hidden on Windows via Startup folder.
- **Dual-mode SSRF lab** — Flask server that toggles between vulnerable and patched
  at runtime. No external dependency needed for live testing.

---

## Quick start

### 1. Install dependencies

```bash
pip install pydantic-ai anthropic requests fastapi uvicorn
```

For AI-enhanced mode (optional):

```bash
# Either set ANTHROPIC_API_KEY
export ANTHROPIC_API_KEY=sk-ant-...

# Or install Claude Code CLI (uses its own auth — no key needed)
npm install -g @anthropic-ai/claude-code
```

### 2. Configure keys

```bash
cp .env.example .env
# Edit .env — NVD_API_KEY is recommended for higher NVD rate limits
```

`.env.example`:
```
ANTHROPIC_API_KEY=sk-ant-...   # optional
NVD_API_KEY=your-nvd-key-here  # optional but recommended
GITHUB_TOKEN=ghp_...           # optional, for GHSA private advisories
```

### 3. Run a single CVE

```bash
# Text report
python cve_pipeline.py CVE-2026-33626

# JSON report
python cve_pipeline.py CVE-2026-33626 --format json --out report.json

# Skip live probe
python cve_pipeline.py CVE-2026-33626 --no-probe

# Force fresh fetch (bypass cache)
python cve_pipeline.py CVE-2026-33626 --no-cache

# GHSA ID also accepted
python cve_pipeline.py GHSA-6w67-hwm5-92mq
```

### 4. Start the background watcher

```powershell
# Windows — starts a hidden background process
.\start_watcher.ps1

# Check live output
Get-Content watcher_stderr.log -Tail 30 -Wait

# Stop
$pid = Get-Content watcher.pid; Stop-Process -Id $pid
```

Linux / macOS:
```bash
python cve_watcher.py --interval 60 --workers 2
```

---

## Project structure

```
AI CVE Exploit Automation/
├── cve_pipeline.py          # Core pipeline: all 4 stages + Stage 3.5
├── cve_watcher.py           # Feed watcher — polls NVD + GHSA, dispatches pipeline
├── dryrun.py                # End-to-end smoke test with no API key needed
├── ghsa_extractor.py        # GitHub Security Advisory extractor
│
├── ssrf_lab/
│   ├── server.py            # Dual-mode Flask lab (vulnerable / patched)
│   ├── image_loader.py      # URL fetcher with SSRF guard logic
│   ├── ssrf_probe.py        # Live SSRF probe runner
│   ├── bypass_analysis.py   # 5-technique bypass analysis against patched mode
│   └── bypass_demo.py       # Interactive bypass demo
│
├── reports/
│   ├── CVE-2026-33626.txt   # Text report (one file per CVE)
│   ├── CVE-2025-11024/
│   │   ├── poc.iter1.v0.py          # Runnable PoC exploit
│   │   └── target_app.iter1.v0.py   # Minimal vulnerable Flask target
│   └── ...
│
├── CVE-2026-33626/          # Reference snapshot: original pipeline built
│   ├── cve_pipeline.py      # against this CVE (SSRF in lmdeploy image loader)
│   ├── dryrun.py
│   └── ssrf_lab/
│
├── .pipeline_cache/         # Per-stage JSON cache (TTL 24h, gitignored)
├── seen_cves.json           # Watcher deduplication store
│
├── start_watcher.ps1        # PowerShell background launcher
├── run_watcher_silent.vbs   # VBScript bridge for Windows Startup folder
├── run_watcher.bat          # Direct batch launcher
└── .env.example             # Environment variable template
```

---

## Pipeline stages in detail

### Stage 1 — Advisory Fetch

Pulls structured advisory data from NVD v2 API or GitHub Security Advisories (GHSA).
Extracts: CVE/GHSA ID, CVSS score, severity, CWE, affected packages and versions,
root cause description, patch links, and any linked source file locations.

Supports both CVE IDs (`CVE-2026-33626`) and GHSA IDs (`GHSA-6w67-hwm5-92mq`).

### Stage 2 — Vulnerability Analysis

Classifies the vulnerability into one of eight classes:

| Class | CWE | Probe |
|---|---|---|
| SSRF | CWE-918 | Live HTTP fetch to internal endpoints |
| SQL Injection | CWE-89 | Boolean-blind SQLi + UNION injection |
| OS Command Injection | CWE-78 | Shell metacharacter injection |
| XSS | CWE-79 | Reflected payload execution |
| Path Traversal | CWE-22 | Directory traversal sequences |
| Deserialization | CWE-502 | Unsafe object deserialization |
| Memory Safety (buffer overflow / UAF / underflow) | CWE-121, CWE-416, CWE-191 | Compile + run a generated PoV harness against the real C source - see "Stage 3 (native code)" below |
| UNKNOWN | — | Generic template |

When Claude is available, it reads the patch diff to identify unsafe code patterns
and generate a fix description. In text-only mode, classification uses keyword
matching against the advisory description.

### Stage 3 — Live Probe

Routes to a class-specific probe function. For SSRF:

1. Starts the SSRF lab in **vulnerable mode**
2. Sends a crafted payload pointing to `169.254.169.254/latest/meta-data/`
3. Records the response verdict (EXPLOITED / FAIL)
4. Switches lab to **patched mode**
5. Retests the same payload and all bypass variants
6. Returns curl commands, bypass results, and BLOCKED/EXPLOITED/THEORETICAL per technique

**Honest gap, stated plainly (fixed by Stage 3.6 below for the artifact-execution
half of it)**: SSRF is the only class above with a live lab wired into Stage 3
itself. `_probe_sqli`, `_probe_cmdi`, `_probe_path_traversal`, `_probe_xss`, and
`_probe_deserialization` are all static regex pattern-matching against the code
diff - not live exploitation. Every one of their `bypass_results` entries carries
`"tested": False` in the code, hardcoded. "THEORETICAL — test against WAF/patched
endpoint" was a literal, honest label for what those probes actually do; it just
wasn't obvious from the report output alone that "probe" and "regex match" meant
the same thing for six of the seven classes.

#### Stage 3 (native code) — Memory Safety

The one class this pipeline had **zero** capability for before: buffer overflow,
use-after-free, unsigned-integer underflow (the exact bug class behind AIxCC's
own "Needle" case study, CVE-2023-0179). `_probe_memory_safety` generates a
minimal proof-of-vulnerability `main()` harness (via `claude -p`, or a narrow
rule-based fallback for the one calling shape it recognizes without a model - a
raw `(buffer, unsigned length)` signature feeding an underflow into a copy call),
compiles it together with the vulnerable source, and runs it. A real segfault
(`exit -11`) on the vulnerable version and a clean exit on the patched version is
what "confirmed: true" actually means here - not a regex match. Falls back
honestly (`confirmed: false`, with a stated reason) when no C compiler is on
PATH, or the function's signature isn't one a harness could be generated for.

### Stage 3.5 — Exploit Artifact Generation

Writes two runnable Python files into `reports/<CVE-ID>/` for every CVE processed:

**`poc.iter1.v0.py`** — the exploit script:
```python
# 4-phase pattern
def health():   # verify target is up
def exploit():  # send the payload
def verify(r):  # check for exploitation evidence
# sys.exit(0) = exploited, sys.exit(1) = failed
```

**`target_app.iter1.v0.py`** — a minimal Flask app that replicates the vulnerability.

Usage:
```bash
# Terminal 1 — start the vulnerable target
python reports/CVE-2025-11024/target_app.iter1.v0.py

# Terminal 2 — run the exploit
python reports/CVE-2025-11024/poc.iter1.v0.py 127.0.0.1:5000
# exit 0 = exploited, exit 1 = failed
```

Templates are available for all 6 vuln classes. When the `claude` CLI is available,
the pipeline asks Claude to write CVE-specific code with the full advisory context;
the template is the fallback.

### Stage 3.6 — Actually run what Stage 3.5 generated

Stage 3.5 above wrote `poc.py` + `target_app.py` to disk and stopped there - a
human had to open two terminals and run them by hand to find out whether the
generated exploit actually worked. `execute_exploit_artifacts()` closes that
loop automatically: it starts `target_app.py` as a subprocess, polls `/health`
until it's up, runs `poc.py` against it, and reads the real exit code (the
convention every generated PoC's own docstring already documents: `0=exploited,
1=failed`). `dynamically_confirmed` on the report is a genuine pass/fail from
actually running the code, for **any** vulnerability class Stage 3.5 could
generate an artifact for - not just SSRF, and not limited to the six classes
with hardcoded templates, since the `claude -p` generation path works from the
advisory text for classes it has never seen a template for too.

```bash
# What used to require two manual terminals now happens automatically as
# part of the pipeline run - the CVE-2026-24712 example above would show:
#   EXPLOIT ARTIFACTS
#   Status               : GENERATED (iter 1, v0)
#   Executed             : True
#   Exit code             : 0
#   Dynamically confirmed : True
```

Degrades honestly rather than faking success: if `target_app.py` never becomes
healthy, or `poc.py` hangs past its timeout, `executed=True` but
`dynamically_confirmed` stays `None` with the real reason recorded in
`execution_log` - the same "say why nothing ran" philosophy the rest of this
pipeline already uses for a missing API key or an unreachable NVD endpoint.

### Stage 4 — Report

Compiles everything into a structured report. Example output:

```
======================================================================
  CVE PIPELINE REPORT
======================================================================
  CVE          : CVE-2026-24712
  Stages done  : 1_advisory, 2_analysis, 3_vuln_probe, 4_report

  ADVISORY
  Severity   : CRITICAL  CVSS 9.8
  Class      : OS Command Injection  CWE-78

  CURL TEST COMMANDS
  curl -s 'http://target/ping?host=127.0.0.1;id'
  curl -s 'http://target/ping?host=127.0.0.1|cat+/etc/passwd'

  BYPASS ANALYSIS vs PATCHED MODE
  [1] IFS Separator      — THEORETICAL
  [2] Newline / LF       — THEORETICAL
  [3] Backtick subshell  — THEORETICAL

  EXPLOIT ARTIFACTS
  Status    : GENERATED (iter 1, v0)
  PoC       : reports/CVE-2026-24712/poc.iter1.v0.py
  Target    : reports/CVE-2026-24712/target_app.iter1.v0.py

  FINAL REPORT
  Overall risk : CRITICAL
  Recommendations:
    1. Never pass user input to shell commands without sanitization.
    2. Use subprocess with a list of arguments instead of shell=True.
======================================================================
```

---

## SSRF lab

The SSRF lab (`ssrf_lab/server.py`) is a local FastAPI server that simulates the
lmdeploy SSRF vulnerability (CVE-2026-33626 / GHSA-6w67-hwm5-92mq).

```bash
# Start in vulnerable mode (default is patched)
LAB_MODE=vulnerable python ssrf_lab/server.py

# Switch mode at runtime
curl -X POST http://127.0.0.1:8000/mode -d '{"mode":"vulnerable"}'
curl http://127.0.0.1:8000/mode        # check current mode

# View audit log
curl http://127.0.0.1:8000/audit
```

The lab implements two URL validators:

- `vulnerable_load_image()` — no SSRF protection, fetches any URL including internal
- `hardened_load_image()` — blocks all RFC-1918, loopback, and link-local CIDRs

The pipeline's bypass analysis tests 5 techniques against the hardened validator:
decimal IP encoding, IPv6 loopback, URL redirection chains, DNS rebinding
(requires external infra), and protocol confusion.

---

## CVE-2026-33626 — the reference example

This pipeline was originally built to analyze **CVE-2026-33626** (GHSA-6w67-hwm5-92mq),
an SSRF vulnerability in the [lmdeploy](https://github.com/InternLM/lmdeploy) inference
framework's image loading code.

The vulnerability: `image_loader.py` fetched user-supplied URLs without validating
the resolved IP address, allowing an attacker to reach internal metadata services
(`169.254.169.254`) via a crafted `image_url` in the `/v1/chat/completions` API.

The `CVE-2026-33626/` folder contains a snapshot of the codebase from when this CVE
was the primary test case, including the original `dryrun.py` that calls each stage
function directly with `GHSA-6w67-hwm5-92mq` as the input.

Run the dry run (no API key needed):
```bash
cd CVE-2026-33626
python dryrun.py
```

---

## AI backend

The pipeline auto-selects from three modes at startup:

| Priority | Condition | What it does |
|---|---|---|
| 1 | `ANTHROPIC_API_KEY` + `pydantic_ai` installed | Full agent mode via pydantic-ai RunContext |
| 2 | `claude` CLI available in PATH | `claude -p` subprocess calls with structured marker extraction |
| 3 | Neither | Text-only: keyword classification, heuristic fix extraction |

Mode 3 requires no credentials and produces useful reports for all standard CVE types.
Mode 2 (Claude Code CLI) adds AI-written PoC code and richer advisory summaries.

---

## Watcher configuration

```bash
python cve_watcher.py \
  --interval 60 \    # poll every 60 minutes (default)
  --workers 2 \      # process 2 CVEs in parallel (default)
  --lookback 6 \     # on first run, fetch CVEs from last 6 hours
  --format text \    # text or json
  --no-probe         # skip live probes (faster, no lab needed)
```

On Windows, `run_watcher_silent.vbs` launches `start_watcher.ps1` as a hidden
process. Place a shortcut to `run_watcher_silent.vbs` in the Startup folder
(`shell:startup`) to auto-start on login.

---

## Configuration reference

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `NVD_API_KEY` | No | — | Higher NVD rate limits (10 req/s vs 5 req/60s) |
| `ANTHROPIC_API_KEY` | No | — | Enables pydantic-ai agent mode |
| `GITHUB_TOKEN` | No | — | Access private GHSA advisories |
| `OBSIDIAN_VAULT` | No | — | Path to Obsidian vault for auto-wiki ingest |
| `LAB_MODE` | No | `patched` | SSRF lab start mode (`vulnerable` or `patched`) |
| `LAB_PORT` | No | `8000` | SSRF lab port |

Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key

---

## Disclaimer

This tool is for authorized security research and education only. Running exploit
probes or PoC scripts against systems you do not own or have explicit written
permission to test is illegal. The SSRF lab is bound to `127.0.0.1` by design —
never expose it on a public interface.
