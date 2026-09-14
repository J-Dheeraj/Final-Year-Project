# Pipeline metrics

Computed by `python -m src.metrics` directly from `reports/*/report.json` already on disk — no re-run, no estimation beyond what's noted.

- CVEs in catalog: **6**
- Dynamically confirmed (PoV rate): **5/6 (83%)**
- Self-improvement (Stage 3.7) invoked: **3**
- Patch attempted (Stage 3.8): **0**
- Patch validated: **0 (none attempted)**
- Wall-clock per CVE: mean **1.21s**, median **0.97s**
- LLM calls per CVE (estimate, undercounts Stage 2/3.5): mean **0**, total **0**

## By vulnerability class

| Class | Confirmed | Attempted | Rate |
|---|---|---|---|
| Cross-Site Scripting (XSS) | 1 | 1 | 100% |
| Insecure Deserialization | 1 | 1 | 100% |
| OS Command Injection | 1 | 1 | 100% |
| Path Traversal | 1 | 1 | 100% |
| SQL Injection | 1 | 1 | 100% |
| Server-Side Request Forgery (SSRF) | 0 | 1 | 0% |
