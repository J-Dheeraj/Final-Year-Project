# free5GC memorization control: REAL CVE baseline (claude)

Target: `HandleApplicationDataInfluenceDataSubsToNotifyGet` (the real, disclosed CVE-2026-40248 handler).

| Model | Compiles (fixes the real CVE) | Cost (USD) |
|---|---|---|
| `claude-haiku-4-5-20251001` | yes | $0.0552 |
| `claude-sonnet-4-6` | yes | $0.1494 |
| `claude-sonnet-5` | NO (RuntimeError: claude -p failed (exit 1): ) | n/a |
| `claude-opus-4-6` | yes | $0.2480 |
| `claude-opus-4-7` | yes | $0.3427 |
| `claude-opus-4-8` | yes | $0.3882 |
