# free5GC memorization control: REAL CVE baseline (matched models)

Target: `HandleApplicationDataInfluenceDataSubsToNotifyGet` (the real, disclosed CVE-2026-40248 handler).

| Model | Compiles (fixes the real CVE) |
|---|---|
| `llama3.2:1b` | NO (# github.com/free5gc/udr/internal/sbi
internal\sbi\api_datarepository.go:2752:33: undefined: problemDetails
internal\sbi\api_datarepository.go:2762:33: invalid operation: cannot call problemDetails (variable of struct type models.ProblemDetails): models.ProblemDetails is not a function
) |
| `llama3.2:3b` | yes |
| `qwen3:8b` | NO (TimeoutError: timed out) |
| `deepseek-r1:14b` | NO (TimeoutError: timed out) |
