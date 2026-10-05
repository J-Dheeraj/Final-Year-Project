# free5GC memorization control: synthetic, never-disclosed bug

Target: `HandleCreateAuthenticationStatus` (NOT one of the four real CVE-2026-40248 handlers) - same bug class, injected fresh by this experiment.

| Model | Compiles (fixes the synthetic bug) |
|---|---|
| `llama3.2:1b` | yes |
| `llama3.2:3b` | NO (# github.com/free5gc/udr/internal/sbi
internal\sbi\api_datarepository.go:1011:17: problemDetail.Title undefined (type string has no field or method Title)
internal\sbi\api_datarepository.go:1013:50: problemDetail.Cause undefined (type string has no field or method Cause)
internal\sbi\api_datarepository.go:1014:10: cannot use rsp.Status (variable of type int32) as int value in argument to c.JSON
) |
| `qwen3:8b` | NO (TimeoutError: timed out) |
| `deepseek-r1:14b` | NO (TimeoutError: timed out) |
