# free5GC memorization control (claude): synthetic, never-disclosed bug

Target: `HandleCreateAuthenticationStatus` (NOT one of the four real CVE-2026-40248 handlers) - same bug class, injected fresh by this experiment.

| Model | Compiles (fixes the synthetic bug) | Cost (USD) |
|---|---|---|
| `claude-haiku-4-5-20251001` | yes | $0.0557 |
| `claude-sonnet-4-6` | yes | $0.1522 |
| `claude-sonnet-5` | NO (RuntimeError: claude -p failed (exit 1): ) | n/a |
| `claude-opus-4-6` | yes | $0.2513 |
| `claude-opus-4-7` | NO (# github.com/free5gc/udr/internal/sbi
internal\sbi\api_datarepository.go:978:1: syntax error: non-declaration statement outside function body
internal\sbi\api_datarepository.go:984:25: more than one character in rune literal
internal\sbi\api_datarepository.go:984: newline in rune literal
internal\sbi\api_datarepository.go:986:3: string not terminated
) | $0.3512 |
| `claude-opus-4-8` | yes | $0.3941 |
