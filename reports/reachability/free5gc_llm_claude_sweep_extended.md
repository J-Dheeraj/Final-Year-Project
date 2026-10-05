# free5GC LLM patch: extended Claude model comparison

| Model | Compiles | Applied/4 | Cost (USD) | Runtime verdict |
|---|---|---|---|---|
| `claude-sonnet-4-6` | yes | 4/4 | $0.1494 | confirmed_fix_all_four_handlers |
| `claude-sonnet-5` | NO (generate_patch failed: RuntimeError: claude -p failed (exit 1): ) | 0/4 | n/a | not reached (compile failed) |
| `claude-opus-4-6` | yes | 4/4 | $0.2477 | confirmed_fix_all_four_handlers |
| `claude-opus-4-7` | yes | 4/4 | $0.3427 | confirmed_fix_all_four_handlers |
| `claude-opus-4-8` | yes | 4/4 | $0.3460 | confirmed_fix_all_four_handlers |
