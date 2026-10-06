# free5GC LLM patch quality scoring (beyond pass/fail)

| Model | Diff similarity to real fix | Lines added | Lines removed | Minimal fix shape |
|---|---|---|---|---|
| `qwen2.5-coder:7b (original single-model run)` | 1.0000 | 0 | 0 | True |
| `claude-haiku-4-5-20251001` | 1.0000 | 0 | 0 | True |
| `claude-opus-4-6` | 1.0000 | 0 | 0 | True |
| `claude-opus-4-7` | 1.0000 | 0 | 0 | True |
| `claude-opus-4-8` | 1.0000 | 0 | 0 | True |
| `claude-opus-5-5` | 1.0000 | 0 | 0 | True |
| `claude-sonnet-4-6` | 1.0000 | 0 | 0 | True |
| `claude-sonnet-5-5` | 1.0000 | 0 | 0 | True |
| `gemma2:9b` | 1.0000 | 0 | 0 | True |
| `codellama:13b` | 0.9851 | 0 | 1 | False |
| `qwen2.5-coder:1.5b` | 0.9552 | 1 | 2 | False |
| `llama3.1:8b` | 0.9412 | 2 | 2 | False |
| `qwen2.5-coder:3b` | 0.9412 | 2 | 2 | False |
| `mistral:7b` | 0.9118 | 3 | 3 | False |
