# free5GC bypass-probe sweep: all local Ollama models vs. the real fix

| Model | Proposal parsed | Request executed | Genuine trick | Bypass confirmed |
|---|---|---|---|---|
| `deepseek-coder-v2:16b` | NO (RuntimeError: Ollama request failed (500): {"error":"llama-server reported out-of-memory during startup: ggml_backend_cpu_buffer_type_alloc_buffer: failed to allocate buffer of size 45298483200\nalloc_tensor_range: failed to allocate CPU buffer of size 45298483200\nllama_init_from_model: failed to initialize the context: failed to allocate buffer for kv cache"}) | no | n/a | no (fix held) |
| `codellama:13b` | yes | yes | no | no (fix held) |
| `gemma2:9b` | yes | yes | yes | no (fix held) |
| `mistral:7b` | yes | yes | yes | no (fix held) |
| `llama3.1:8b` | yes | yes | yes | no (fix held) |
| `qwen2.5-coder:7b` | yes | yes | no | no (fix held) |
| `qwen2.5-coder:3b` | yes | yes | no | no (fix held) |
| `qwen2.5-coder:1.5b` | yes | yes | no | no (fix held) |
