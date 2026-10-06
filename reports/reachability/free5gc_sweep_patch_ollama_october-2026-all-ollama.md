# free5GC patch sweep: ollama (1 run(s)/model)

| Model | Compiles | Applied/4 | Cost (USD) | Runtime verdict |
|---|---|---|---|---|
| `deepseek-coder-v2:16b` | NO (generate_patch failed: RuntimeError: Ollama request failed (500): {"error":"llama-server reported out-of-memory during startup: ggml_backend_cpu_buffer_type_alloc_buffer: failed to allocate buffer of size 45298483200\nalloc_tensor_range: failed to allocate CPU buffer of size 45298483200\nllama_init_from_model: failed to initialize the context: failed to allocate buffer for kv cache"}) | 0/4 | n/a | not reached (compile failed) |
| `codellama:13b` | NO (patched source doesn't build) | 4/4 | n/a | not reached (compile failed) |
| `gemma2:9b` | yes | 4/4 | n/a | confirmed_fix_all_four_handlers |
| `mistral:7b` | yes | 4/4 | n/a | confirmed_fix_all_four_handlers |
| `llama3.1:8b` | yes | 4/4 | n/a | confirmed_fix_all_four_handlers |
| `qwen2.5-coder:7b` | yes | 4/4 | n/a | confirmed_fix_all_four_handlers |
| `qwen2.5-coder:3b` | yes | 4/4 | n/a | confirmed_fix_all_four_handlers |
| `qwen2.5-coder:1.5b` | NO (patched source doesn't build) | 4/4 | n/a | not reached (compile failed) |
