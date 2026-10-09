# free5GC patch sweep: openai (1 run(s)/model)

| Model | Compiles | Applied/4 | Cost (USD) | Runtime verdict |
|---|---|---|---|---|
| `gpt-3.5-turbo` | yes | 4/4 | $0.0008 | confirmed_fix_all_four_handlers |
| `gpt-3.5-turbo-0125` | yes | 4/4 | $0.0008 | confirmed_fix_all_four_handlers |
| `gpt-3.5-turbo-1106` | NO (generate_patch failed: NotFoundError: Error code: 404 - {'error': {'message': 'The model `gpt-3.5-turbo-1106` has been deprecated, learn more here: https://platform.openai.com/docs/deprecations', 'type': 'invalid_request_error', 'param': None, 'code': 'model_not_found'}}) | 0/4 | n/a | not reached (compile failed) |
| `gpt-4` | yes | 4/4 | $0.0353 | confirmed_fix_all_four_handlers |
| `gpt-4-turbo` | NO (patched source doesn't build) | 4/4 | $0.0143 | not reached (compile failed) |
| `gpt-4o` | yes | 4/4 | $0.0047 | confirmed_fix_all_four_handlers |
