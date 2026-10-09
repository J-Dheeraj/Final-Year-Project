# free5GC memorization control (aixtech): synthetic, never-disclosed bug

Target: `HandleCreateAuthenticationStatus` (NOT one of the four real CVE-2026-40248 handlers) - same bug class, injected fresh by this experiment.

| Model | Compiles (fixes the synthetic bug) | Cost (USD) |
|---|---|---|
| `claude-haiku-4-5-20251001` | yes | n/a |
| `claude-haiku-5-5` | yes | n/a |
| `claude-sonnet-4-6` | yes | n/a |
| `claude-sonnet-5` | yes | n/a |
| `claude-sonnet-5-5` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-sonnet-5-5' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | n/a |
| `claude-opus-4-6` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-4-6' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | n/a |
| `claude-opus-4-7` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-4-7' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | n/a |
| `claude-opus-4-8` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-4-8' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | n/a |
| `claude-opus-5` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-5' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | n/a |
| `claude-opus-5-5` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-5-5' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | n/a |
