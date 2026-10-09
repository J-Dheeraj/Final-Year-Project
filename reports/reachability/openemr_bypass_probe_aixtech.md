# OpenEMR bypass-probe (aixtech): admin.php's real fix

| Model | Proposal parsed | Bypass confirmed | Cost (USD) |
|---|---|---|---|
| `claude-haiku-4-5-20251001` | yes | no (fix held) | n/a |
| `claude-haiku-5-5` | NO (model did not return parseable JSON) | no (fix held) | n/a |
| `claude-sonnet-4-6` | yes | no (fix held) | n/a |
| `claude-sonnet-5` | NO (JSONDecodeError: Expecting ',' delimiter: line 1 column 80 (char 79)) | no (fix held) | n/a |
| `claude-sonnet-5-5` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-sonnet-5-5' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | no (fix held) | n/a |
| `claude-opus-4-6` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-4-6' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | no (fix held) | n/a |
| `claude-opus-4-7` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-4-7' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | no (fix held) | n/a |
| `claude-opus-4-8` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-4-8' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | no (fix held) | n/a |
| `claude-opus-5` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-5' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | no (fix held) | n/a |
| `claude-opus-5-5` | NO (PermissionDeniedError: Error code: 403 - {'error': {'message': "The requested model 'claude-opus-5-5' is not available for this API key, or the model name is invalid. Check the models available to you and try again.", 'type': 'team_model_access_denied', 'param': 'model', 'code': '403'}}) | no (fix held) | n/a |
