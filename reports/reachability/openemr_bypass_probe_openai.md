# OpenEMR bypass-probe (openai): admin.php's real fix

| Model | Proposal parsed | Bypass confirmed | Cost (USD) |
|---|---|---|---|
| `gpt-3.5-turbo` | yes | no (fix held) | $0.0003 |
| `gpt-3.5-turbo-0125` | yes | no (fix held) | $0.0002 |
| `gpt-3.5-turbo-1106` | NO (NotFoundError: Error code: 404 - {'error': {'message': 'The model `gpt-3.5-turbo-1106` has been deprecated, learn more here: https://platform.openai.com/docs/deprecations', 'type': 'invalid_request_error', 'param': None, 'code': 'model_not_found'}}) | no (fix held) | n/a |
| `gpt-4` | yes | no (fix held) | $0.0145 |
| `gpt-4-turbo` | yes | no (fix held) | $0.0054 |
| `gpt-4o` | yes | no (fix held) | $0.0016 |
| `gpt-4.1` | yes | no (fix held) | $0.0015 |
| `gpt-4.1-mini` | yes | no (fix held) | $0.0002 |
| `gpt-4.1-nano` | yes | no (fix held) | $0.0001 |
| `gpt-5` | yes | no (fix held) | n/a |
| `gpt-5-mini` | yes | no (fix held) | n/a |
| `gpt-5-nano` | yes | no (fix held) | n/a |
| `gpt-5.1` | yes | no (fix held) | n/a |
| `gpt-5.2` | yes | no (fix held) | n/a |
| `gpt-5.4` | yes | no (fix held) | n/a |
| `gpt-5.4-mini` | yes | no (fix held) | n/a |
| `gpt-5.6-luna` | yes | no (fix held) | n/a |
| `gpt-5.6-sol` | NO (BadRequestError: Error code: 400 - {'error': {'message': 'This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. To get authorized for security work, join the Trusted Access for Cyber program: https://chatgpt.com/cyber', 'type': 'invalid_request_error', 'param': None, 'code': 'cyber_policy'}}) | no (fix held) | n/a |
| `gpt-5.6-terra` | yes | no (fix held) | n/a |
| `gpt-6-astra` | yes | no (fix held) | n/a |
| `gpt-6.1-sol` | NO (BadRequestError: Error code: 400 - {'error': {'message': 'This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. To get authorized for security work, join the Trusted Access for Cyber program: https://chatgpt.com/cyber', 'type': 'invalid_request_error', 'param': None, 'code': 'cyber_policy'}}) | no (fix held) | n/a |
| `gpt-6-luna` | yes | no (fix held) | n/a |
| `gpt-6-sol` | yes | no (fix held) | n/a |
