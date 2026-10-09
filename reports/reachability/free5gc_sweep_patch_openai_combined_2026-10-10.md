# free5GC OpenAI patch sweep (combined 2026-10-10)

23 model IDs attempted across the initial, continuation, and final single-model runs.

- Runtime-confirmed across all four handlers: **18**
- Compiled patches: **18**
- Compile failures: **5**
- Generation/API failures: **1**
- Total model-call runtime: **125.77 s**
- Input/output tokens: **11,284 / 9,141**
- Estimated cost for priced IDs: **US$0.0603**

| Model | Compiles | Runtime verdict | Error |
|---|---|---|---|
| `gpt-3.5-turbo` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-3.5-turbo-0125` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-3.5-turbo-1106` | no | `not reached` | generate_patch failed: NotFoundError: Error code: 404 - {'error': {'message': 'The model `gpt-3.5-turbo-1106` has been d |
| `gpt-4` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-4-turbo` | no | `not reached` | patched source doesn't build |
| `gpt-4o` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-5` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-5-mini` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-5-nano` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-5.1` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-5.2` | no | `not reached` | patched source doesn't build |
| `gpt-5.4` | no | `not reached` | patched source doesn't build |
| `gpt-5.4-mini` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-5.6-luna` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-5.6-sol` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-5.6-terra` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-6-astra` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-6.1-sol` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-6-luna` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-6-sol` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-4.1-mini` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-4.1-nano` | yes | `confirmed_fix_all_four_handlers` |  |
| `gpt-4.1` | no | `not reached` | patched source doesn't build |
