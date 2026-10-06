# free5GC OAuth2 enforcement: does it change the CVE-2026-40248 picture?

| Build | OAuth2 active | No token: seed status | Valid token: collection leak | Valid token: single leak | Valid token: benign preserved |
|---|---|---|---|---|---|
| `vulnerable` | True | 401 | True | True | True |
| `patched` | True | 401 | False | False | True |
