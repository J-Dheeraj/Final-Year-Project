# Final demonstration checklist (10-15 minutes)

1. Identify the pinned repository commit/tag (`fyp-rd-freeze-2026-10-13-final-v6`) and explain the research questions. (Eleven earlier tags, from 2026-10-10 through 2026-10-13, are now stale; the most recent supersession closes the last gap from the release-hardening review - CI's own `pip-audit` install is now hash-pinned via `requirements-ci.lock.txt` (`pip install --require-hashes -r requirements-ci.lock.txt`), confirmed directly in GitHub Actions' own raw run logs, not just locally, since v5 was pushed one commit short of this. v5 itself (still current in all other respects) renamed the generic Stage 3.8 verdict from `confirmed_fix` to `heuristic_fix_screened`, added a stricter additive benign-probe HTTP-status signal (`patch_function_preserved_strict`) catching a deleted route's clean 404, tightened the multi-payload re-probe to reject on even one untested variant, caught a `subprocess.Popen` failure that escaped this pipeline's "never raises" contract, digest-pinned and hardened the UDR Dockerfile, hash-locked every dependency and fixed 17 real CVEs in `pydantic-ai`, and locked down CI with read-only permissions and a hash-verified install. See `docs/PROJECT_STATUS.md`'s session log for the full history. No thesis content changed in this or the v5 supersession. Always use the newest tag for any demo or submission, and check `git tag -l 'fyp-rd-freeze-*'` if in doubt which is newest.)
2. Show the vulnerable free5GC UDR behavior for unauthorized read, collection read, write, and delete.
3. Show one OpenAI-generated patch and its preserved run ID.
4. Show Go compilation and the Docker image used for validation.
5. Demonstrate runtime confirmation across all four handlers.
6. Send a benign request and show that legitimate behavior remains available.
7. Show a compile-failing GPT-5.2 patch and explain why it is rejected.
8. Show the OpenAI bypass reports: zero genuine bypasses after the stricter XSS validator.
9. Show the repeatability table and the final evidence summary.
10. Close with limitations, cost/token accounting, and post-R&D work (including the OAuth2-enforcement follow-up, "Final evidence freeze and interpretation": OAuth2 blocks a fully unauthenticated caller but provides no additional protection against this CVE once a caller holds any validly-scoped token, so the real fix remains necessary even in an OAuth2-enforced deployment).

Keep raw JSON reports and logs open in a second window so every headline number can be traced to evidence.


## Final targeted evidence note

The Claude/AIxTech prompt-cache sensitivity study used unique no-op markers and found no byte-identical convergence across successful variants. The latest OpenAI controlled-repeat attempt was authentication-limited (HTTP 401) and is shown as an environment limitation, not a model failure.
