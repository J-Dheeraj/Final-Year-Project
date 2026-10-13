# Final demonstration checklist (10-15 minutes)

1. Identify the pinned repository commit/tag (`fyp-rd-freeze-2026-10-13-final-v5`) and explain the research questions. (Ten earlier tags, from 2026-10-10 through 2026-10-13, are now stale and superseded in sequence by content fixes documented in `docs/PROJECT_STATUS.md`'s session log; the most recent supersession, prompted by a further independent deep-inspection review, renames the generic Stage 3.8 verdict from `confirmed_fix` to `heuristic_fix_screened` and adds a stricter, additive benign-probe HTTP-status signal (`patch_function_preserved_strict`) that catches a deleted route's clean 404 where the crash-only check alone could not - verified empirically, reproducing the exact gap; tightens the multi-payload re-probe to reject when even one declared alternate payload wasn't actually tested, not just when all of them weren't; catches a `subprocess.Popen` failure that previously escaped this pipeline's own "never raises" contract; pins both UDR Dockerfile base images by digest, validates `UDR_COMMIT` injection-safely (verified against real Docker with a crafted payload), and runs the image as non-root; hash-locks every dependency (`requirements.lock.txt`, verified installable and cross-platform) and fixes 17 real CVEs `pip-audit` found in `pydantic-ai`, cutting its dependency footprint from 157 packages to 47; and locks down CI with read-only permissions, a hash-verified install, and a hash-pinned `pip-audit` step - all independently confirmed green on GitHub Actions, not just locally. No thesis content changed in this supersession. Always use the newest tag for any demo or submission, and check `git tag -l 'fyp-rd-freeze-*'` if in doubt which is newest.)
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
