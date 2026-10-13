# Final demonstration checklist (10-15 minutes)

1. Identify the pinned repository commit/tag (`fyp-rd-freeze-2026-10-13-final-v4`) and explain the research questions. (Nine earlier tags, from 2026-10-10 through 2026-10-13, are now stale and superseded in sequence by content fixes documented in `docs/PROJECT_STATUS.md`'s session log; the most recent supersession, prompted by an independent deep-inspection review, fixes cve_id/run_id path traversal in artifact paths, a GraphQL query built by string interpolation instead of variables, every exploit template silently ignoring the benign/alternate-payload override (so Stage 3.8's benign probe and multi-payload check were untested no-ops for template-generated patches), and two import-time bugs (module-level `logging.basicConfig()` and an unconditional `sys.stdout` reassignment) that had silently prevented this project's own code from ever being imported under pytest before; adds 35 passing tests (up from 10, covering the patch validator, the watcher, and the new fixes), a pinned `requirements.txt`, a green CI workflow, an opt-out `UNSANDBOXED_EXEC=0` kill switch for generated-code execution, and corrects a stale scope-summary-table claim plus the Windows pytest temp-directory issue (now a real project-local-temp-dir fix, not just a documented workaround). No thesis content changed in this supersession. Always use the newest tag for any demo or submission, and check `git tag -l 'fyp-rd-freeze-*'` if in doubt which is newest.)
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
