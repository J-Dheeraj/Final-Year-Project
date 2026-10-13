# Final demonstration checklist (10-15 minutes)

1. Identify the pinned repository commit/tag (`fyp-rd-freeze-2026-10-13-final-v3`) and explain the research questions. (Eight earlier tags, from 2026-10-10 through 2026-10-13, are now stale and superseded in sequence by content fixes documented in `docs/PROJECT_STATUS.md`'s session log; the most recent supersession fixes two bugs in the browser-level XSS validator (`browser_xss_replay.py`) - an async-execution blind spot (the instrumented result was recorded before a delayed payload could fire) and a failed Chrome run being silently read as a negative result rather than inconclusive - verified against real Chrome and re-run across all 33 historical raw-positive proposals with the same "zero genuine bypasses" result as before, plus a correction to a stale claim in `DEFENSE_PREP.md`/`SCOPE_AND_LIMITATIONS.md` that `/health` alone would catch a deleted vulnerable route (it is a separate, independent endpoint; the corrected validator's same-route benign probe is what actually closes that gap), and a stale tag reference fixed in `docs/REPRODUCTION_RECORD_2026-10-10.md`. No thesis content changed in this supersession. Always use the newest tag for any demo or submission, and check `git tag -l 'fyp-rd-freeze-*'` if in doubt which is newest.)
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
