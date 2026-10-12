# Final demonstration checklist (10-15 minutes)

1. Identify the pinned repository commit/tag (`fyp-rd-freeze-2026-10-12-final`) and explain the research questions. (Three earlier tags are now stale: `fyp-rd-freeze-2026-10-10-thesis` predates the OpenEMR case, the methodology worksheet, and the literature-review additions; `fyp-rd-freeze-2026-10-11-thesis-final` predates 3 further citations, the CRAAP source evaluation, the grey-literature classification, the Acknowledgements/Project Schedule sections, and the ProvTrail integration; `fyp-rd-freeze-2026-10-11-final-v2` predates the em-dash removal and all fixes from the independent evidence review (screening-pass column rename, cost-rounding footnote, six-survivor table, CVE-attribution wording, and the four-stages/four-phases disambiguation) — use the newest tag for any demo or submission.)
2. Show the vulnerable free5GC UDR behavior for unauthorized read, collection read, write, and delete.
3. Show one OpenAI-generated patch and its preserved run ID.
4. Show Go compilation and the Docker image used for validation.
5. Demonstrate runtime confirmation across all four handlers.
6. Send a benign request and show that legitimate behavior remains available.
7. Show a compile-failing GPT-5.2 patch and explain why it is rejected.
8. Show the OpenAI bypass reports: zero genuine bypasses after the stricter XSS validator.
9. Show the repeatability table and the final evidence summary.
10. Close with limitations, cost/token accounting, and post-R&D work.

Keep raw JSON reports and logs open in a second window so every headline number can be traced to evidence.


## Final targeted evidence note

The Claude/AIxTech prompt-cache sensitivity study used unique no-op markers and found no byte-identical convergence across successful variants. The latest OpenAI controlled-repeat attempt was authentication-limited (HTTP 401) and is shown as an environment limitation, not a model failure.
