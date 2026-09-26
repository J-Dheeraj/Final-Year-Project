# Stronger patch reassessment (2026-09-26)

Step 2 of the post-review roadmap: reassess saved patches with a proper,
class-specific success test (real expected content on both the malicious
and legitimate request), not the corrected validator's own weaker
crash-absence check (Section 4.1.2 of the FYP report, and the external
review that prompted it).

## What could actually be reassessed

The 36-run hosted-Claude comparison's own artifact writer (Stage 3.5/3.8)
hardcodes a shared, non-model-specific scratch path
(`reports/claude_code_catalog_run_2026-09-25/reports/<CVE-ID>/`) regardless
of each run's own `--out` destination - a harness gap found while trying to
locate the saved patches for this reassessment, not previously documented.
Every model that touched the same CVE overwrote the same file. Only **6
patched targets survive on disk, one per CVE** (whichever model happened to
run last for it), not 36. CVE-2026-46492's survivor was identified as
`claude-opus-4-8`'s own patch via its unique `generation_output_tokens=14789`
fingerprint, cross-referenced against file mtimes; the other five CVEs'
survivors could not be attributed to a specific model with the same
confidence and are reported as "last writer, model unknown."

## Test design

For each of the 6 CVEs, a real expected malicious result and a real expected
legitimate result were defined by reading the actual generated target/PoC
source (not assumed):

| CVE | Malicious request | Expected (patched) | Legitimate request | Expected response |
|---|---|---|---|---|
| CVE-2026-42208 (SQLi) | `Authorization: Bearer ' OR '1'='1'--` | No marker in response | `Authorization: Bearer sk-legit-user-001` | `{"status":"authenticated","user_id":"u1"}` |
| CVE-2026-27602 (OS CmdI) | `domain_name=legit.com; echo PWNED...` | No marker in response | `domain_name=example.com` | `{"output":"domain created successfully",...}` |
| CVE-2026-23949 (Path Trav.) | `member=../../../srv/config/.env` | No marker in response | `member=readme.txt` | `{"data":"example extracted file"}` |
| CVE-2026-78683 (Deserial.) | pickled `__reduce__` RCE gadget | No marker in response | pickled plain `dict` | `{"status":"loaded","object_type":"dict"}` |
| CVE-2026-54729 (SSRF) | `url=http://0.0.0.0/latest/meta-data/` | No marker in response | `url=http://example.com` | `{"fetched":...,"internal":false,"data":"<html>external site</html>"}` |
| CVE-2026-46492 (XSS) | `content=# Shared Note\n\n<script>...` | No marker in response | `content=# Hello\nWorld` | Exact `<h1>Hello</h1>` / `<p>World</p>`, no marker |

Each surviving patched target was started fresh, sent the malicious request
first, then the legitimate request, and both real HTTP responses were
checked against the table above - not merely "did the process crash."

## Results

| CVE | Exploit blocked | Legit preserved (content-verified) | Verdict | Malicious status | Legit status |
|---|---|---|---|---|---|
| CVE-2026-42208 | True | True | `confirmed_fix` | 401 | 200 |
| CVE-2026-27602 | True | True | `confirmed_fix` | 400 | 200 |
| CVE-2026-23949 | True | True | `confirmed_fix` | 400 | 200 |
| CVE-2026-78683 | True | True | `confirmed_fix` | 400 | 200 |
| CVE-2026-54729 | True | True | `confirmed_fix` | 403 | 200 |
| CVE-2026-46492 | True | True | `confirmed_fix` | 200 | 200 |

**All 6 surviving patches pass this stronger test.** Every malicious
request now gets a clean, class-appropriate rejection (401/403/400 -
never the same 200-with-marker the vulnerable version returns), and every
legitimate request gets exactly its expected 200 response, not merely a
crash-free one.

## A real, distinct finding surfaced while building this test: CVE-2026-46492

The corrected validator's own recorded verdict for `claude-opus-4-8` on this
CVE was `not_blocked` (every one of the 6 models scored `not_blocked` on
this CVE in the original 36-run comparison). Direct testing here shows the
patch's `html.escape()` fix is genuinely correct against the PoC's default
`<script>` payload. Reading the original run's own `patch_validation_log`
explains the discrepancy: the pipeline's multi-payload bypass check tried
an alternate payload, `# Report<img src=x onerror=alert(...)>`, which the
target's own *self-check* - a regex over its rendered (already-escaped)
output looking for the literal substring pattern `\son\w+\s*=` - matches
even though the actual `<img>` tag itself was escaped to inert text
(`&lt;img src=x onerror=...&gt;`) and would never execute in a real
browser. This is a fidelity limitation of the generated target's own
"did injected script execute" self-check (checking rendered text for a
keyword pattern rather than truly simulating browser parsing), not a real
bypass of the escape-based fix - worth flagging precisely because it shows
the multi-payload bypass mechanism can itself return a false positive on a
synthetic target whose own vulnerability-signalling logic doesn't account
for escaping. Not fixed here (it is a property of how these six targets are
generated, out of scope for a same-day reassessment) - reported as a
finding, not folded silently into the numbers above.

## What this does and does not establish

- **Does**: show that, for these 6 concrete surviving patches specifically,
  a real, content-verified functional-preservation test - not just
  crash-absence - confirms both correct exploit-blocking and correct
  legitimate behaviour. This is real, positive evidence strengthening
  exactly the gap the external review identified in the corrected
  validator's own benign-probe check.
- **Does not**: generalise to the other 30 of 36 original attempts, whose
  patched source no longer exists on disk (overwritten by the shared-path
  bug above) and cannot be reassessed without paying for fresh generation.
  Nor does it establish that this stronger test methodology, applied to a
  *fresh* full 36-run sweep, would find the same 100% pass rate - these 6
  survivors are not a random or representative sample of the 36 (they are
  whichever model happened to finish last for each CVE, a mix of the 6
  models compared).

Raw log: `reports/patch_reassessment_2026-09-26/raw_log.txt`.
Test script (reusable, reads real expected output per class, not a stub):
`reports/patch_reassessment_2026-09-26/stronger_reassessment.py`.
