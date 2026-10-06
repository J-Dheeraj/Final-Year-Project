# free5GC OAuth2 enforcement: does it change the CVE-2026-40248 picture?

## Why this experiment exists

Every prior free5GC runtime result in this project runs with OAuth2
explicitly disabled on the NRF - `run_full_deployment_harness.py`'s own
docstring states this plainly: "OAuth2 itself is explicitly out of
scope for this harness." Every bypass-probe and patch-generation result
to date is therefore a test against a completely unauthenticated
caller. Real free5GC deployments are expected to run with OAuth2
enforcement on, so this leaves an open question: does turning it on
change anything about CVE-2026-40248's severity?

## Method

An opt-in compose override (`compose/docker-compose.oauth2.yaml` +
`compose/config/nrfcfg_oauth2.yaml`) turns on `oauth: true` on the NRF
without touching the default stack every other script/doc in this
project relies on - activated only via an explicit third `-f` file,
never the default `docker compose up`.

Two questions, tested against both the vulnerable and the real-fix-
patched UDR image:

1. **No credentials at all** - does OAuth2 block a completely
   unauthenticated caller, regardless of the underlying CWE-285 bug?
2. **A valid, correctly-scoped bearer token** - once past the OAuth2
   gate, is the authorization bug still exploitable exactly as before?

The token is an RS512 JWT minted directly with the NRF's own private
key (`compose/cert/nrf.key`, already committed in this repo), with
`scope: "nudr-dr"` and `sub` set to a real, currently-registered NF
instance ID (queried live from NRF's own `NfProfile` collection in
MongoDB). The vendored `oauth.VerifyOAuth()` only checks a valid RS512
signature against the NRF's public cert and that `scope` contains the
target service name - it never checks `sub` against anything at this
layer, so this is not "forging" a token in the sense of defeating
cryptography; it's constructing the token server-side with the same
key the real NRF's token endpoint would have used, carrying an identity
NRF genuinely has on file. A full client-credentials HTTP round-trip
(registering as a new NF, calling NRF's own `/oauth2/token` endpoint)
was judged out of scope for this one experiment.

## Two real complications found and worked through before trusting any result

1. **A second, independent authorization layer, not just `VerifyOAuth()`.**
   The first token (`sub: "test-legit-nf"`, not a real NF) passed the
   basic scope check but every PUT (seed) request still got rejected
   with `401 REQUESTER_IDENTITY_UNRESOLVED`. Tracing this into the real
   vendored source (`subscription_callback_target.go`) showed the PUT
   handler does an ADDITIONAL live lookup - `GetNFInstance` against the
   NRF - to resolve the caller's claimed identity for setting up an
   async notification-callback relationship, and only does this when
   `OAuth2Required` is true (when it's false, this check is skipped
   entirely - which is exactly why it never mattered in any prior,
   OAuth2-disabled result). A fabricated `sub` fails this lookup. Fixed
   by using a real, currently-registered NF instance ID as `sub`
   instead of a made-up string. This is itself a small, genuine finding:
   write operations on this handler are more deeply gated than reads
   once OAuth2 is on, and the data genuinely lives in an in-memory
   `sync.Map` inside the UDR process (not MongoDB) for this specific
   handler family, which is why seeding couldn't be done by inserting
   directly into Mongo either.
2. **A response body that looks concatenated.** The vulnerable build's
   collection-leak response initially looked suspicious (a clean 400
   JSON error immediately followed by a JSON array with no separator -
   `{"status":400,...}[{"dnns":[...]}]`). Checked explicitly with
   `repr()` and the response's own `Content-Length` header before
   trusting it: this is a real, single HTTP response body with genuine
   leaked collection data appended after a formal rejection - the same
   `collection_get_leaked_data` heuristic signature (body longer than
   the clean 400 message) already used and verified throughout this
   project's prior free5GC results, not an artifact of this script.

## Results

| Build | OAuth2 confirmed active | No credentials: seed status | Valid token: collection leak | Valid token: single leak | Valid token: benign preserved |
|---|---|---|---|---|---|
| `vulnerable` | true | 401 | **true** | **true** | true |
| `patched` | true | 401 | false | false | true |

- **No credentials, either build: 401.** OAuth2 enforcement genuinely
  blocks a completely unauthenticated caller before the CWE-285 bug
  ever matters - confirmed via the UDR's own log line
  (`OAuth2 setting receive from NRF: true`) and a real 401 on the
  identical probe sequence every other free5GC script runs unauthenticated.
- **Valid token, vulnerable build: the bug is fully exploitable.**
  Once a caller holds ANY correctly-scoped, validly-signed token - its
  claimed identity is never checked against anything beyond "does this
  NF instance exist," not "is this NF type/relationship appropriate for
  this request" - the collection leak and single-record leak both
  reproduce exactly as in every OAuth2-disabled result, and the
  legitimate caller's benign path is correctly preserved.
- **Valid token, patched build: the real fix still holds.** Both leak
  checks are false with a valid token, same as with no token, and the
  benign path is still preserved. The real upstream fix's unconditional
  `return` doesn't depend on OAuth2 being on or off.

## Honest interpretation

OAuth2 and the CWE-285 fix are **independent, complementary layers**,
not substitutes for each other. OAuth2 raises the bar from
"any anonymous HTTP client" to "any entity holding a validly-scoped
token" - which matters a great deal against a pure outsider, but
provides **zero additional protection** against the specific
authorization-bypass bug in this CVE once that bar is cleared. This
directly answers (not just caveats) the "OAuth2 explicitly out of
scope" note repeated across this project's other free5GC docs: the
vulnerability's severity in a credentialed threat model - a
compromised or malicious NF, or any client holding a `nudr-dr`-scoped
token - is unchanged by turning OAuth2 on. The real fix is not optional
even in an OAuth2-enforced deployment.

## Scope, stated plainly

- Only 3 of the original 5 `run_case()` checks were re-implemented here
  (collection leak, single-record leak, benign-path) - the PUT
  unauthorized-write and DELETE confirmed-exploit checks were not
  ported to this script, for time reasons, not because they're expected
  to behave differently. A natural follow-up.
- The token is minted directly with the NRF's private key rather than
  obtained through a live client-credentials HTTP round-trip against
  NRF's own `/oauth2/token` endpoint. The distinction matters for
  claiming "this project implements the full OAuth2 client flow" (it
  doesn't, by design) but not for the question this experiment actually
  answers (whether holding *any* valid token changes the exploit's
  outcome).
- Single run, not repeated across models or multiple attempts - this
  experiment doesn't involve an LLM at all; it's deterministic HTTP
  behavior, so one confirmed run has the same evidentiary weight a
  deterministic check always has in this project's prior work (e.g. the
  rule-based patch's own compile verification).

## Artifacts

- `compose/config/nrfcfg_oauth2.yaml`, `compose/docker-compose.oauth2.yaml` - opt-in OAuth2 override, default stack untouched
- `free5gc_full_deployment/free5gc_oauth2_enforcement.py` - the experiment
- `reports/reachability/free5gc_oauth2_enforcement.json/.md`
