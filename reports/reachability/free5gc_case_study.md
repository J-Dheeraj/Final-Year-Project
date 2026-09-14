# reachcrs report

## Reachability filtering
- 102 functions parsed
- 4 reachable from stated entry points (96.1% reduction in analysis scope)

## Triage
- 4 reachable units analyzed
- 4 flagged as potentially vulnerable
- 4 survived adversarial verification

## Exploit (proof-of-vulnerability, before any patch is generated)
- 0 confirmed by a generated exploit that actually reproduced the bug
- 0 held back from patch generation: the generated exploit compiled and ran but did NOT reproduce it

## Findings

### `HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdPut` — CWE-285 (C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go:1236)
- verify confidence: 0.60
- rationale: This `if` block writes an HTTP response (looks like an early-exit / validation-failure path) but never returns, and the function keeps executing afterward - so the response sent to the client doesn't reflect what actually happens next (same bug class as CVE-2026-40248 in free5GC's UDR).
- exploit: not generated | reproduced pre-patch: None
- patch method: `mock-rule-based`
- compiler available: False | original compiles: None | patched compiles: None
- PoC on original crashed: None | PoC on patched crashed: None
- **fix confirmed (bug reproduced pre-patch AND gone post-patch): None**

```diff
--- a/C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go::HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdPut
+++ b/C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go::HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdPut
@@ -2,6 +2,7 @@
 	influenceId := c.Param("influenceId")
 	if influenceId != "subs-to-notify" {
 		c.String(http.StatusNotFound, "404 page not found")
+		return
 	}
 
 	// Get HTTP request body
```

### `HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet` — CWE-285 (C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go:1222)
- verify confidence: 0.60
- rationale: This `if` block writes an HTTP response (looks like an early-exit / validation-failure path) but never returns, and the function keeps executing afterward - so the response sent to the client doesn't reflect what actually happens next (same bug class as CVE-2026-40248 in free5GC's UDR).
- exploit: not generated | reproduced pre-patch: None
- patch method: `mock-rule-based`
- compiler available: False | original compiles: None | patched compiles: None
- PoC on original crashed: None | PoC on patched crashed: None
- **fix confirmed (bug reproduced pre-patch AND gone post-patch): None**

```diff
--- a/C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go::HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet
+++ b/C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go::HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet
@@ -4,6 +4,7 @@
 	influenceId := c.Param("influenceId")
 	if influenceId != "subs-to-notify" {
 		c.String(http.StatusNotFound, "404 page not found")
+		return
 	}
 
 	subscriptionId := c.Params.ByName("subscriptionId")
```

### `HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete` — CWE-285 (C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go:1208)
- verify confidence: 0.60
- rationale: This `if` block writes an HTTP response (looks like an early-exit / validation-failure path) but never returns, and the function keeps executing afterward - so the response sent to the client doesn't reflect what actually happens next (same bug class as CVE-2026-40248 in free5GC's UDR).
- exploit: not generated | reproduced pre-patch: None
- patch method: `mock-rule-based`
- compiler available: False | original compiles: None | patched compiles: None
- PoC on original crashed: None | PoC on patched crashed: None
- **fix confirmed (bug reproduced pre-patch AND gone post-patch): None**

```diff
--- a/C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go::HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete
+++ b/C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go::HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete
@@ -4,6 +4,7 @@
 	influenceId := c.Param("influenceId")
 	if influenceId != "subs-to-notify" {
 		c.String(http.StatusNotFound, "404 page not found")
+		return
 	}
 
 	subscriptionId := c.Params.ByName("subscriptionId")
```

### `HandleApplicationDataInfluenceDataSubsToNotifyGet` — CWE-285 (C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go:2739)
- verify confidence: 0.60
- rationale: This `if` block writes an HTTP response (looks like an early-exit / validation-failure path) but never returns, and the function keeps executing afterward - so the response sent to the client doesn't reflect what actually happens next (same bug class as CVE-2026-40248 in free5GC's UDR).
- exploit: not generated | reproduced pre-patch: None
- patch method: `mock-rule-based`
- compiler available: False | original compiles: None | patched compiles: None
- PoC on original crashed: None | PoC on patched crashed: None
- **fix confirmed (bug reproduced pre-patch AND gone post-patch): None**

```diff
--- a/C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go::HandleApplicationDataInfluenceDataSubsToNotifyGet
+++ b/C:\Users\dheer\Downloads\AI-exploit-CVE\src\reachability\examples\free5gc_case_study\api_datarepository_vulnerable.go::HandleApplicationDataInfluenceDataSubsToNotifyGet
@@ -17,6 +17,7 @@
 			c.Set(sbi.IN_PB_DETAILS_CTX_STR, http.StatusText(int(problemDetails.Status)))
 			c.JSON(http.StatusBadRequest, problemDetails)
 		}
+		return
 	}
 
 	if dnn == "" && snssai == nil && internalGroupId == "" && supi == "" {
```

## Timing
- reachability: 0.017s
- triage: 0.002s
- verify: 0.001s
- exploit: 0.000s
- patch: 0.000s
- test: 0.000s