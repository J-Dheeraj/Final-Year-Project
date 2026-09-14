// udr_lab.go — a minimal, dependency-free reproduction of a real, disclosed
// free5GC vulnerability: CVE-2026-40246 / GHSA-g9cw-qwhf-24jp.
//
// Real bug (free5GC UDR <= 1.4.2, DeleteInfluenceSubscription handler): the
// handler checks whether the `influenceId` path segment equals the literal
// string "subs-to-notify" and writes an HTTP 404 when it doesn't - but never
// returns after writing that response, so execution falls through and the
// subscription is deleted from the store regardless of the check's outcome.
// An unauthenticated attacker on the 5G Service Based Interface can delete
// ANY Traffic Influence Subscription this way, while the API misleadingly
// reports 404 Not Found either way - which is what makes it hard to notice
// in logs/monitoring, not just a security bug but a "the audit trail lies"
// bug.
//
// This file reproduces that exact control-flow bug in a minimal standalone
// server, not the real free5GC UDR (see docs/FREE5GC_LAB.md for exactly
// what is and isn't a faithful reproduction). Toggle with LAB_MODE=vulnerable
// or LAB_MODE=patched (default: patched, same convention as ssrf_lab).
//
// Run: go run udr_lab.go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	mu            sync.Mutex
	subscriptions = map[string]bool{"sub-001": true, "sub-002": true, "sub-003": true}
	mode          = "patched" // "vulnerable" or "patched"
)

func init() {
	if v := os.Getenv("LAB_MODE"); v == "vulnerable" {
		mode = "vulnerable"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok", "cve": "CVE-2026-40246"})
}

func modeHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	if r.Method == http.MethodPost {
		var body struct{ Mode string `json:"mode"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil &&
			(body.Mode == "vulnerable" || body.Mode == "patched") {
			mode = body.Mode
		}
	}
	writeJSON(w, 200, map[string]string{"mode": mode})
}

func subscriptionsHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	ids := make([]string, 0, len(subscriptions))
	for id := range subscriptions {
		ids = append(ids, id)
	}
	writeJSON(w, 200, map[string]any{"subscriptions": ids})
}

// deleteInfluenceSubscriptionVulnerable is the real, disclosed bug: no
// `return` after the 404 write, so a mismatched influenceId still falls
// through to the delete below.
func deleteInfluenceSubscriptionVulnerable(w http.ResponseWriter, influenceId string) {
	if influenceId != "subs-to-notify" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		// VULNERABLE (CVE-2026-40246): missing `return` here.
	}
	delete(subscriptions, influenceId)
	w.WriteHeader(http.StatusNoContent)
}

func deleteInfluenceSubscriptionPatched(w http.ResponseWriter, influenceId string) {
	if influenceId != "subs-to-notify" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return // PATCHED: stop here on validation failure.
	}
	delete(subscriptions, influenceId)
	w.WriteHeader(http.StatusNoContent)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	const prefix = "/nudr-dr/v2/subscription-data/influenceData/"
	influenceId := strings.TrimPrefix(r.URL.Path, prefix)
	if influenceId == "" || influenceId == r.URL.Path {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing influenceId"})
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if mode == "vulnerable" {
		deleteInfluenceSubscriptionVulnerable(w, influenceId)
	} else {
		deleteInfluenceSubscriptionPatched(w, influenceId)
	}
}

func main() {
	port := os.Getenv("LAB_PORT")
	if port == "" {
		port = "8090"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /mode", modeHandler)
	mux.HandleFunc("POST /mode", modeHandler)
	mux.HandleFunc("GET /subscriptions", subscriptionsHandler)
	mux.HandleFunc("DELETE /nudr-dr/v2/subscription-data/influenceData/", deleteHandler)

	log.Printf("free5GC UDR lab (CVE-2026-40246 repro) on :%s, mode=%s", port, mode)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, mux))
}
