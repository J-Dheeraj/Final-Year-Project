// Minimal stand-in for the real NRF: satisfies exactly the one call this
// runtime-validation case needs (PUT .../nf-instances/{id}, i.e.
// RegisterNFInstance) so UDR's blocking registration retry loop
// (internal/sbi/consumer/nrf_service.go's SendRegisterNFInstance) can
// succeed and let UDR proceed to its own HTTP server startup.
//
// This is NOT a real NRF and makes no claim to be: it does not perform
// discovery, does not track other NFs, and has no bearing on the
// vulnerability under test (the data-repository DELETE handler's own
// missing `return`), which is entirely independent of NRF's behaviour.
//
// It must speak HTTP/2 cleartext (h2c): free5gc's NRF client
// (github.com/free5gc/openapi's innerHTTP2CleartextClient) uses
// golang.org/x/net/http2 with AllowHTTP: true and dials with prior
// knowledge of HTTP/2 framing. A plain HTTP/1.1 server (e.g. Python's
// http.server) cannot answer this client - it produces "http2: frame
// too large" client-side, since the client parses the HTTP/1.1 response
// bytes as if they were HTTP/2 frames.
package main

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body := map[string]string{
			"nfInstanceId": "stub-nrf-nf-instance",
			"nfType":       "UDR",
			"nfStatus":     "REGISTERED",
		}
		payload, _ := json.Marshal(body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", r.URL.Path)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(payload)
	})

	h2s := &http2.Server{}
	server := &http.Server{
		Addr:    "127.0.0.10:8000",
		Handler: h2c.NewHandler(mux, h2s),
	}
	log.Println("stub NRF (h2c) listening on 127.0.0.10:8000")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
