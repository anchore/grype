// Command httpserver is a test fixture: a Go program that runs an HTTP server.
// It references the net/http server entrypoints (and, via ListenAndServeTLS,
// the bundled HTTP/2 server code) that GO-2022-0969 lists as vulnerable, so the
// compiled binary carries those symbols and must MATCH the stdlib advisory.
package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	})
	// server-side entrypoints; the TLS variant pulls in the bundled http2 server code.
	go func() { log.Fatal(http.ListenAndServe(":8080", nil)) }()
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
}
