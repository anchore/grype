// Command httpclient is a test fixture: a Go program that only makes HTTP
// *client* calls. It links net/http but references none of the server
// entrypoints GO-2022-0969 lists as vulnerable, so the compiled binary lacks
// those symbols and must NOT match the stdlib server advisory (the false
// positive grype produced before symbol matching). It still links runtime, so
// it correctly matches the package-scoped GO-2023-1840 (runtime) advisory.
package main

import (
	"fmt"
	"io"
	"net/http"
)

func main() {
	resp, err := http.Get("https://example.com")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	_, _ = http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(len(b))
}
