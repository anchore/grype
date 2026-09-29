// Command xnet-html is a test fixture: a Go program that uses
// golang.org/x/net/html but none of the golang.org/x/net/http2 server symbols
// GO-2022-0969 lists as vulnerable. It links golang.org/x/net at a vulnerable
// version, so before symbol matching grype flagged it; the compiled binary
// carries no vulnerable http2 symbols, so it must NOT match the x/net advisory.
package main

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

func main() {
	doc, err := html.Parse(strings.NewReader("<p>hi</p>"))
	if err != nil {
		return
	}
	fmt.Println(doc.Type)
}
