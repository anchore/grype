// Command gjson-valid is a test fixture: a Go program that uses only
// gjson.Valid — not Get, GetBytes, GetMany, GetManyBytes, Result.Get, or any
// other symbol GO-2021-0265 lists as vulnerable for github.com/tidwall/gjson.
// It links the same vulnerable gjson version as gobin-gjson-get, so before
// symbol matching grype flagged it; the compiled binary carries none of the
// vulnerable symbols, so it must NOT match the advisory.
package main

import (
	"fmt"

	"github.com/tidwall/gjson"
)

func main() {
	fmt.Println(gjson.Valid(`{"name":{"first":"Janet","last":"Prichard"},"age":47}`))
}
