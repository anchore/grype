// Command gjson-get is a test fixture: a Go program that calls gjson.Get, one
// of the vulnerable symbols GO-2021-0265 lists for github.com/tidwall/gjson
// (ReDoS via crafted JSON path). It pins a vulnerable gjson version, so with the
// vulnerable symbol present in the compiled binary the advisory must match —
// via the GHSA records once the build-time merge patches them with the symbols.
package main

import (
	"fmt"

	"github.com/tidwall/gjson"
)

func main() {
	value := gjson.Get(`{"name":{"first":"Janet","last":"Prichard"},"age":47}`, "name.last")
	fmt.Println(value.String())
}
