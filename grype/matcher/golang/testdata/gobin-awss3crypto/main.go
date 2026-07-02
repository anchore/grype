// Command awss3crypto is a test fixture: a Go program that calls
// s3crypto.NewDecryptionClient, a vulnerable symbol GO-2022-0635 (CVE-2020-8912)
// lists for github.com/aws/aws-sdk-go. The govulndb record is open-ended
// (introduced: 0, no fix — the module predates Go module versioning), so
// govulncheck reports every aws-sdk-go version as affected, including current
// ones; the aliased GHSA bounds the range at < 1.34.0. This fixture pins a
// CURRENT aws-sdk-go, so after the build-time merge grype must NOT match it —
// the merged record carries the GHSA's bounded range and govulndb's symbols.
package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3crypto"
)

func main() {
	sess := session.Must(session.NewSession())
	client := s3crypto.NewDecryptionClient(sess)
	fmt.Println(client != nil)
}
