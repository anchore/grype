package java

import (
	"context"
	"errors"

	"github.com/anchore/grype/grype/pkg"
)

// mockMavenSearcher is an HTTP adapter stand-in for a real
// search.maven.org client. It is not a vulnerability mock - the
// vulnerability data flows in from a real built v6 DB. We mock the
// network because the test suite must not hit search.maven.org. The
// equivalent test that does hit the live API is in
// matcher_integration_test.go behind the `api_limits` build tag.
type mockMavenSearcher struct {
	pkg                  pkg.Package
	simulateRateLimiting bool
}

func (m mockMavenSearcher) GetMavenPackageBySha(context.Context, string) (*pkg.Package, error) {
	if m.simulateRateLimiting {
		return nil, errors.New("you been rate limited")
	}
	return &m.pkg, nil
}
