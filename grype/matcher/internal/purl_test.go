package internal

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
)

func newPURLTestStore() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		// TODO: Add test cases.
	}...)
}

func TestMatchPackageByPURL(t *testing.T) {
	matcher := match.BitnamiMatcher
	tests := []struct {
		name     string
		p        pkg.Package
		expected []match.Match
		wantErr  require.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := MatchPackageByPURL(newPURLTestStore(), test.p, matcher)
			if test.wantErr == nil {
				test.wantErr = require.NoError
			}
			test.wantErr(t, err)
			assertMatchesUsingIDsForVulnerabilities(t, test.expected, actual)
			for idx, e := range test.expected {
				if idx < len(actual) {
					if d := cmp.Diff(e.Details, actual[idx].Details); d != "" {
						t.Errorf("unexpected match details (-want +got):\n%s", d)
					}
				} else {
					t.Errorf("expected match details (-want +got)\n%+v:\n", e.Details)
				}
			}
		})
	}
}
