package common

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/go-test/deep"
)

func assertMatchesUsingIDsForVulnerabilities(t testing.TB, expected, actual []match.Match) {
	for idx, a := range actual {
		// only compare the vulnerability ID, nothing else
		a.Vulnerability = vulnerability.Vulnerability{ID: a.Vulnerability.ID}
		for _, d := range deep.Equal(expected[idx], a) {
			t.Errorf("diff idx=%d: %+v", idx, d)
		}
	}
}
