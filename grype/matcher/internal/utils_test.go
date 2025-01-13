package internal

import (
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

func assertMatchesUsingIDsForVulnerabilities(t testing.TB, expected, actual []match.Match) {
	t.Helper()
	assert.Len(t, actual, len(expected))
	for idx, a := range actual {
		// only compare the vulnerability ID, nothing else
		a.Vulnerability = vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: a.Vulnerability.ID}}
		for _, d := range deep.Equal(expected[idx], a) {
			t.Errorf("diff idx=%d: %+v", idx, d)
		}
	}
}
