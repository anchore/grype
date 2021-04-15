package common

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/go-test/deep"
	"github.com/scylladb/go-set"
	"github.com/stretchr/testify/assert"
)

func assertMatchesWithoutVulnData(t testing.TB, expected, actual []match.Match) {
	expectedCves := set.NewStringSet()
	for _, e := range expected {
		expectedCves.Add(e.Vulnerability.ID)
	}

	foundCVEs := set.NewStringSet()

	for idx, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		// only compare the vulnerability ID, nothing else
		a.Vulnerability = vulnerability.Vulnerability{ID: a.Vulnerability.ID}

		for _, d := range deep.Equal(expected[idx], a) {
			t.Errorf("diff idx=%d: %+v", idx, d)
		}
	}

	assert.Equal(t, true, expectedCves.IsEqual(foundCVEs))
}
