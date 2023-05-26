package search

import (
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"

	"github.com/nextlinux/griffon/griffon/match"
	"github.com/nextlinux/griffon/griffon/vulnerability"
)

func assertMatchesUsingIDsForVulnerabilities(t testing.TB, expected, actual []match.Match) {
	t.Helper()
	assert.Len(t, actual, len(expected))
	for idx, a := range actual {
		// only compare the vulnerability ID, nothing else
		a.Vulnerability = vulnerability.Vulnerability{ID: a.Vulnerability.ID}
		for _, d := range deep.Equal(expected[idx], a) {
			t.Errorf("diff idx=%d: %+v", idx, d)
		}
	}
}
