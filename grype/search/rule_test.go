package search

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/vulnerability"
)

func TestRuleCriteria_MatchesEverything(t *testing.T) {
	matches, reason, err := ByRule(10).MatchesVulnerability(vulnerability.Vulnerability{})
	assert.NoError(t, err)
	assert.True(t, matches)
	assert.Empty(t, reason)
}
