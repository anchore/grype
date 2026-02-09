package dbtest

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// DefaultMatchCompareOptions returns the default cmp.Options for comparing matches.
// These options ignore fields that are typically not relevant for testing match correctness:
//   - vulnerability.Vulnerability.Constraint (already represented in match details)
//   - pkg.Package.Locations (package location implementation detail)
//   - distro.Distro unexported fields
func DefaultMatchCompareOptions() []cmp.Option {
	return []cmp.Option{
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
		cmpopts.IgnoreUnexported(distro.Distro{}),
	}
}

// AssertMatches compares expected and actual matches using cmp.Diff.
// Uses DefaultMatchCompareOptions() plus any additional options provided.
func AssertMatches(t *testing.T, expected, actual []match.Match, opts ...cmp.Option) {
	t.Helper()

	allOpts := append(DefaultMatchCompareOptions(), opts...)

	if diff := cmp.Diff(expected, actual, allOpts...); diff != "" {
		t.Errorf("matches mismatch (-want +got):\n%s", diff)
	}
}

// AssertNoMatches asserts that there are no matches.
func AssertNoMatches(t *testing.T, actual []match.Match) {
	t.Helper()
	assert.Empty(t, actual, "expected no matches, got %d", len(actual))
}

// AssertMatchCount asserts that there are exactly the expected number of matches.
func AssertMatchCount(t *testing.T, actual []match.Match, count int) {
	t.Helper()
	require.Len(t, actual, count, "expected %d matches, got %d", count, len(actual))
}

// AssertMatchVulnerabilityIDs asserts that matches contain exactly the expected vulnerability IDs.
// Order does not matter.
func AssertMatchVulnerabilityIDs(t *testing.T, actual []match.Match, expectedIDs ...string) {
	t.Helper()

	actualIDs := make([]string, len(actual))
	for i, m := range actual {
		actualIDs[i] = m.Vulnerability.ID
	}

	assert.ElementsMatch(t, expectedIDs, actualIDs,
		"vulnerability IDs mismatch: expected %v, got %v", expectedIDs, actualIDs)
}

// AssertMatchDetails compares expected and actual match details using cmp.Diff.
func AssertMatchDetails(t *testing.T, expected, actual []match.Detail, opts ...cmp.Option) {
	t.Helper()

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("match details mismatch (-want +got):\n%s", diff)
	}
}

// MatchAssertion provides a fluent API for asserting on a single match.
type MatchAssertion struct {
	t     *testing.T
	match match.Match
}

// AssertMatch creates a MatchAssertion for fluent assertions on a single match.
func AssertMatch(t *testing.T, m match.Match) *MatchAssertion {
	t.Helper()
	return &MatchAssertion{t: t, match: m}
}

// HasVulnerabilityID asserts the match has the expected vulnerability ID.
func (a *MatchAssertion) HasVulnerabilityID(id string) *MatchAssertion {
	a.t.Helper()
	assert.Equal(a.t, id, a.match.Vulnerability.ID, "unexpected vulnerability ID")
	return a
}

// HasNamespace asserts the match has the expected vulnerability namespace.
func (a *MatchAssertion) HasNamespace(namespace string) *MatchAssertion {
	a.t.Helper()
	assert.Equal(a.t, namespace, a.match.Vulnerability.Namespace, "unexpected namespace")
	return a
}

// HasPackageName asserts the match has the expected package name.
func (a *MatchAssertion) HasPackageName(name string) *MatchAssertion {
	a.t.Helper()
	assert.Equal(a.t, name, a.match.Package.Name, "unexpected package name")
	return a
}

// HasDetailCount asserts the match has the expected number of details.
func (a *MatchAssertion) HasDetailCount(count int) *MatchAssertion {
	a.t.Helper()
	assert.Len(a.t, a.match.Details, count, "unexpected detail count")
	return a
}

// HasMatchType asserts that at least one match detail has the expected match type.
func (a *MatchAssertion) HasMatchType(matchType match.Type) *MatchAssertion {
	a.t.Helper()
	found := false
	for _, d := range a.match.Details {
		if d.Type == matchType {
			found = true
			break
		}
	}
	assert.True(a.t, found, "expected match type %q not found in details", matchType)
	return a
}

// FirstMatch returns the first match from a slice, failing if empty.
func FirstMatch(t *testing.T, matches []match.Match) match.Match {
	t.Helper()
	require.NotEmpty(t, matches, "expected at least one match")
	return matches[0]
}

// MatchByVulnID finds and returns the first match with the given vulnerability ID.
// Fails if not found.
func MatchByVulnID(t *testing.T, matches []match.Match, vulnID string) match.Match {
	t.Helper()
	for _, m := range matches {
		if m.Vulnerability.ID == vulnID {
			return m
		}
	}
	t.Fatalf("no match found with vulnerability ID %q", vulnID)
	return match.Match{} // unreachable
}
