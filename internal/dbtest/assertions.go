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

// FindingsAssertion provides a string-based, API-agnostic fluent assertion chain for match results.
// This approach abstracts away internal struct shapes so that tests don't need to change when
// the high-level API is refactored (e.g., in grype v1).
//
// Example:
//
//	dbtest.AssertFindings(t, matches).
//	    HasCount(2).
//	    ContainsVulns("CVE-2024-1234", "CVE-2024-5678").
//	    DoesNotContainVuln("CVE-2024-9999")
type FindingsAssertion struct {
	t       *testing.T
	matches []match.Match
}

// AssertFindings creates a new FindingsAssertion for API-agnostic assertions.
func AssertFindings(t *testing.T, matches []match.Match) *FindingsAssertion {
	t.Helper()
	return &FindingsAssertion{t: t, matches: matches}
}

// HasCount asserts that there are exactly n findings.
func (f *FindingsAssertion) HasCount(n int) *FindingsAssertion {
	f.t.Helper()
	require.Len(f.t, f.matches, n, "expected %d findings, got %d", n, len(f.matches))
	return f
}

// IsEmpty asserts that there are no findings.
func (f *FindingsAssertion) IsEmpty() *FindingsAssertion {
	f.t.Helper()
	assert.Empty(f.t, f.matches, "expected no findings, got %d", len(f.matches))
	return f
}

// ContainsVuln asserts that a finding with the given vulnerability ID exists.
func (f *FindingsAssertion) ContainsVuln(vulnID string) *FindingsAssertion {
	f.t.Helper()
	found := false
	for _, m := range f.matches {
		if m.Vulnerability.ID == vulnID {
			found = true
			break
		}
	}
	assert.True(f.t, found, "expected to find vulnerability %q but it was not present", vulnID)
	return f
}

// ContainsVulns asserts that findings with all the given vulnerability IDs exist.
func (f *FindingsAssertion) ContainsVulns(vulnIDs ...string) *FindingsAssertion {
	f.t.Helper()
	for _, id := range vulnIDs {
		f.ContainsVuln(id)
	}
	return f
}

// DoesNotContainVuln asserts that no finding with the given vulnerability ID exists.
func (f *FindingsAssertion) DoesNotContainVuln(vulnID string) *FindingsAssertion {
	f.t.Helper()
	for _, m := range f.matches {
		if m.Vulnerability.ID == vulnID {
			f.t.Errorf("expected vulnerability %q to not be present, but it was found", vulnID)
			return f
		}
	}
	return f
}

// ForPackage asserts that at least one finding affects the named package.
func (f *FindingsAssertion) ForPackage(name string) *FindingsAssertion {
	f.t.Helper()
	found := false
	for _, m := range f.matches {
		if m.Package.Name == name {
			found = true
			break
		}
	}
	assert.True(f.t, found, "expected at least one finding for package %q", name)
	return f
}

// AffectsPackages asserts that findings affect all the named packages.
func (f *FindingsAssertion) AffectsPackages(names ...string) *FindingsAssertion {
	f.t.Helper()
	for _, name := range names {
		f.ForPackage(name)
	}
	return f
}

// HasSeverity asserts that the finding for the given vulnerability ID has the expected severity.
func (f *FindingsAssertion) HasSeverity(vulnID, severity string) *FindingsAssertion {
	f.t.Helper()
	for _, m := range f.matches {
		if m.Vulnerability.ID == vulnID {
			if m.Vulnerability.Metadata == nil {
				f.t.Errorf("vulnerability %q has no metadata to check severity", vulnID)
				return f
			}
			assert.Equal(f.t, severity, m.Vulnerability.Metadata.Severity,
				"expected vulnerability %q to have severity %q, got %q", vulnID, severity, m.Vulnerability.Metadata.Severity)
			return f
		}
	}
	f.t.Errorf("vulnerability %q not found when checking severity", vulnID)
	return f
}

// InNamespace asserts that the finding for the given vulnerability ID is in the expected namespace.
func (f *FindingsAssertion) InNamespace(vulnID, namespace string) *FindingsAssertion {
	f.t.Helper()
	for _, m := range f.matches {
		if m.Vulnerability.ID == vulnID {
			assert.Equal(f.t, namespace, m.Vulnerability.Namespace,
				"expected vulnerability %q to be in namespace %q, got %q", vulnID, namespace, m.Vulnerability.Namespace)
			return f
		}
	}
	f.t.Errorf("vulnerability %q not found when checking namespace", vulnID)
	return f
}

// Finding returns a SingleFindingAssertion for detailed assertions on a specific finding.
func (f *FindingsAssertion) Finding(vulnID string) *SingleFindingAssertion {
	f.t.Helper()
	for i := range f.matches {
		if f.matches[i].Vulnerability.ID == vulnID {
			return &SingleFindingAssertion{t: f.t, match: &f.matches[i]}
		}
	}
	f.t.Fatalf("vulnerability %q not found", vulnID)
	return nil
}

// SingleFindingAssertion provides detailed string-based assertions on a single finding.
type SingleFindingAssertion struct {
	t     *testing.T
	match *match.Match
}

// AffectsPackage asserts the finding affects the named package.
func (s *SingleFindingAssertion) AffectsPackage(name string) *SingleFindingAssertion {
	s.t.Helper()
	assert.Equal(s.t, name, s.match.Package.Name, "unexpected package name")
	return s
}

// HasPackageVersion asserts the finding's package has the expected version.
func (s *SingleFindingAssertion) HasPackageVersion(version string) *SingleFindingAssertion {
	s.t.Helper()
	assert.Equal(s.t, version, s.match.Package.Version, "unexpected package version")
	return s
}

// InNamespace asserts the finding is in the expected namespace.
func (s *SingleFindingAssertion) InNamespace(namespace string) *SingleFindingAssertion {
	s.t.Helper()
	assert.Equal(s.t, namespace, s.match.Vulnerability.Namespace, "unexpected namespace")
	return s
}

// HasDetailCount asserts the finding has the expected number of match details.
func (s *SingleFindingAssertion) HasDetailCount(n int) *SingleFindingAssertion {
	s.t.Helper()
	assert.Len(s.t, s.match.Details, n, "expected %d match details, got %d", n, len(s.match.Details))
	return s
}

// HasMatchType asserts that at least one match detail has the expected match type.
func (s *SingleFindingAssertion) HasMatchType(matchType match.Type) *SingleFindingAssertion {
	s.t.Helper()
	for _, d := range s.match.Details {
		if d.Type == matchType {
			return s
		}
	}
	s.t.Errorf("expected match type %q not found in details", matchType)
	return s
}

// ByMatcher asserts that at least one match detail was produced by the expected matcher.
func (s *SingleFindingAssertion) ByMatcher(matcherType match.MatcherType) *SingleFindingAssertion {
	s.t.Helper()
	for _, d := range s.match.Details {
		if d.Matcher == matcherType {
			return s
		}
	}
	s.t.Errorf("expected matcher %q not found in details", matcherType)
	return s
}

// HasDetail asserts that at least one match detail matches the given type and matcher combination.
func (s *SingleFindingAssertion) HasDetail(matchType match.Type, matcherType match.MatcherType) *SingleFindingAssertion {
	s.t.Helper()
	for _, d := range s.match.Details {
		if d.Type == matchType && d.Matcher == matcherType {
			return s
		}
	}
	s.t.Errorf("expected detail with type=%q matcher=%q not found", matchType, matcherType)
	return s
}

// HasOnlyMatchTypes asserts that all match details have one of the expected types.
func (s *SingleFindingAssertion) HasOnlyMatchTypes(matchTypes ...match.Type) *SingleFindingAssertion {
	s.t.Helper()
	allowed := make(map[match.Type]bool)
	for _, mt := range matchTypes {
		allowed[mt] = true
	}
	for _, d := range s.match.Details {
		if !allowed[d.Type] {
			s.t.Errorf("unexpected match type %q found in details", d.Type)
		}
	}
	return s
}

// IsSingleMatch asserts there is exactly one match and returns it for further assertions.
func (f *FindingsAssertion) IsSingleMatch() *SingleFindingAssertion {
	f.t.Helper()
	require.Len(f.t, f.matches, 1, "expected exactly one match, got %d", len(f.matches))
	return &SingleFindingAssertion{t: f.t, match: &f.matches[0]}
}

// HasAnyMatchOfType asserts that at least one finding has a detail with the given match type.
func (f *FindingsAssertion) HasAnyMatchOfType(matchType match.Type) *FindingsAssertion {
	f.t.Helper()
	for _, m := range f.matches {
		for _, d := range m.Details {
			if d.Type == matchType {
				return f
			}
		}
	}
	f.t.Errorf("expected at least one finding with match type %q", matchType)
	return f
}

// HasNoMatchOfType asserts that no finding has a detail with the given match type.
func (f *FindingsAssertion) HasNoMatchOfType(matchType match.Type) *FindingsAssertion {
	f.t.Helper()
	for _, m := range f.matches {
		for _, d := range m.Details {
			if d.Type == matchType {
				f.t.Errorf("expected no findings with match type %q, but found one", matchType)
				return f
			}
		}
	}
	return f
}
