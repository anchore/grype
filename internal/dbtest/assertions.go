package dbtest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
)

// singleFindingTracker tracks which details have been asserted for a single match.
type singleFindingTracker struct {
	// selectedDetails tracks details that were selected via SelectDetailByType/SelectDetailBy*
	selectedDetails map[int]bool
	// completedDetails tracks details where As*Search() was called (with vuln validation)
	completedDetails map[int]bool
}

// FindingsAssertion provides a string-based, API-agnostic fluent assertion chain for match results.
// This approach abstracts away internal struct shapes so that tests don't need to change when
// the high-level API is refactored (e.g., in grype v1).
//
// Example:
//
//	dbtest.AssertFindings(t, matches, p).
//	    HasCount(2).
//	    OnlyHasVulnerabilities("CVE-2024-1234", "CVE-2024-5678").
//	    DoesNotHaveAnyVulnerabilities("CVE-2024-9999")
type FindingsAssertion struct {
	t       *testing.T
	pkg     pkg.Package
	matches []match.Match

	// tracking for completeness check
	assertedMatches  map[int]*singleFindingTracker
	skipCompleteness bool
}

// AssertFindings creates a new FindingsAssertion for API-agnostic assertions.
// The package parameter is the package that was matched against.
// If the package is zero-value (empty name), asserts that there are no matches.
// Otherwise, asserts that all matches are for the given package.
//
// Use complete() to enable completeness checking, which verifies that all matches
// and details were asserted.
func AssertFindings(t *testing.T, matches []match.Match, p pkg.Package) *FindingsAssertion {
	t.Helper()

	if p.Name == "" {
		// no package specified means we expect no matches
		assert.Empty(t, matches, "expected no findings, got %d", len(matches))
	} else {
		// all matches must be for the given package
		for _, m := range matches {
			if m.Package.Name != p.Name {
				t.Errorf("unexpected match for package %q (expected %q)", m.Package.Name, p.Name)
			}
		}
	}

	f := &FindingsAssertion{
		t:               t,
		pkg:             p,
		matches:         matches,
		assertedMatches: make(map[int]*singleFindingTracker),
	}
	f.complete()
	return f
}

// IsEmpty asserts that there are no findings.
func (f *FindingsAssertion) IsEmpty() *FindingsAssertion {
	f.t.Helper()
	assert.Empty(f.t, f.matches, "expected no findings, got %d", len(f.matches))
	return f
}

// Matches returns the underlying matches for direct assertions if needed, but using this is not recommended as it
func (f *FindingsAssertion) Matches() []match.Match {
	f.t.Helper()
	return f.matches
}

// SkipCompleteness disables the completeness check for this assertion chain.
// Use this when you only want to assert on a subset of matches/details.
func (f *FindingsAssertion) SkipCompleteness() *FindingsAssertion {
	f.skipCompleteness = true
	return f
}

// complete registers a cleanup handler to verify that all matches and their details
// were asserted. If any were missed, the test will fail with a helpful message.
func (f *FindingsAssertion) complete() {
	f.t.Cleanup(func() {
		f.checkCompleteness()
	})
}

// checkCompleteness verifies that all matches and their details were asserted.
func (f *FindingsAssertion) checkCompleteness() {
	f.t.Helper()

	if f.skipCompleteness {
		return
	}

	if len(f.matches) == 0 {
		return
	}

	var missed []string

	for i, m := range f.matches {
		tracker, matchAsserted := f.assertedMatches[i]
		if !matchAsserted {
			missed = append(missed, fmt.Sprintf("  - match[%d]: %s (not selected)", i, m.Vulnerability.ID))
			continue
		}

		// check details for this match - must be both selected AND completed
		for j, d := range m.Details {
			if !tracker.selectedDetails[j] {
				missed = append(missed, fmt.Sprintf("  - match[%d]/%s detail[%d]: type=%s (not selected)", i, m.Vulnerability.ID, j, d.Type))
			} else if !tracker.completedDetails[j] {
				missed = append(missed, fmt.Sprintf("  - match[%d]/%s detail[%d]: type=%s (selected but As*Search not called)", i, m.Vulnerability.ID, j, d.Type))
			}
		}
	}

	if len(missed) > 0 {
		f.t.Errorf("incomplete assertions - the following matches/details were not asserted:\n%s", strings.Join(missed, "\n"))
	}
}

// HasCount asserts that there are exactly n findings.
func (f *FindingsAssertion) HasCount(n int) *FindingsAssertion {
	f.t.Helper()
	require.Len(f.t, f.matches, n, "expected %d findings, got %d", n, len(f.matches))
	return f
}

// ContainsVulnerabilities asserts that findings with all the given vulnerability IDs exist.
// Other vulnerabilities may also be present.
func (f *FindingsAssertion) ContainsVulnerabilities(vulnIDs ...string) *FindingsAssertion {
	f.t.Helper()
	ids := strset.New()
	for _, m := range f.matches {
		ids.Add(m.Vulnerability.ID)
	}
	for _, id := range vulnIDs {
		assert.True(f.t, ids.Has(id), "expected to find vulnerability %q but it was not present", id)
	}
	return f
}

// OnlyHasVulnerabilities asserts that findings contain exactly the given vulnerability IDs and no others.
// Order does not matter.
func (f *FindingsAssertion) OnlyHasVulnerabilities(vulnIDs ...string) *FindingsAssertion {
	f.t.Helper()
	actualIDs := strset.New()
	for _, m := range f.matches {
		actualIDs.Add(m.Vulnerability.ID)
	}
	expectedIDs := strset.New(vulnIDs...)

	// check for missing expected IDs
	for _, id := range vulnIDs {
		if !actualIDs.Has(id) {
			f.t.Errorf("expected vulnerability %q but it was not present", id)
		}
	}

	// check for unexpected IDs
	actualIDs.Each(func(id string) bool {
		if !expectedIDs.Has(id) {
			f.t.Errorf("unexpected vulnerability %q found", id)
		}
		return true
	})

	return f
}

// DoesNotHaveAnyVulnerabilities asserts that no finding with the given vulnerability ID exists.
func (f *FindingsAssertion) DoesNotHaveAnyVulnerabilities(vulnIDs ...string) *FindingsAssertion {
	f.t.Helper()

	if len(vulnIDs) == 0 {
		f.t.Errorf("DoesNotHaveAnyVulnerabilities requires at least one vulnerability ID to check")
		return f
	}

	ids := strset.New()
	for _, m := range f.matches {
		ids.Add(m.Vulnerability.ID)
	}
	for _, id := range vulnIDs {
		if ids.Has(id) {
			f.t.Errorf("expected vulnerability %q to not be present, but it was found", id)
			return f
		}
	}

	return f
}

// SelectMatch returns a SingleFindingAssertion for detailed assertions on a specific finding.
// With no arguments, selects the single match (fails if not exactly one).
// With one argument, selects the match with the given vulnerability ID.
func (f *FindingsAssertion) SelectMatch(vulnIDs ...string) *SingleFindingAssertion {
	f.t.Helper()

	var idx int
	switch len(vulnIDs) {
	case 0:
		require.Len(f.t, f.matches, 1, "expected exactly one match, got %d", len(f.matches))
		idx = 0
	case 1:
		idx = -1
		for i := range f.matches {
			if f.matches[i].Vulnerability.ID == vulnIDs[0] {
				if idx != -1 {
					f.t.Fatalf("SelectMatch expected exactly one match with vulnerability ID %q, but found multiple", vulnIDs[0])
				}
				idx = i
			}
		}
		if idx == -1 {
			f.t.Fatalf("SelectMatch expected to find a match with vulnerability ID %q, but it was not found", vulnIDs[0])
			return nil
		}
	default:
		f.t.Fatalf("SelectMatch only supports asserting on a single vulnerability ID, got %d", len(vulnIDs))
		return nil
	}

	// create or get tracker for this match
	tracker := f.assertedMatches[idx]
	if tracker == nil {
		tracker = &singleFindingTracker{
			selectedDetails:  make(map[int]bool),
			completedDetails: make(map[int]bool),
		}
		f.assertedMatches[idx] = tracker
	}

	return newSingleFindingAssertion(f.t, f.pkg, &f.matches[idx], idx, tracker)
}

// SingleFindingAssertion provides detailed string-based assertions on a single finding.
type SingleFindingAssertion struct {
	t        *testing.T
	pkg      pkg.Package
	match    *match.Match
	matchIdx int
	tracker  *singleFindingTracker
	vulnID   string // the vulnerability ID from the match
}

// newSingleFindingAssertion creates a SingleFindingAssertion and asserts that the match
// affects the expected package (name and version if provided).
func newSingleFindingAssertion(t *testing.T, p pkg.Package, m *match.Match, matchIdx int, tracker *singleFindingTracker) *SingleFindingAssertion {
	t.Helper()
	assert.Equal(t, p.Name, m.Package.Name, "unexpected package name")
	if p.Version != "" {
		assert.Equal(t, p.Version, m.Package.Version, "unexpected package version")
	}
	return &SingleFindingAssertion{
		t:        t,
		pkg:      p,
		match:    m,
		matchIdx: matchIdx,
		tracker:  tracker,
		vulnID:   m.Vulnerability.ID,
	}
}

// HasDetailCount asserts the match has the expected number of details.
func (s *SingleFindingAssertion) HasDetailCount(count int) *SingleFindingAssertion {
	s.t.Helper()
	assert.Len(s.t, s.match.Details, count, "unexpected detail count")
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

// SelectDetailByType returns a SingleDetailAssertion for assertions on a specific detail.
// With no arguments, requires exactly one detail (fails if not exactly one).
// With one argument, selects the detail matching the given type (fails if not exactly one match).
// More than one argument is an error.
func (s *SingleFindingAssertion) SelectDetailByType(matchType ...match.Type) *SingleDetailAssertion {
	s.t.Helper()
	if len(matchType) > 1 {
		s.t.Fatalf("SelectDetailByType accepts at most one match type argument, got %d", len(matchType))
		return nil
	}

	if len(s.match.Details) == 0 {
		s.t.Fatalf("no details to select from")
		return nil
	}

	var idx int
	if len(matchType) == 0 {
		if len(s.match.Details) > 1 {
			s.t.Fatalf("SelectDetailByType with no arguments requires exactly one detail, got %d", len(s.match.Details))
			return nil
		}
		idx = 0
	} else {
		idx = -1
		for i := range s.match.Details {
			if s.match.Details[i].Type == matchType[0] {
				if idx != -1 {
					s.t.Fatalf("SelectDetailByType expected exactly one detail with match type %q, but found multiple", matchType[0])
					return nil
				}
				idx = i
			}
		}

		if idx == -1 {
			s.t.Fatalf("no detail with match type %q found", matchType[0])
			return nil
		}
	}

	// track this detail as selected (completion tracked when As*Search is called)
	s.tracker.selectedDetails[idx] = true

	return &SingleDetailAssertion{t: s.t, pkg: s.pkg, detail: &s.match.Details[idx], detailIdx: idx, tracker: s.tracker, vulnID: s.vulnID}
}

// SelectDetailByDistro finds a detail where SearchedBy is DistroParameters matching the given
// distro type and version, and validates the found vulnerability.
// Fails if not exactly one detail matches.
// Takes an optional version constraint to validate (0 = no assertion, 1 = assert, 2+ = error).
func (s *SingleFindingAssertion) SelectDetailByDistro(distroType, distroVersion string, constraint ...string) *DistroDetailAssertion {
	s.t.Helper()

	var matchedIdx = -1
	var matched *match.Detail
	var searchedBy match.DistroParameters
	var found match.DistroResult

	for i := range s.match.Details {
		d := &s.match.Details[i]
		sb, ok := d.SearchedBy.(match.DistroParameters)
		if !ok {
			continue
		}
		if sb.Distro.Type == distroType && sb.Distro.Version == distroVersion {
			if matched != nil {
				s.t.Fatalf("SelectDetailByDistro expected exactly one detail with distro %s:%s, but found multiple", distroType, distroVersion)
				return nil
			}
			matchedIdx = i
			matched = d
			searchedBy = sb
			f, ok := d.Found.(match.DistroResult)
			if !ok {
				s.t.Fatalf("expected Found to be DistroResult, got %T", d.Found)
				return nil
			}
			found = f
		}
	}

	if matched == nil {
		s.t.Fatalf("SelectDetailByDistro found no detail with distro %s:%s", distroType, distroVersion)
		return nil
	}

	// track this detail as selected and completed
	s.tracker.selectedDetails[matchedIdx] = true
	s.tracker.completedDetails[matchedIdx] = true

	result := newDistroDetailAssertion(s.t, s.pkg, matched, searchedBy, found)
	result.foundVulnerability(s.vulnID, constraint...)
	return result
}

// SelectDetailByCPE finds a detail where SearchedBy is CPEParameters containing the given CPE,
// and validates the found vulnerability.
// Fails if not exactly one detail matches.
// Takes an optional version constraint to validate (0 = no assertion, 1 = assert, 2+ = error).
func (s *SingleFindingAssertion) SelectDetailByCPE(cpe string, constraint ...string) *CPEDetailAssertion {
	s.t.Helper()

	var matchedIdx = -1
	var matched *match.Detail
	var searchedBy match.CPEParameters
	var found match.CPEResult

	for i := range s.match.Details {
		d := &s.match.Details[i]
		sb, ok := d.SearchedBy.(match.CPEParameters)
		if !ok {
			continue
		}
		// check if the searched CPEs contain the given CPE
		hasCPE := false
		for _, c := range sb.CPEs {
			if c == cpe {
				hasCPE = true
				break
			}
		}
		if hasCPE {
			if matched != nil {
				s.t.Fatalf("SelectDetailByCPE expected exactly one detail with CPE %q, but found multiple", cpe)
				return nil
			}
			matchedIdx = i
			matched = d
			searchedBy = sb
			f, ok := d.Found.(match.CPEResult)
			if !ok {
				s.t.Fatalf("expected Found to be CPEResult, got %T", d.Found)
				return nil
			}
			found = f
		}
	}

	if matched == nil {
		s.t.Fatalf("SelectDetailByCPE found no detail with CPE %q", cpe)
		return nil
	}

	// track this detail as selected and completed
	s.tracker.selectedDetails[matchedIdx] = true
	s.tracker.completedDetails[matchedIdx] = true

	result := newCPEDetailAssertion(s.t, s.pkg, matched, searchedBy, found)
	result.foundVulnerability(s.vulnID, constraint...)
	return result
}

// SelectDetailByEcosystem finds a detail where SearchedBy is EcosystemParameters matching the given
// language, and validates the found vulnerability.
// Fails if not exactly one detail matches.
// Takes an optional version constraint to validate (0 = no assertion, 1 = assert, 2+ = error).
func (s *SingleFindingAssertion) SelectDetailByEcosystem(language string, constraint ...string) *EcosystemDetailAssertion {
	s.t.Helper()

	var matchedIdx = -1
	var matched *match.Detail
	var searchedBy match.EcosystemParameters
	var found match.EcosystemResult

	for i := range s.match.Details {
		d := &s.match.Details[i]
		sb, ok := d.SearchedBy.(match.EcosystemParameters)
		if !ok {
			continue
		}
		if sb.Language == language {
			if matched != nil {
				s.t.Fatalf("SelectDetailByEcosystem expected exactly one detail with language %q, but found multiple", language)
				return nil
			}
			matchedIdx = i
			matched = d
			searchedBy = sb
			f, ok := d.Found.(match.EcosystemResult)
			if !ok {
				s.t.Fatalf("expected Found to be EcosystemResult, got %T", d.Found)
				return nil
			}
			found = f
		}
	}

	if matched == nil {
		s.t.Fatalf("SelectDetailByEcosystem found no detail with language %q", language)
		return nil
	}

	// track this detail as selected and completed
	s.tracker.selectedDetails[matchedIdx] = true
	s.tracker.completedDetails[matchedIdx] = true

	result := newEcosystemDetailAssertion(s.t, s.pkg, matched, searchedBy, found)
	result.foundVulnerability(s.vulnID, constraint...)
	return result
}

// SingleDetailAssertion provides assertions on a single match detail.
// Use AsDistroSearch(), AsCPESearch(), or AsEcosystemSearch() for type-specific assertions.
type SingleDetailAssertion struct {
	t         *testing.T
	pkg       pkg.Package
	detail    *match.Detail
	detailIdx int
	tracker   *singleFindingTracker
	vulnID    string // the vulnerability ID from the parent match
}

// AsDistroSearch validates that SearchedBy is DistroParameters and Found is DistroResult,
// asserts the searched distro matches the package's distro, and validates the found vulnerability.
// Takes an optional version constraint to validate (0 = no assertion, 1 = assert, 2+ = error).
func (d *SingleDetailAssertion) AsDistroSearch(constraint ...string) *DistroDetailAssertion {
	d.t.Helper()
	searchedBy, ok := d.detail.SearchedBy.(match.DistroParameters)
	if !ok {
		d.t.Fatalf("expected SearchedBy to be DistroParameters, got %T", d.detail.SearchedBy)
		return nil
	}
	found, ok := d.detail.Found.(match.DistroResult)
	if !ok {
		d.t.Fatalf("expected Found to be DistroResult, got %T", d.detail.Found)
		return nil
	}

	// mark as completed
	d.tracker.completedDetails[d.detailIdx] = true

	result := newDistroDetailAssertion(d.t, d.pkg, d.detail, searchedBy, found)
	result.foundVulnerability(d.vulnID, constraint...)
	return result
}

// AsCPESearch validates that SearchedBy is CPEParameters and Found is CPEResult,
// and validates the found vulnerability.
// Takes an optional version constraint to validate (0 = no assertion, 1 = assert, 2+ = error).
func (d *SingleDetailAssertion) AsCPESearch(constraint ...string) *CPEDetailAssertion {
	d.t.Helper()
	searchedBy, ok := d.detail.SearchedBy.(match.CPEParameters)
	if !ok {
		d.t.Fatalf("expected SearchedBy to be CPEParameters, got %T", d.detail.SearchedBy)
		return nil
	}
	found, ok := d.detail.Found.(match.CPEResult)
	if !ok {
		d.t.Fatalf("expected Found to be CPEResult, got %T", d.detail.Found)
		return nil
	}

	// mark as completed
	d.tracker.completedDetails[d.detailIdx] = true

	result := newCPEDetailAssertion(d.t, d.pkg, d.detail, searchedBy, found)
	result.foundVulnerability(d.vulnID, constraint...)
	return result
}

// AsEcosystemSearch validates that SearchedBy is EcosystemParameters and Found is EcosystemResult,
// asserts the searched language matches the package's language, and validates the found vulnerability.
// Takes an optional version constraint to validate (0 = no assertion, 1 = assert, 2+ = error).
func (d *SingleDetailAssertion) AsEcosystemSearch(constraint ...string) *EcosystemDetailAssertion {
	d.t.Helper()
	searchedBy, ok := d.detail.SearchedBy.(match.EcosystemParameters)
	if !ok {
		d.t.Fatalf("expected SearchedBy to be EcosystemParameters, got %T", d.detail.SearchedBy)
		return nil
	}
	found, ok := d.detail.Found.(match.EcosystemResult)
	if !ok {
		d.t.Fatalf("expected Found to be EcosystemResult, got %T", d.detail.Found)
		return nil
	}

	// mark as completed
	d.tracker.completedDetails[d.detailIdx] = true

	result := newEcosystemDetailAssertion(d.t, d.pkg, d.detail, searchedBy, found)
	result.foundVulnerability(d.vulnID, constraint...)
	return result
}

// DistroDetailAssertion provides assertions for distro/OS package matches.
// SearchedBy is DistroParameters, Found is DistroResult.
type DistroDetailAssertion struct {
	t          *testing.T
	pkg        pkg.Package
	detail     *match.Detail
	searchedBy match.DistroParameters
	found      match.DistroResult
}

// newDistroDetailAssertion creates a DistroDetailAssertion and asserts that the searched
// distro matches the package's distro (if the package has distro info).
func newDistroDetailAssertion(t *testing.T, p pkg.Package, detail *match.Detail, searchedBy match.DistroParameters, found match.DistroResult) *DistroDetailAssertion {
	t.Helper()
	if p.Distro != nil {
		assert.Equal(t, string(p.Distro.Type), searchedBy.Distro.Type, "unexpected distro type in SearchedBy")
		if p.Distro.Version != "" {
			assert.Equal(t, p.Distro.Version, searchedBy.Distro.Version, "unexpected distro version in SearchedBy")
		}
	}
	return &DistroDetailAssertion{t: t, pkg: p, detail: detail, searchedBy: searchedBy, found: found}
}

// foundVulnerability asserts the found vulnerability ID and optionally the version constraint.
func (d *DistroDetailAssertion) foundVulnerability(vulnID string, constraint ...string) {
	d.t.Helper()
	if len(constraint) > 1 {
		d.t.Fatalf("foundVulnerability accepts at most one constraint argument, got %d", len(constraint))
		return
	}
	assert.Equal(d.t, vulnID, d.found.VulnerabilityID, "unexpected vulnerability ID in Found")
	if len(constraint) == 1 {
		assert.Equal(d.t, constraint[0], d.found.VersionConstraint, "unexpected version constraint in Found")
	}
}

// HasMatchType asserts that the detail has the expected match type.
func (d *DistroDetailAssertion) HasMatchType(matchType match.Type) *DistroDetailAssertion {
	d.t.Helper()
	assert.Equal(d.t, matchType, d.detail.Type, "unexpected match type")
	return d
}

// CPEDetailAssertion provides assertions for CPE-based matches.
// SearchedBy is CPEParameters, Found is CPEResult.
type CPEDetailAssertion struct {
	t          *testing.T
	pkg        pkg.Package
	detail     *match.Detail
	searchedBy match.CPEParameters
	found      match.CPEResult
}

// newCPEDetailAssertion creates a CPEDetailAssertion.
// Note: package name is not asserted since it may differ for upstream/indirect matches.
func newCPEDetailAssertion(t *testing.T, p pkg.Package, detail *match.Detail, searchedBy match.CPEParameters, found match.CPEResult) *CPEDetailAssertion {
	t.Helper()
	return &CPEDetailAssertion{t: t, pkg: p, detail: detail, searchedBy: searchedBy, found: found}
}

// foundVulnerability asserts the found vulnerability ID and optionally the version constraint.
func (c *CPEDetailAssertion) foundVulnerability(vulnID string, constraint ...string) {
	c.t.Helper()
	if len(constraint) > 1 {
		c.t.Fatalf("foundVulnerability accepts at most one constraint argument, got %d", len(constraint))
		return
	}
	assert.Equal(c.t, vulnID, c.found.VulnerabilityID, "unexpected vulnerability ID in Found")
	if len(constraint) == 1 {
		assert.Equal(c.t, constraint[0], c.found.VersionConstraint, "unexpected version constraint in Found")
	}
}

// FoundCPEs asserts that the found CPEs contain all the given CPEs.
func (c *CPEDetailAssertion) FoundCPEs(cpes ...string) *CPEDetailAssertion {
	c.t.Helper()
	foundSet := strset.New(c.found.CPEs...)
	for _, cpe := range cpes {
		if !foundSet.Has(cpe) {
			c.t.Errorf("expected Found.CPEs to contain %q, got %v", cpe, c.found.CPEs)
		}
	}
	return c
}

// HasMatchType asserts that the detail has the expected match type.
func (c *CPEDetailAssertion) HasMatchType(matchType match.Type) *CPEDetailAssertion {
	c.t.Helper()
	assert.Equal(c.t, matchType, c.detail.Type, "unexpected match type")
	return c
}

// EcosystemDetailAssertion provides assertions for language/ecosystem package matches.
// SearchedBy is EcosystemParameters, Found is EcosystemResult.
type EcosystemDetailAssertion struct {
	t          *testing.T
	pkg        pkg.Package
	detail     *match.Detail
	searchedBy match.EcosystemParameters
	found      match.EcosystemResult
}

// newEcosystemDetailAssertion creates an EcosystemDetailAssertion and asserts that the searched
// language matches the package's language (if the package has language info).
// Note: package name is not asserted since it may differ for upstream/indirect matches.
func newEcosystemDetailAssertion(t *testing.T, p pkg.Package, detail *match.Detail, searchedBy match.EcosystemParameters, found match.EcosystemResult) *EcosystemDetailAssertion {
	t.Helper()
	if p.Language != "" {
		assert.Equal(t, string(p.Language), searchedBy.Language, "unexpected language in SearchedBy")
	}
	return &EcosystemDetailAssertion{t: t, pkg: p, detail: detail, searchedBy: searchedBy, found: found}
}

// foundVulnerability asserts the found vulnerability ID and optionally the version constraint.
func (e *EcosystemDetailAssertion) foundVulnerability(vulnID string, constraint ...string) {
	e.t.Helper()
	if len(constraint) > 1 {
		e.t.Fatalf("foundVulnerability accepts at most one constraint argument, got %d", len(constraint))
		return
	}
	assert.Equal(e.t, vulnID, e.found.VulnerabilityID, "unexpected vulnerability ID in Found")
	if len(constraint) == 1 {
		assert.Equal(e.t, constraint[0], e.found.VersionConstraint, "unexpected version constraint in Found")
	}
}

// HasMatchType asserts that the detail has the expected match type.
func (e *EcosystemDetailAssertion) HasMatchType(matchType match.Type) *EcosystemDetailAssertion {
	e.t.Helper()
	assert.Equal(e.t, matchType, e.detail.Type, "unexpected match type")
	return e
}
