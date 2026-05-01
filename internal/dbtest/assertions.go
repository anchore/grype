package dbtest

import (
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/artifact"
)

// TestingT is the interface required for assertions, satisfied by *testing.T and mock implementations.
type TestingT interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	FailNow()
	Cleanup(f func())
	Name() string
}

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
	t       TestingT
	pkg     pkg.Package
	matches []match.Match
	ignores []match.IgnoreFilter

	// tracking for completeness check
	assertedMatches  map[int]*singleFindingTracker
	skipCompleteness bool

	// ignoresAssertion is created lazily on the first call to Ignores().
	// When non-nil, the cleanup hook also enforces ignore-filter completeness.
	ignoresAssertion *IgnoreFiltersAssertion
}

// AssertFindings creates a new FindingsAssertion for API-agnostic assertions.
// The package parameter is the package that was matched against.
// If the package is zero-value (empty name), asserts that there are no matches.
// Otherwise, asserts that all matches are for the given package.
//
// Use complete() to enable completeness checking, which verifies that all matches
// and details were asserted.
func AssertFindings(t TestingT, matches []match.Match, p pkg.Package) *FindingsAssertion {
	return AssertFindingsAndIgnores(t, matches, nil, p)
}

// AssertFindingsAndIgnores is the same as AssertFindings but also captures the
// ignore filters returned by the matcher so they can be asserted on via
// FindingsAssertion.Ignores().
func AssertFindingsAndIgnores(t TestingT, matches []match.Match, ignores []match.IgnoreFilter, p pkg.Package) *FindingsAssertion {
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
		ignores:         ignores,
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
// bypasses the completeness checking and makes tests more fragile to internal API changes.
func (f *FindingsAssertion) Matches() []match.Match {
	f.t.Helper()
	return f.matches
}

// SkipCompleteness asserts that this chain is intentionally checking only a
// subset of matches/details. The default mode requires every match and detail
// to be asserted; calling SkipCompleteness inverts that contract: the chain
// fails if everything happened to be asserted anyway. The inversion exists so
// that SkipCompleteness calls don't rot in tests that have grown into being
// exhaustive - if the chain is fully asserting, drop the SkipCompleteness call.
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

// checkCompleteness verifies that the assertion chain matched its declared
// completeness intent. By default (SkipCompleteness not called), every match
// and detail must be asserted on. If SkipCompleteness was called, at least one
// match or detail must remain un-asserted - otherwise the call is dead weight
// and the test fails so the author removes it. Ignore-filter completeness
// follows the same rule once Ignores() has been opted into.
func (f *FindingsAssertion) checkCompleteness() {
	f.t.Helper()

	var missed []string
	if len(f.matches) > 0 {
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
	}

	if f.skipCompleteness {
		if len(f.matches) > 0 && len(missed) == 0 {
			f.t.Errorf("SkipCompleteness was called but every match and detail was asserted - drop the SkipCompleteness call")
		}
	} else if len(missed) > 0 {
		f.t.Errorf("incomplete assertions - the following items were not asserted:\n%s", strings.Join(missed, "\n"))
	}

	if f.ignoresAssertion != nil {
		var ignoresMissed []string
		for i, ig := range f.ignoresAssertion.ignores {
			if !f.ignoresAssertion.asserted[i] {
				ignoresMissed = append(ignoresMissed, fmt.Sprintf("  - ignore[%d]: %T %s (not asserted)", i, ig, ignoreSummary(ig)))
			}
		}
		if f.ignoresAssertion.skipCompleteness {
			if len(f.ignoresAssertion.ignores) > 0 && len(ignoresMissed) == 0 {
				f.t.Errorf("SkipCompleteness was called on Ignores() but every ignore filter was asserted - drop the SkipCompleteness call")
			}
		} else if len(ignoresMissed) > 0 {
			f.t.Errorf("incomplete ignore-filter assertions - the following items were not asserted:\n%s", strings.Join(ignoresMissed, "\n"))
		}
	}
}

// Ignores returns an IgnoreFiltersAssertion for asserting on the ignore filters
// returned alongside the matches. Calling this opts the assertion chain into
// completeness checking on ignore filters - if any ignore was not asserted by
// test end, the test fails. Use SkipCompleteness on the returned assertion to
// disable that check (e.g., when the test only cares about a subset).
func (f *FindingsAssertion) Ignores() *IgnoreFiltersAssertion {
	if f.ignoresAssertion == nil {
		f.ignoresAssertion = &IgnoreFiltersAssertion{
			t:        f.t,
			ignores:  f.ignores,
			asserted: make(map[int]bool),
		}
	}
	return f.ignoresAssertion
}

// IgnoreFiltersAssertion provides assertions on the ignore filters returned by
// a matcher. Like FindingsAssertion, it tracks which ignores were asserted and
// fails the test if any were missed (unless SkipCompleteness is called).
type IgnoreFiltersAssertion struct {
	t                TestingT
	ignores          []match.IgnoreFilter
	asserted         map[int]bool
	skipCompleteness bool
}

// SkipCompleteness asserts that this ignore-filter chain is intentionally
// partial. Mirrors the inverted semantics of FindingsAssertion.SkipCompleteness:
// the default requires every ignore filter to be asserted, and calling this
// flips the contract so the chain fails if everything happened to be asserted
// anyway. Drop the call once you are exhaustively asserting on ignores.
func (i *IgnoreFiltersAssertion) SkipCompleteness() *IgnoreFiltersAssertion {
	i.skipCompleteness = true
	return i
}

// IsEmpty asserts there are no ignore filters.
func (i *IgnoreFiltersAssertion) IsEmpty() *IgnoreFiltersAssertion {
	i.t.Helper()
	assert.Empty(i.t, i.ignores, "expected no ignore filters, got %d", len(i.ignores))
	return i
}

// HasCount asserts the number of ignore filters.
func (i *IgnoreFiltersAssertion) HasCount(n int) *IgnoreFiltersAssertion {
	i.t.Helper()
	require.Len(i.t, i.ignores, n, "expected %d ignore filters, got %d", n, len(i.ignores))
	return i
}

// SelectRelatedPackageIgnore finds an IgnoreRelatedPackage with the given reason
// and vulnerability ID. Fails if not exactly one matches. The returned assertion
// can be further qualified with ForPackage and WithRelationshipType.
func (i *IgnoreFiltersAssertion) SelectRelatedPackageIgnore(reason, vulnID string) *IgnoreRelatedPackageAssertion {
	i.t.Helper()
	matchedIdx := -1
	for idx, ig := range i.ignores {
		irp, ok := ig.(match.IgnoreRelatedPackage)
		if !ok {
			continue
		}
		if irp.Reason == reason && irp.VulnerabilityID == vulnID {
			if matchedIdx != -1 {
				i.t.Fatalf("expected exactly one IgnoreRelatedPackage{Reason=%q, VulnerabilityID=%q}, found multiple", reason, vulnID)
				return nil
			}
			matchedIdx = idx
		}
	}
	if matchedIdx == -1 {
		i.t.Fatalf("expected IgnoreRelatedPackage{Reason=%q, VulnerabilityID=%q}, not found", reason, vulnID)
		return nil
	}
	i.asserted[matchedIdx] = true
	return &IgnoreRelatedPackageAssertion{
		t:      i.t,
		filter: i.ignores[matchedIdx].(match.IgnoreRelatedPackage),
	}
}

// IgnoreRelatedPackageAssertion provides assertions on a single
// match.IgnoreRelatedPackage that has already been selected by reason+vuln.
type IgnoreRelatedPackageAssertion struct {
	t      TestingT
	filter match.IgnoreRelatedPackage
}

// ForPackage asserts the related package ID matches the given pkg.ID. This is
// the most common follow-up assertion: tests typically capture the package ID
// when constructing the test package and then assert that the ignore points
// back at it.
func (a *IgnoreRelatedPackageAssertion) ForPackage(pkgID pkg.ID) *IgnoreRelatedPackageAssertion {
	a.t.Helper()
	assert.Equal(a.t, pkgID, a.filter.RelatedPackageID, "unexpected related package ID")
	return a
}

// WithRelationshipType asserts the ignore filter's relationship type.
// The vast majority of cases use OwnershipByFileOverlapRelationship so this is
// only needed for the rare cases that use a different relationship.
func (a *IgnoreRelatedPackageAssertion) WithRelationshipType(rt artifact.RelationshipType) *IgnoreRelatedPackageAssertion {
	a.t.Helper()
	assert.Equal(a.t, rt, a.filter.RelationshipType, "unexpected relationship type")
	return a
}

// ignoreSummary returns a short, human-readable description of an IgnoreFilter
// for use in error messages from completeness checking.
func ignoreSummary(ig match.IgnoreFilter) string {
	if irp, ok := ig.(match.IgnoreRelatedPackage); ok {
		return fmt.Sprintf("Reason=%q, VulnerabilityID=%q, RelatedPackageID=%q", irp.Reason, irp.VulnerabilityID, irp.RelatedPackageID)
	}
	return fmt.Sprintf("%+v", ig)
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

// SelectMatches returns the subset of matches with the given vulnerability ID.
// Unlike SelectMatch, which fatals when multiple matches share an ID,
// SelectMatches accepts any non-zero count and lets callers narrow further via
// WithDetailType. The returned MultipleFindingAssertion participates in
// completeness tracking; selecting a sub-match here is what marks the
// underlying match as asserted.
func (f *FindingsAssertion) SelectMatches(vulnID string) *MultipleFindingAssertion {
	f.t.Helper()

	var indices []int
	for i := range f.matches {
		if f.matches[i].Vulnerability.ID == vulnID {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		f.t.Fatalf("SelectMatches expected to find at least one match with vulnerability ID %q, but none were found", vulnID)
		return nil
	}

	return &MultipleFindingAssertion{
		t:       f.t,
		parent:  f,
		indices: indices,
		vulnID:  vulnID,
	}
}

// MultipleFindingAssertion is a subset of a FindingsAssertion's matches that
// share a vulnerability ID. Used to disambiguate the otherwise-ambiguous case
// where one matcher emits multiple findings for the same CVE (e.g., a distro
// disclosure plus a CPE-fallback NVD finding for an EOL distro).
type MultipleFindingAssertion struct {
	t       TestingT
	parent  *FindingsAssertion
	indices []int
	vulnID  string
}

// HasCount asserts the number of matches in this subset.
func (m *MultipleFindingAssertion) HasCount(n int) *MultipleFindingAssertion {
	m.t.Helper()
	require.Len(m.t, m.indices, n, "SelectMatches(%q) expected %d matches, got %d", m.vulnID, n, len(m.indices))
	return m
}

// WithDetailType narrows the subset to the single match that has at least one
// detail of the given type. Fatals if zero or more than one match in the
// subset has a detail of that type. The selected match (and the detail used to
// pick it) become tracked for completeness purposes.
func (m *MultipleFindingAssertion) WithDetailType(detailType match.Type) *SingleFindingAssertion {
	m.t.Helper()

	matchIdx := -1
	for _, idx := range m.indices {
		for _, d := range m.parent.matches[idx].Details {
			if d.Type == detailType {
				if matchIdx != -1 && matchIdx != idx {
					m.t.Fatalf("SelectMatches(%q).WithDetailType(%q) expected exactly one match with that detail type, but found multiple", m.vulnID, detailType)
					return nil
				}
				matchIdx = idx
			}
		}
	}
	if matchIdx == -1 {
		m.t.Fatalf("SelectMatches(%q).WithDetailType(%q) found no match with that detail type", m.vulnID, detailType)
		return nil
	}

	tracker := m.parent.assertedMatches[matchIdx]
	if tracker == nil {
		tracker = &singleFindingTracker{
			selectedDetails:  make(map[int]bool),
			completedDetails: make(map[int]bool),
		}
		m.parent.assertedMatches[matchIdx] = tracker
	}

	return newSingleFindingAssertion(m.t, m.parent.pkg, &m.parent.matches[matchIdx], matchIdx, tracker)
}

// SingleFindingAssertion provides detailed string-based assertions on a single finding.
type SingleFindingAssertion struct {
	t        TestingT
	pkg      pkg.Package
	match    *match.Match
	matchIdx int
	tracker  *singleFindingTracker
	vulnID   string // the vulnerability ID from the match
}

// newSingleFindingAssertion creates a SingleFindingAssertion and asserts that the match
// affects the expected package (name and version if provided).
func newSingleFindingAssertion(t TestingT, p pkg.Package, m *match.Match, matchIdx int, tracker *singleFindingTracker) *SingleFindingAssertion {
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

// HasFix asserts the match's vulnerability has the expected fix state and (if
// any are passed) the exact set of fix versions in order.
func (s *SingleFindingAssertion) HasFix(state vulnerability.FixState, versions ...string) *SingleFindingAssertion {
	s.t.Helper()
	assert.Equal(s.t, state, s.match.Vulnerability.Fix.State, "unexpected fix state")
	if len(versions) > 0 {
		assert.Equal(s.t, versions, s.match.Vulnerability.Fix.Versions, "unexpected fix versions")
	}
	return s
}

// HasAdvisories asserts the match's vulnerability has exactly the given
// advisory IDs (order doesn't matter, but the count must match).
func (s *SingleFindingAssertion) HasAdvisories(ids ...string) *SingleFindingAssertion {
	s.t.Helper()
	got := make([]string, 0, len(s.match.Vulnerability.Advisories))
	for _, a := range s.match.Vulnerability.Advisories {
		got = append(got, a.ID)
	}
	assert.ElementsMatch(s.t, ids, got, "unexpected advisory IDs")
	return s
}

// InNamespace asserts the match's vulnerability lives in the expected
// namespace - useful when one matcher's results are scoped to a different
// namespace than the package's distro (e.g., AlmaLinux disclosures live in
// the rhel namespace).
func (s *SingleFindingAssertion) InNamespace(namespace string) *SingleFindingAssertion {
	s.t.Helper()
	assert.Equal(s.t, namespace, s.match.Vulnerability.Namespace, "unexpected vulnerability namespace")
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

// SelectDetailByDistro finds a detail where SearchedBy is DistroParameters
// matching the given distro type and version, and validates the found
// vulnerability. Fails if not exactly one detail matches.
//
// Takes an optional version constraint. When provided, the constraint serves
// as BOTH a selection filter (the matched detail must have this exact
// Found.VersionConstraint) AND a validation - so callers can disambiguate
// findings that produce multiple details with the same (distro, version) but
// different version constraints, like RHEL EUS findings whose details cover
// the EUS-overlay fix and the mainline fix paths in the same match.
//
// At most one constraint may be passed.
func (s *SingleFindingAssertion) SelectDetailByDistro(distroType, distroVersion string, constraint ...string) *DistroDetailAssertion {
	s.t.Helper()

	if len(constraint) > 1 {
		s.t.Fatalf("SelectDetailByDistro accepts at most one constraint argument, got %d", len(constraint))
		return nil
	}

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
		if sb.Distro.Type != distroType || sb.Distro.Version != distroVersion {
			continue
		}
		f, ok := d.Found.(match.DistroResult)
		if !ok {
			s.t.Fatalf("expected Found to be DistroResult, got %T", d.Found)
			return nil
		}
		if len(constraint) == 1 && f.VersionConstraint != constraint[0] {
			continue
		}
		if matched != nil {
			if len(constraint) == 1 {
				s.t.Fatalf("SelectDetailByDistro expected exactly one detail with distro %s:%s and constraint %q, but found multiple", distroType, distroVersion, constraint[0])
			} else {
				s.t.Fatalf("SelectDetailByDistro expected exactly one detail with distro %s:%s, but found multiple (pass a constraint to disambiguate)", distroType, distroVersion)
			}
			return nil
		}
		matchedIdx = i
		matched = d
		searchedBy = sb
		found = f
	}

	if matched == nil {
		if len(constraint) == 1 {
			s.t.Fatalf("SelectDetailByDistro found no detail with distro %s:%s and constraint %q", distroType, distroVersion, constraint[0])
		} else {
			s.t.Fatalf("SelectDetailByDistro found no detail with distro %s:%s", distroType, distroVersion)
		}
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
	t         TestingT
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

	assertSearchedDistroMatchesPackage(d.t, d.pkg, searchedBy)
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
	t          TestingT
	pkg        pkg.Package
	detail     *match.Detail
	searchedBy match.DistroParameters
	found      match.DistroResult
}

// newDistroDetailAssertion creates a DistroDetailAssertion. Callers that want
// the package-distro vs. searched-by-distro consistency check should call
// AsDistroSearch (which goes through assertSearchedDistroMatchesPackage). The
// constructor itself doesn't validate, so paths like SelectDetailByDistro -
// which already filter by an explicit distro that may diverge from the
// package's distro (e.g., AlmaLinux packages searched against rhel) - don't
// trip the consistency check.
func newDistroDetailAssertion(t TestingT, p pkg.Package, detail *match.Detail, searchedBy match.DistroParameters, found match.DistroResult) *DistroDetailAssertion {
	t.Helper()
	return &DistroDetailAssertion{t: t, pkg: p, detail: detail, searchedBy: searchedBy, found: found}
}

// assertSearchedDistroMatchesPackage validates that the SearchedBy distro
// matches the package's distro - the common case where a matcher queries the
// distro namespace declared on the package. Cross-namespace matchers
// (AlmaLinux -> rhel; EUS -> base + +eus) shouldn't go through this path.
func assertSearchedDistroMatchesPackage(t TestingT, p pkg.Package, searchedBy match.DistroParameters) {
	t.Helper()
	if p.Distro == nil {
		return
	}
	assert.Equal(t, string(p.Distro.Type), searchedBy.Distro.Type, "unexpected distro type in SearchedBy")
	if p.Distro.Version != "" {
		assert.Equal(t, p.Distro.Version, searchedBy.Distro.Version, "unexpected distro version in SearchedBy")
	}
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
	t          TestingT
	pkg        pkg.Package
	detail     *match.Detail
	searchedBy match.CPEParameters
	found      match.CPEResult
}

// newCPEDetailAssertion creates a CPEDetailAssertion.
// Note: package name is not asserted since it may differ for upstream/indirect matches.
func newCPEDetailAssertion(t TestingT, p pkg.Package, detail *match.Detail, searchedBy match.CPEParameters, found match.CPEResult) *CPEDetailAssertion {
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
	t          TestingT
	pkg        pkg.Package
	detail     *match.Detail
	searchedBy match.EcosystemParameters
	found      match.EcosystemResult
}

// newEcosystemDetailAssertion creates an EcosystemDetailAssertion and asserts that the searched
// language matches the package's language (if the package has language info).
// Note: package name is not asserted since it may differ for upstream/indirect matches.
func newEcosystemDetailAssertion(t TestingT, p pkg.Package, detail *match.Detail, searchedBy match.EcosystemParameters, found match.EcosystemResult) *EcosystemDetailAssertion {
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
