package dbtest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// mockT is a mock testing.T that captures test failures without actually failing.
// It implements enough of testing.TB to work with testify assertions.
type mockT struct {
	failed   bool
	fataled  bool
	errors   []string
	cleanups []func()
}

func newMockT() *mockT {
	return &mockT{}
}

func (m *mockT) Helper() {}

func (m *mockT) Errorf(format string, args ...any) {
	m.failed = true
	m.errors = append(m.errors, format)
}

func (m *mockT) Fatalf(format string, args ...any) {
	m.failed = true
	m.fataled = true
	m.errors = append(m.errors, format)
}

func (m *mockT) FailNow() {
	m.failed = true
	m.fataled = true
}

func (m *mockT) Failed() bool {
	return m.failed
}

func (m *mockT) Cleanup(f func()) {
	m.cleanups = append(m.cleanups, f)
}

func (m *mockT) runCleanups() {
	for i := len(m.cleanups) - 1; i >= 0; i-- {
		m.cleanups[i]()
	}
}

// additional methods required by testify
func (m *mockT) Name() string {
	return "mockT"
}

func (m *mockT) Log(args ...any) {}

func (m *mockT) Logf(format string, args ...any) {}

func (m *mockT) Error(args ...any) {
	m.failed = true
}

func (m *mockT) Fatal(args ...any) {
	m.failed = true
	m.fataled = true
}

func makeVuln(id, namespace string) vulnerability.Vulnerability {
	return vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        id,
			Namespace: namespace,
		},
	}
}

func TestAssertFindings_IsEmpty(t *testing.T) {
	var matches []match.Match
	// empty package = assert empty matches
	AssertFindings(t, matches, pkg.Package{})
}

func TestAssertFindings_ContainsVulnerabilities(t *testing.T) {
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
		{Vulnerability: makeVuln("CVE-2024-0002", ""), Package: p},
		{Vulnerability: makeVuln("CVE-2024-0003", ""), Package: p},
	}

	AssertFindings(t, matches, p).SkipCompleteness().
		ContainsVulnerabilities("CVE-2024-0001", "CVE-2024-0003")
}

func TestAssertFindings_OnlyHasVulnerabilities(t *testing.T) {
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
		{Vulnerability: makeVuln("CVE-2024-0002", ""), Package: p},
	}

	AssertFindings(t, matches, p).SkipCompleteness().
		OnlyHasVulnerabilities("CVE-2024-0001", "CVE-2024-0002")
}

func TestAssertFindings_DoesNotContainVuln(t *testing.T) {
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
	}

	AssertFindings(t, matches, p).SkipCompleteness().
		DoesNotHaveAnyVulnerabilities("CVE-2024-9999")
}

func TestAssertFindings_Finding(t *testing.T) {
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
			Details: []match.Detail{{
				Type: match.ExactDirectMatch,
				SearchedBy: match.DistroParameters{
					Package: match.PackageParameter{Name: "curl", Version: "7.88.1"},
					Distro:  match.DistroIdentification{Type: "debian", Version: "11"},
				},
				Found: match.DistroResult{
					VulnerabilityID:   "CVE-2024-0001",
					VersionConstraint: "< 8.0.0",
				},
			}},
		},
	}

	AssertFindings(t, matches, p).
		SelectMatch("CVE-2024-0001").
		HasMatchType(match.ExactDirectMatch).
		SelectDetailByType(match.ExactDirectMatch).
		AsDistroSearch() // asserts distro matches package and validates vuln ID
}

func TestAssertFindings_Chaining(t *testing.T) {
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
		},
		{
			Vulnerability: makeVuln("CVE-2024-0002", "debian:11"),
			Package:       p,
		},
	}

	AssertFindings(t, matches, p).SkipCompleteness().
		OnlyHasVulnerabilities("CVE-2024-0001", "CVE-2024-0002").
		DoesNotHaveAnyVulnerabilities("CVE-2024-9999")
}

func TestSingleFindingAssertion(t *testing.T) {
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
			Details:       []match.Detail{{Type: match.ExactDirectMatch}, {Type: match.CPEMatch}},
		},
	}

	AssertFindings(t, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-0001"). // package checked automatically on construction
		HasMatchType(match.ExactDirectMatch)
}

func TestDistroDetailAssertion(t *testing.T) {
	p := pkg.Package{Name: "libssl3", Version: "3.0.0"}
	m := match.Match{
		Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
		Package:       p,
		Details: []match.Detail{
			{
				Type: match.ExactDirectMatch,
				SearchedBy: match.DistroParameters{
					// searched by upstream package name
					Package:   match.PackageParameter{Name: "openssl", Version: "3.0.0"},
					Distro:    match.DistroIdentification{Type: "debian", Version: "11"},
					Namespace: "debian:distro:debian:11",
				},
				Found: match.DistroResult{
					VulnerabilityID:   "CVE-2024-0001",
					VersionConstraint: "< 3.1.0",
				},
			},
		},
	}

	matches := []match.Match{m}

	// distro is asserted in constructor (package has no Distro set so only type validation happens)
	AssertFindings(t, matches, p).
		SelectMatch("CVE-2024-0001").
		SelectDetailByType().
		AsDistroSearch("< 3.1.0")
}

func TestCPEDetailAssertion(t *testing.T) {
	p := pkg.Package{Name: "openssl", Version: "1.1.1k"}
	m := match.Match{
		Vulnerability: makeVuln("CVE-2024-0001", "nvd:cpe"),
		Package:       p,
		Details: []match.Detail{
			{
				Type: match.CPEMatch,
				SearchedBy: match.CPEParameters{
					Package:   match.PackageParameter{Name: "openssl", Version: "1.1.1k"},
					CPEs:      []string{"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
					Namespace: "nvd:cpe",
				},
				Found: match.CPEResult{
					VulnerabilityID:   "CVE-2024-0001",
					VersionConstraint: "< 1.1.1w",
					CPEs:              []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"},
				},
			},
		},
	}

	matches := []match.Match{m}

	AssertFindings(t, matches, p).
		SelectMatch("CVE-2024-0001").
		SelectDetailByType(match.CPEMatch).
		AsCPESearch("< 1.1.1w").
		FoundCPEs("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")
}

func TestEcosystemDetailAssertion(t *testing.T) {
	p := pkg.Package{Name: "requests", Version: "2.25.0"}
	m := match.Match{
		Vulnerability: makeVuln("CVE-2024-0001", "github:language:python"),
		Package:       p,
		Details: []match.Detail{
			{
				Type: match.ExactDirectMatch,
				SearchedBy: match.EcosystemParameters{
					Package:   match.PackageParameter{Name: "requests", Version: "2.25.0"},
					Language:  "python",
					Namespace: "github:language:python",
				},
				Found: match.EcosystemResult{
					VulnerabilityID:   "CVE-2024-0001",
					VersionConstraint: "< 2.26.0",
				},
			},
		},
	}

	matches := []match.Match{m}

	// language is asserted in constructor (package has no Language set so only type validation happens)
	AssertFindings(t, matches, p).
		SelectMatch("CVE-2024-0001").
		SelectDetailByType().
		AsEcosystemSearch("< 2.26.0")
}

func TestSelectDetailByDistro(t *testing.T) {
	p := pkg.Package{Name: "openssl-libs", Version: "3.0.7-27.el9_3"}
	m := match.Match{
		Vulnerability: makeVuln("CVE-2024-6119", "redhat:distro:redhat:9"),
		Package:       p,
		Details: []match.Detail{
			{
				Type: match.ExactIndirectMatch,
				SearchedBy: match.DistroParameters{
					Distro:    match.DistroIdentification{Type: "redhat", Version: "9.3"},
					Package:   match.PackageParameter{Name: "openssl", Version: "3.0.7-27.el9_3"},
					Namespace: "redhat:distro:redhat:9",
				},
				Found: match.DistroResult{
					VulnerabilityID:   "CVE-2024-6119",
					VersionConstraint: "< 1:3.0.7-28.el9_4 (rpm)",
				},
			},
			{
				Type: match.ExactIndirectMatch,
				SearchedBy: match.DistroParameters{
					Distro:    match.DistroIdentification{Type: "redhat", Version: "9.3+eus"},
					Package:   match.PackageParameter{Name: "openssl", Version: "3.0.7-27.el9_3"},
					Namespace: "redhat:distro:redhat:9",
				},
				Found: match.DistroResult{
					VulnerabilityID:   "CVE-2024-6119",
					VersionConstraint: "< 1:3.0.7-28.el9_4 (rpm)",
				},
			},
		},
	}

	matches := []match.Match{m}

	// select the non-EUS detail by distro version
	AssertFindings(t, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-6119").
		SelectDetailByDistro("redhat", "9.3", "< 1:3.0.7-28.el9_4 (rpm)")

	// select the EUS detail by distro version
	AssertFindings(t, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-6119").
		SelectDetailByDistro("redhat", "9.3+eus", "< 1:3.0.7-28.el9_4 (rpm)")
}

func TestSelectDetailByCPE(t *testing.T) {
	p := pkg.Package{Name: "openssl", Version: "1.1.1k"}
	m := match.Match{
		Vulnerability: makeVuln("CVE-2024-0001", "nvd:cpe"),
		Package:       p,
		Details: []match.Detail{
			{
				Type: match.CPEMatch,
				SearchedBy: match.CPEParameters{
					Package:   match.PackageParameter{Name: "openssl", Version: "1.1.1k"},
					CPEs:      []string{"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
					Namespace: "nvd:cpe",
				},
				Found: match.CPEResult{
					VulnerabilityID:   "CVE-2024-0001",
					VersionConstraint: "< 1.1.1w",
					CPEs:              []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"},
				},
			},
			{
				Type: match.CPEMatch,
				SearchedBy: match.CPEParameters{
					Package:   match.PackageParameter{Name: "openssl", Version: "1.1.1k"},
					CPEs:      []string{"cpe:2.3:a:other:other:1.1.1k:*:*:*:*:*:*:*"},
					Namespace: "nvd:cpe",
				},
				Found: match.CPEResult{
					VulnerabilityID:   "CVE-2024-0001",
					VersionConstraint: "< 1.1.1w",
					CPEs:              []string{"cpe:2.3:a:other:other:*:*:*:*:*:*:*:*"},
				},
			},
		},
	}

	matches := []match.Match{m}

	// select by openssl CPE
	AssertFindings(t, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-0001").
		SelectDetailByCPE("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", "< 1.1.1w")

	// select by other CPE
	AssertFindings(t, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-0001").
		SelectDetailByCPE("cpe:2.3:a:other:other:1.1.1k:*:*:*:*:*:*:*", "< 1.1.1w")
}

func TestSelectDetailByEcosystem(t *testing.T) {
	p := pkg.Package{Name: "requests", Version: "2.25.0"}
	m := match.Match{
		Vulnerability: makeVuln("CVE-2024-0001", "github:language:python"),
		Package:       p,
		Details: []match.Detail{
			{
				Type: match.ExactDirectMatch,
				SearchedBy: match.EcosystemParameters{
					Package:   match.PackageParameter{Name: "requests", Version: "2.25.0"},
					Language:  "python",
					Namespace: "github:language:python",
				},
				Found: match.EcosystemResult{
					VulnerabilityID:   "CVE-2024-0001",
					VersionConstraint: "< 2.26.0",
				},
			},
			{
				Type: match.ExactDirectMatch,
				SearchedBy: match.EcosystemParameters{
					Package:   match.PackageParameter{Name: "requests", Version: "2.25.0"},
					Language:  "ruby",
					Namespace: "github:language:ruby",
				},
				Found: match.EcosystemResult{
					VulnerabilityID:   "CVE-2024-0001",
					VersionConstraint: "< 2.26.0",
				},
			},
		},
	}

	matches := []match.Match{m}

	// select by python language
	AssertFindings(t, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-0001").
		SelectDetailByEcosystem("python", "< 2.26.0")

	// select by ruby language
	AssertFindings(t, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-0001").
		SelectDetailByEcosystem("ruby", "< 2.26.0")
}

func TestComplete(t *testing.T) {
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{
						Package: match.PackageParameter{Name: "curl", Version: "7.88.1"},
						Distro:  match.DistroIdentification{Type: "debian", Version: "11"},
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 8.0.0",
					},
				},
			},
		},
		{
			Vulnerability: makeVuln("CVE-2024-0002", "debian:11"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{
						Package: match.PackageParameter{Name: "curl", Version: "7.88.1"},
						Distro:  match.DistroIdentification{Type: "debian", Version: "11"},
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2024-0002",
						VersionConstraint: "< 8.0.0",
					},
				},
			},
		},
	}

	// completeness is enabled by default - all matches and details must be asserted
	// store the findings reference so we can assert on multiple matches
	findings := AssertFindings(t, matches, p)
	findings.SelectMatch("CVE-2024-0001").SelectDetailByType().AsDistroSearch()
	findings.SelectMatch("CVE-2024-0002").SelectDetailByType().AsDistroSearch()
}

// Failure path tests - these verify that assertions correctly fail when conditions are not met

func TestAssertFindings_IsEmpty_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().IsEmpty()

	assert.True(t, mockT.Failed(), "expected IsEmpty to fail when matches exist")
}

func TestAssertFindings_ContainsVulnerabilities_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		ContainsVulnerabilities("CVE-2024-9999") // not present

	assert.True(t, mockT.Failed(), "expected ContainsVulnerabilities to fail when vulnerability is missing")
}

func TestAssertFindings_OnlyHasVulnerabilities_Failure_Missing(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		OnlyHasVulnerabilities("CVE-2024-0001", "CVE-2024-9999") // 9999 not present

	assert.True(t, mockT.Failed(), "expected OnlyHasVulnerabilities to fail when expected vulnerability is missing")
}

func TestAssertFindings_OnlyHasVulnerabilities_Failure_Extra(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
		{Vulnerability: makeVuln("CVE-2024-0002", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		OnlyHasVulnerabilities("CVE-2024-0001") // 0002 is extra

	assert.True(t, mockT.Failed(), "expected OnlyHasVulnerabilities to fail when extra vulnerability exists")
}

func TestAssertFindings_DoesNotHaveAnyVulnerabilities_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		DoesNotHaveAnyVulnerabilities("CVE-2024-0001") // is present

	assert.True(t, mockT.Failed(), "expected DoesNotHaveAnyVulnerabilities to fail when vulnerability is present")
}

func TestAssertFindings_DoesNotHaveAnyVulnerabilities_ReportsAllViolations(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
		{Vulnerability: makeVuln("CVE-2024-0002", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		DoesNotHaveAnyVulnerabilities("CVE-2024-0001", "CVE-2024-0002") // both present

	assert.True(t, mockT.Failed(), "expected DoesNotHaveAnyVulnerabilities to fail")
	// should report both violations, not just the first one
	assert.Len(t, mockT.errors, 2, "expected both violations to be reported")
}

func TestAssertFindings_SelectMatch_NotFound(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-9999") // not present

	assert.True(t, mockT.fataled, "expected SelectMatch to fatal when vulnerability not found")
}

func TestAssertFindings_SelectMatch_MultipleMatches(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p}, // duplicate
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-0001") // ambiguous

	assert.True(t, mockT.fataled, "expected SelectMatch to fatal when multiple matches exist")
}

func TestAssertFindings_SelectMatch_NoArgsMultipleMatches(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
		{Vulnerability: makeVuln("CVE-2024-0002", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch() // no args but multiple matches

	assert.True(t, mockT.fataled, "expected SelectMatch() to fatal when multiple matches exist")
}

func TestSingleFindingAssertion_HasMatchType_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details:       []match.Detail{{Type: match.ExactDirectMatch}},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		HasMatchType(match.CPEMatch) // wrong type

	assert.True(t, mockT.Failed(), "expected HasMatchType to fail when type not present")
}

func TestSingleFindingAssertion_HasOnlyMatchTypes(t *testing.T) {
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details: []match.Detail{
				{Type: match.ExactDirectMatch},
				{Type: match.ExactIndirectMatch},
			},
		},
	}

	// success case - all types are allowed
	AssertFindings(t, matches, p).SkipCompleteness().
		SelectMatch().
		HasOnlyMatchTypes(match.ExactDirectMatch, match.ExactIndirectMatch)
}

func TestSingleFindingAssertion_HasOnlyMatchTypes_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details: []match.Detail{
				{Type: match.ExactDirectMatch},
				{Type: match.CPEMatch}, // not in allowed list
			},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		HasOnlyMatchTypes(match.ExactDirectMatch) // CPEMatch not allowed

	assert.True(t, mockT.Failed(), "expected HasOnlyMatchTypes to fail when unexpected type present")
}

func TestSingleFindingAssertion_SelectDetailByType_NotFound(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details:       []match.Detail{{Type: match.ExactDirectMatch}},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		SelectDetailByType(match.CPEMatch) // wrong type

	assert.True(t, mockT.fataled, "expected SelectDetailByType to fatal when type not found")
}

func TestSingleFindingAssertion_SelectDetailByType_MultipleMatches(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details: []match.Detail{
				{Type: match.ExactDirectMatch},
				{Type: match.ExactDirectMatch}, // duplicate type
			},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		SelectDetailByType(match.ExactDirectMatch) // ambiguous

	assert.True(t, mockT.fataled, "expected SelectDetailByType to fatal when multiple details match")
}

func TestCompleteness_MatchNotSelected(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{},
					Found:      match.DistroResult{VulnerabilityID: "CVE-2024-0001"},
				},
			},
		},
		{
			Vulnerability: makeVuln("CVE-2024-0002", ""),
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{},
					Found:      match.DistroResult{VulnerabilityID: "CVE-2024-0002"},
				},
			},
		},
	}

	findings := AssertFindings(mockT, matches, p)
	// only assert on first match, leave second unselected
	findings.SelectMatch("CVE-2024-0001").SelectDetailByType().AsDistroSearch()

	// run cleanups to trigger completeness check
	mockT.runCleanups()

	assert.True(t, mockT.Failed(), "expected completeness check to fail when match not selected")
}

func TestCompleteness_DetailNotSelected(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{},
					Found:      match.DistroResult{VulnerabilityID: "CVE-2024-0001"},
				},
				{
					Type:       match.CPEMatch,
					SearchedBy: match.CPEParameters{},
					Found:      match.CPEResult{VulnerabilityID: "CVE-2024-0001"},
				},
			},
		},
	}

	findings := AssertFindings(mockT, matches, p)
	// select match but only assert on one detail
	findings.SelectMatch("CVE-2024-0001").SelectDetailByType(match.ExactDirectMatch).AsDistroSearch()

	// run cleanups to trigger completeness check
	mockT.runCleanups()

	assert.True(t, mockT.Failed(), "expected completeness check to fail when detail not selected")
}

func TestCompleteness_DetailSelectedButAsSearchNotCalled(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{},
					Found:      match.DistroResult{VulnerabilityID: "CVE-2024-0001"},
				},
			},
		},
	}

	findings := AssertFindings(mockT, matches, p)
	// select detail but don't call As*Search()
	findings.SelectMatch("CVE-2024-0001").SelectDetailByType(match.ExactDirectMatch)

	// run cleanups to trigger completeness check
	mockT.runCleanups()

	assert.True(t, mockT.Failed(), "expected completeness check to fail when As*Search not called")
}

func TestDistroDetailAssertion_HasMatchType(t *testing.T) {
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{
						Package: match.PackageParameter{Name: "curl", Version: "7.88.1"},
						Distro:  match.DistroIdentification{Type: "debian", Version: "11"},
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 8.0.0",
					},
				},
			},
		},
	}

	AssertFindings(t, matches, p).
		SelectMatch().
		SelectDetailByType().
		AsDistroSearch().
		HasMatchType(match.ExactDirectMatch)
}

func TestDistroDetailAssertion_HasMatchType_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{
						Package: match.PackageParameter{Name: "curl", Version: "7.88.1"},
						Distro:  match.DistroIdentification{Type: "debian", Version: "11"},
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 8.0.0",
					},
				},
			},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		SelectDetailByType().
		AsDistroSearch().
		HasMatchType(match.CPEMatch) // wrong type

	assert.True(t, mockT.Failed(), "expected HasMatchType to fail on DistroDetailAssertion")
}

func TestCPEDetailAssertion_HasMatchType(t *testing.T) {
	p := pkg.Package{Name: "openssl", Version: "1.1.1k"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "nvd:cpe"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.CPEMatch,
					SearchedBy: match.CPEParameters{
						Package:   match.PackageParameter{Name: "openssl", Version: "1.1.1k"},
						CPEs:      []string{"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
					},
					Found: match.CPEResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 1.1.1w",
						CPEs:              []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"},
					},
				},
			},
		},
	}

	AssertFindings(t, matches, p).
		SelectMatch().
		SelectDetailByType().
		AsCPESearch().
		HasMatchType(match.CPEMatch)
}

func TestCPEDetailAssertion_HasMatchType_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "openssl", Version: "1.1.1k"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "nvd:cpe"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.CPEMatch,
					SearchedBy: match.CPEParameters{
						Package:   match.PackageParameter{Name: "openssl", Version: "1.1.1k"},
						CPEs:      []string{"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
					},
					Found: match.CPEResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 1.1.1w",
						CPEs:              []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"},
					},
				},
			},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		SelectDetailByType().
		AsCPESearch().
		HasMatchType(match.ExactDirectMatch) // wrong type

	assert.True(t, mockT.Failed(), "expected HasMatchType to fail on CPEDetailAssertion")
}

func TestEcosystemDetailAssertion_HasMatchType(t *testing.T) {
	p := pkg.Package{Name: "requests", Version: "2.25.0"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "github:language:python"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.EcosystemParameters{
						Package:   match.PackageParameter{Name: "requests", Version: "2.25.0"},
						Language:  "python",
						Namespace: "github:language:python",
					},
					Found: match.EcosystemResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 2.26.0",
					},
				},
			},
		},
	}

	AssertFindings(t, matches, p).
		SelectMatch().
		SelectDetailByType().
		AsEcosystemSearch().
		HasMatchType(match.ExactDirectMatch)
}

func TestEcosystemDetailAssertion_HasMatchType_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "requests", Version: "2.25.0"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "github:language:python"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.EcosystemParameters{
						Package:   match.PackageParameter{Name: "requests", Version: "2.25.0"},
						Language:  "python",
						Namespace: "github:language:python",
					},
					Found: match.EcosystemResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 2.26.0",
					},
				},
			},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		SelectDetailByType().
		AsEcosystemSearch().
		HasMatchType(match.CPEMatch) // wrong type

	assert.True(t, mockT.Failed(), "expected HasMatchType to fail on EcosystemDetailAssertion")
}

func TestConstraintValidation_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{
						Package: match.PackageParameter{Name: "curl", Version: "7.88.1"},
						Distro:  match.DistroIdentification{Type: "debian", Version: "11"},
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 8.0.0",
					},
				},
			},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		SelectDetailByType().
		AsDistroSearch("< 9.0.0") // wrong constraint

	assert.True(t, mockT.Failed(), "expected constraint validation to fail with wrong constraint")
}

func TestFoundCPEs_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "openssl", Version: "1.1.1k"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "nvd:cpe"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.CPEMatch,
					SearchedBy: match.CPEParameters{
						Package:   match.PackageParameter{Name: "openssl", Version: "1.1.1k"},
						CPEs:      []string{"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
					},
					Found: match.CPEResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 1.1.1w",
						CPEs:              []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"},
					},
				},
			},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		SelectDetailByType().
		AsCPESearch().
		FoundCPEs("cpe:2.3:a:other:other:*:*:*:*:*:*:*:*") // not present

	assert.True(t, mockT.Failed(), "expected FoundCPEs to fail when CPE not present")
}

func TestPackageVersionMismatch_Failure(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       pkg.Package{Name: "curl", Version: "8.0.0"}, // wrong version
			Details:       []match.Detail{{Type: match.ExactDirectMatch}},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().SelectMatch()

	assert.True(t, mockT.Failed(), "expected assertion to fail when package version doesn't match")
}

// TestSkipCompleteness_DeadWeightFails covers the inverted SkipCompleteness
// contract: if the chain ends up asserting on every match and detail, the
// SkipCompleteness call is dead weight and the test must fail.
func TestSkipCompleteness_DeadWeightFails(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{
						Package: match.PackageParameter{Name: "curl", Version: "7.88.1"},
						Distro:  match.DistroIdentification{Type: "debian", Version: "11"},
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 8.0.0",
					},
				},
			},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch().
		SelectDetailByType().
		AsDistroSearch()

	mockT.runCleanups()

	assert.True(t, mockT.Failed(), "expected SkipCompleteness to fail when nothing was actually missed")
}

// TestSkipCompleteness_PartialPasses confirms the other side of the inversion:
// when at least one match or detail remains un-asserted, SkipCompleteness has
// done its job and the test passes cleanly.
func TestSkipCompleteness_PartialPasses(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl", Version: "7.88.1"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: match.DistroParameters{
						Package: match.PackageParameter{Name: "curl", Version: "7.88.1"},
						Distro:  match.DistroIdentification{Type: "debian", Version: "11"},
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2024-0001",
						VersionConstraint: "< 8.0.0",
					},
				},
			},
		},
		{
			Vulnerability: makeVuln("CVE-2024-0002", "debian:11"),
			Package:       p,
			Details:       []match.Detail{{Type: match.ExactDirectMatch}},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatch("CVE-2024-0001").
		SelectDetailByType().
		AsDistroSearch() // CVE-2024-0002 left intentionally un-asserted

	mockT.runCleanups()

	assert.False(t, mockT.Failed(), "expected SkipCompleteness to pass when something is genuinely un-asserted")
}

// TestIgnoresSkipCompleteness_DeadWeightFails mirrors
// TestSkipCompleteness_DeadWeightFails for ignore filters: opting into
// Ignores().SkipCompleteness() while asserting on every ignore is dead weight.
func TestIgnoresSkipCompleteness_DeadWeightFails(t *testing.T) {
	// synthetic reason - this package can't import grype/matcher/rpm without
	// inverting the dbtest -> matcher layering, so we use a local constant to
	// keep the produced/asserted strings paired.
	const reason = "Distro Fixed"

	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	pkgID := pkg.ID("pkg-1")
	ignores := []match.IgnoreFilter{
		match.IgnoreRelatedPackage{
			Reason:           reason,
			VulnerabilityID:  "CVE-2024-0001",
			RelatedPackageID: pkgID,
		},
	}

	AssertFindingsAndIgnores(mockT, nil, ignores, p).
		Ignores().
		SkipCompleteness().
		SelectRelatedPackageIgnore(reason, "CVE-2024-0001").
		ForPackage(pkgID)

	mockT.runCleanups()

	assert.True(t, mockT.Failed(), "expected SkipCompleteness on Ignores() to fail when nothing was missed")
}

// TestSelectMatches_DisambiguatesByDetailType is the end-to-end use case the
// helper was added for: a matcher emits two findings for the same CVE (e.g., a
// distro disclosure plus a CPE-fallback NVD finding), and SelectMatch can't
// pick between them. SelectMatches + WithDetailType should narrow to each in
// turn so the chain can be exhaustive without raw match introspection.
func TestSelectMatches_DisambiguatesByDetailType(t *testing.T) {
	p := pkg.Package{Name: "openssl", Version: "1.1.0a"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2018-0735", "redhat:distro:redhat:7"),
			Package:       p,
			Details: []match.Detail{{
				Type: match.ExactDirectMatch,
				SearchedBy: match.DistroParameters{
					Package: match.PackageParameter{Name: "openssl", Version: "1.1.0a"},
					Distro:  match.DistroIdentification{Type: "redhat", Version: "7"},
				},
				Found: match.DistroResult{
					VulnerabilityID:   "CVE-2018-0735",
					VersionConstraint: "< 1.1.0j",
				},
			}},
		},
		{
			Vulnerability: makeVuln("CVE-2018-0735", "nvd:cpe"),
			Package:       p,
			Details: []match.Detail{{
				Type: match.CPEMatch,
				SearchedBy: match.CPEParameters{
					Package: match.PackageParameter{Name: "openssl", Version: "1.1.0a"},
					CPEs:    []string{"cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*"},
				},
				Found: match.CPEResult{
					VulnerabilityID:   "CVE-2018-0735",
					VersionConstraint: "< 1.1.0j",
					CPEs:              []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"},
				},
			}},
		},
	}

	findings := AssertFindings(t, matches, p)
	ms := findings.SelectMatches("CVE-2018-0735")
	ms.WithDetailType(match.CPEMatch).
		SelectDetailByCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*")
	ms.WithDetailType(match.ExactDirectMatch).
		SelectDetailByDistro("redhat", "7")
}

// TestSelectMatches_NotFound fatals when the vulnerability ID has no matches.
func TestSelectMatches_NotFound(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatches("CVE-2024-9999")

	assert.True(t, mockT.fataled, "expected SelectMatches to fatal when no matches share the vulnerability ID")
}

// TestSelectMatches_WithDetailType_Ambiguous fatals when multiple matches in
// the subset share the requested detail type - the helper picks exactly one
// match by detail type and refuses to silently pick.
func TestSelectMatches_WithDetailType_Ambiguous(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "ns1"),
			Package:       p,
			Details:       []match.Detail{{Type: match.ExactDirectMatch}},
		},
		{
			Vulnerability: makeVuln("CVE-2024-0001", "ns2"),
			Package:       p,
			Details:       []match.Detail{{Type: match.ExactDirectMatch}}, // same detail type
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatches("CVE-2024-0001").
		WithDetailType(match.ExactDirectMatch)

	assert.True(t, mockT.fataled, "expected WithDetailType to fatal when multiple matches share the detail type")
}

// TestSelectMatches_WithDetailType_NoMatch fatals when no match in the subset
// has a detail of the requested type.
func TestSelectMatches_WithDetailType_NoMatch(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       p,
			Details:       []match.Detail{{Type: match.ExactDirectMatch}},
		},
	}

	AssertFindings(mockT, matches, p).SkipCompleteness().
		SelectMatches("CVE-2024-0001").
		WithDetailType(match.CPEMatch)

	assert.True(t, mockT.fataled, "expected WithDetailType to fatal when no match has a detail of that type")
}

// TestSelectRelatedPackageIgnores covers the variadic batch helper: same
// reason + same package, different vuln IDs, with one trailing ForPackage to
// fan over the whole set. This is the alma alias-unwind shape.
func TestSelectRelatedPackageIgnores(t *testing.T) {
	const reason = "Alma Unaffected"
	pkgID := pkg.ID("pkg-1")
	p := pkg.Package{Name: "httpd"}
	ignores := []match.IgnoreFilter{
		match.IgnoreRelatedPackage{Reason: reason, VulnerabilityID: "ALSA-2021:4537", RelatedPackageID: pkgID},
		match.IgnoreRelatedPackage{Reason: reason, VulnerabilityID: "CVE-2021-40438", RelatedPackageID: pkgID},
		match.IgnoreRelatedPackage{Reason: reason, VulnerabilityID: "CVE-2021-26691", RelatedPackageID: pkgID},
	}

	AssertFindingsAndIgnores(t, nil, ignores, p).
		Ignores().
		SelectRelatedPackageIgnores(reason,
			"ALSA-2021:4537",
			"CVE-2021-40438",
			"CVE-2021-26691").
		ForPackage(pkgID)
}

// TestSelectRelatedPackageIgnores_NoIDs fatals when called with no
// vulnerability IDs - it's a footgun otherwise (an empty batch silently
// asserts nothing).
func TestSelectRelatedPackageIgnores_NoIDs(t *testing.T) {
	mockT := newMockT()
	p := pkg.Package{Name: "httpd"}

	AssertFindingsAndIgnores(mockT, nil, nil, p).
		Ignores().SkipCompleteness().
		SelectRelatedPackageIgnores("Alma Unaffected")

	assert.True(t, mockT.fataled, "expected SelectRelatedPackageIgnores to fatal when called with no vulnerability IDs")
}

// TestSelectRelatedPackageIgnores_MissingFatal fatals as soon as one of the
// requested vulnerability IDs is missing from the ignore set.
func TestSelectRelatedPackageIgnores_MissingFatal(t *testing.T) {
	mockT := newMockT()
	const reason = "Alma Unaffected"
	pkgID := pkg.ID("pkg-1")
	p := pkg.Package{Name: "httpd"}
	ignores := []match.IgnoreFilter{
		match.IgnoreRelatedPackage{Reason: reason, VulnerabilityID: "ALSA-2021:4537", RelatedPackageID: pkgID},
	}

	AssertFindingsAndIgnores(mockT, nil, ignores, p).
		Ignores().SkipCompleteness().
		SelectRelatedPackageIgnores(reason, "ALSA-2021:4537", "CVE-9999-9999")

	assert.True(t, mockT.fataled, "expected SelectRelatedPackageIgnores to fatal when one of the IDs is missing")
}

// TestSelectRelatedPackageIgnores_ForPackageMismatch reports a per-filter
// failure naming the offending vuln ID, not a generic mismatch.
func TestSelectRelatedPackageIgnores_ForPackageMismatch(t *testing.T) {
	mockT := newMockT()
	const reason = "Alma Unaffected"
	wantID := pkg.ID("pkg-1")
	otherID := pkg.ID("pkg-2")
	p := pkg.Package{Name: "httpd"}
	ignores := []match.IgnoreFilter{
		match.IgnoreRelatedPackage{Reason: reason, VulnerabilityID: "ALSA-2021:4537", RelatedPackageID: wantID},
		match.IgnoreRelatedPackage{Reason: reason, VulnerabilityID: "CVE-2021-40438", RelatedPackageID: otherID},
	}

	AssertFindingsAndIgnores(mockT, nil, ignores, p).
		Ignores().
		SelectRelatedPackageIgnores(reason, "ALSA-2021:4537", "CVE-2021-40438").
		ForPackage(wantID)

	assert.True(t, mockT.Failed(), "expected ForPackage to fail when one filter in the batch points at a different package")
}
