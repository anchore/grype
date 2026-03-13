package dbtest

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

func makeVuln(id, namespace string) vulnerability.Vulnerability {
	return vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        id,
			Namespace: namespace,
		},
	}
}

func TestAssertFindings_HasCount(t *testing.T) {
	p := pkg.Package{Name: "curl"}
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", ""), Package: p},
		{Vulnerability: makeVuln("CVE-2024-0002", ""), Package: p},
	}

	AssertFindings(t, matches, p).SkipCompleteness().HasCount(2)
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
		HasCount(2).
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
