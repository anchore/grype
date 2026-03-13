package dbtest

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", "")},
		{Vulnerability: makeVuln("CVE-2024-0002", "")},
	}

	// this should pass
	AssertFindings(t, matches).HasCount(2)
}

func TestAssertFindings_IsEmpty(t *testing.T) {
	var matches []match.Match
	AssertFindings(t, matches).IsEmpty()
}

func TestAssertFindings_ContainsVuln(t *testing.T) {
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", "")},
		{Vulnerability: makeVuln("CVE-2024-0002", "")},
	}

	AssertFindings(t, matches).ContainsVuln("CVE-2024-0001")
	AssertFindings(t, matches).ContainsVuln("CVE-2024-0002")
}

func TestAssertFindings_ContainsVulns(t *testing.T) {
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", "")},
		{Vulnerability: makeVuln("CVE-2024-0002", "")},
		{Vulnerability: makeVuln("CVE-2024-0003", "")},
	}

	AssertFindings(t, matches).ContainsVulns("CVE-2024-0001", "CVE-2024-0003")
}

func TestAssertFindings_DoesNotContainVuln(t *testing.T) {
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", "")},
	}

	AssertFindings(t, matches).DoesNotContainVuln("CVE-2024-9999")
}

func TestAssertFindings_ForPackage(t *testing.T) {
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", ""),
			Package:       pkg.Package{Name: "curl"},
		},
		{
			Vulnerability: makeVuln("CVE-2024-0002", ""),
			Package:       pkg.Package{Name: "openssl"},
		},
	}

	AssertFindings(t, matches).ForPackage("curl")
	AssertFindings(t, matches).AffectsPackages("curl", "openssl")
}

func TestAssertFindings_InNamespace(t *testing.T) {
	matches := []match.Match{
		{Vulnerability: makeVuln("CVE-2024-0001", "debian:11")},
	}

	AssertFindings(t, matches).InNamespace("CVE-2024-0001", "debian:11")
}

func TestAssertFindings_Finding(t *testing.T) {
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       pkg.Package{Name: "curl", Version: "7.88.1"},
			Details:       []match.Detail{{Type: match.ExactDirectMatch}},
		},
	}

	AssertFindings(t, matches).
		Finding("CVE-2024-0001").
		AffectsPackage("curl").
		HasPackageVersion("7.88.1").
		InNamespace("debian:11").
		HasDetailCount(1)
}

func TestAssertFindings_Chaining(t *testing.T) {
	matches := []match.Match{
		{
			Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
			Package:       pkg.Package{Name: "curl"},
		},
		{
			Vulnerability: makeVuln("CVE-2024-0002", "debian:11"),
			Package:       pkg.Package{Name: "openssl"},
		},
	}

	// chained assertions should all pass
	AssertFindings(t, matches).
		HasCount(2).
		ContainsVulns("CVE-2024-0001", "CVE-2024-0002").
		DoesNotContainVuln("CVE-2024-9999").
		AffectsPackages("curl", "openssl")
}

func TestSingleFindingAssertion(t *testing.T) {
	m := match.Match{
		Vulnerability: makeVuln("CVE-2024-0001", "debian:11"),
		Package:       pkg.Package{Name: "curl", Version: "7.88.1"},
		Details:       []match.Detail{{Type: match.ExactDirectMatch}, {Type: match.CPEMatch}},
	}

	assertion := AssertMatch(t, m)
	assert.NotNil(t, assertion)

	assertion.
		HasVulnerabilityID("CVE-2024-0001").
		HasNamespace("debian:11").
		HasPackageName("curl").
		HasDetailCount(2).
		HasMatchType(match.ExactDirectMatch)
}

func TestAssertFindings_HasSeverity(t *testing.T) {
	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-2024-0001",
					Namespace: "debian:11",
				},
				Metadata: &vulnerability.Metadata{
					Severity: "High",
				},
			},
		},
	}

	AssertFindings(t, matches).HasSeverity("CVE-2024-0001", "High")
}
