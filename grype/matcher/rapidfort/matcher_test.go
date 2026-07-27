package rapidfort

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

func TestInstalledReleaseIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected string
	}{
		{
			name:     "fedora release",
			pkg:      pkg.Package{Name: "curl", Version: "8.6.0-7.fc41"},
			expected: "fc41",
		},
		{
			name:     "rapidfort release from version suffix",
			pkg:      pkg.Package{Name: "curl", Version: "3.6.1-11.rf"},
			expected: "rf",
		},
		{
			name:     "rhel release with minor suffix",
			pkg:      pkg.Package{Name: "curl", Version: "7.88.1-5.el9_4.1"},
			expected: "el9",
		},
		{
			name:     "rf package fallback",
			pkg:      pkg.Package{Name: "rf-curl", Version: "1.2.3-1"},
			expected: "rf",
		},
		{
			name:     "unknown release",
			pkg:      pkg.Package{Name: "curl", Version: "1.2.3-1"},
			expected: "",
		},
		// Ubuntu-distro cases: dpkgVariantID mirrors the vunnel annotator's
		// ordered substring rule ("rf" takes precedence over "ubuntu").
		{
			name:     "ubuntu rf-curated variant (rf substring wins over ubuntu)",
			pkg:      pkg.Package{Name: "curl", Version: "3.12.10-1rfubu.1", Distro: distro.New(distro.RapidFortUbuntu, "20.04", "")},
			expected: "rf",
		},
		{
			name:     "ubuntu stock variant",
			pkg:      pkg.Package{Name: "curl", Version: "2.39-0ubuntu8.3", Distro: distro.New(distro.RapidFortUbuntu, "20.04", "")},
			expected: "ubuntu",
		},
		{
			name:     "ubuntu unmarkered version (legacy) — fallback path takes over",
			pkg:      pkg.Package{Name: "curl", Version: "3.14.5", Distro: distro.New(distro.RapidFortUbuntu, "20.04", "")},
			expected: "",
		},
		{
			name:     "ubuntu distro does NOT apply RPM chain (fc marker in dpkg-style version is ignored)",
			pkg:      pkg.Package{Name: "curl", Version: "1.2.3.fc41-1", Distro: distro.New(distro.RapidFortUbuntu, "20.04", "")},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, installedReleaseIdentifier(test.pkg))
		})
	}
}

func TestByReleaseIdentifier_RedHat(t *testing.T) {
	criteria := byReleaseIdentifier(pkg.Package{
		Name:    "curl",
		Version: "8.6.0-7.fc41",
		Distro:  distro.New(distro.RapidFortRedHat, "9", ""),
	})

	matched, reason, err := criteria.MatchesVulnerability(vulnerability.Vulnerability{
		Advisories: []vulnerability.Advisory{
			{ID: "release-identifier:fc41"},
		},
	})
	assert.NoError(t, err)
	assert.True(t, matched)
	assert.Empty(t, reason)

	matched, reason, err = criteria.MatchesVulnerability(vulnerability.Vulnerability{
		Advisories: []vulnerability.Advisory{
			{ID: "release-identifier:el9"},
		},
	})
	assert.NoError(t, err)
	assert.False(t, matched)
	assert.Equal(t, reasonReleaseIdentifierMismatch, reason)
}

func TestByReleaseIdentifier_FallsBackToEL_WhenInstalledIdentifierUnknown(t *testing.T) {
	criteria := byReleaseIdentifier(pkg.Package{
		Name:    "curl",
		Version: "1.2.3-1",
		Distro:  distro.New(distro.RapidFortRedHat, "9", ""),
	})

	matched, reason, err := criteria.MatchesVulnerability(vulnerability.Vulnerability{
		Advisories: []vulnerability.Advisory{
			{ID: "release-identifier:el9"},
		},
	})
	assert.NoError(t, err)
	assert.True(t, matched)
	assert.Empty(t, reason)

	matched, reason, err = criteria.MatchesVulnerability(vulnerability.Vulnerability{
		Advisories: []vulnerability.Advisory{
			{ID: "release-identifier:fc41"},
		},
	})
	assert.NoError(t, err)
	assert.False(t, matched)
	assert.Contains(t, reason, "no el release identifier")
}

// TestByReleaseIdentifier_Ubuntu exercises the Ubuntu path through the same
// byReleaseIdentifier function used by RedHat — verifying that adding a new
// RF-curated base distro is a policy-registry entry, not a code fork.
func TestByReleaseIdentifier_Ubuntu(t *testing.T) {
	t.Run("ubuntu rf variant matches release-identifier:rf", func(t *testing.T) {
		criteria := byReleaseIdentifier(pkg.Package{
			Name:    "openssl",
			Version: "3.12.10-1rfubu.1",
			Distro:  distro.New(distro.RapidFortUbuntu, "20.04", ""),
		})

		matched, reason, err := criteria.MatchesVulnerability(vulnerability.Vulnerability{
			Advisories: []vulnerability.Advisory{
				{ID: "release-identifier:rf"},
			},
		})
		assert.NoError(t, err)
		assert.True(t, matched)
		assert.Empty(t, reason)
	})

	t.Run("ubuntu rf variant rejects release-identifier:ubuntu (variant mismatch)", func(t *testing.T) {
		criteria := byReleaseIdentifier(pkg.Package{
			Name:    "openssl",
			Version: "3.12.10-1rfubu.1",
			Distro:  distro.New(distro.RapidFortUbuntu, "20.04", ""),
		})

		matched, reason, err := criteria.MatchesVulnerability(vulnerability.Vulnerability{
			Advisories: []vulnerability.Advisory{
				{ID: "release-identifier:ubuntu"},
			},
		})
		assert.NoError(t, err)
		assert.False(t, matched)
		assert.Equal(t, reasonReleaseIdentifierMismatch, reason)
	})

	t.Run("ubuntu stock variant matches release-identifier:ubuntu", func(t *testing.T) {
		criteria := byReleaseIdentifier(pkg.Package{
			Name:    "libc6",
			Version: "2.39-0ubuntu8.3",
			Distro:  distro.New(distro.RapidFortUbuntu, "20.04", ""),
		})

		matched, reason, err := criteria.MatchesVulnerability(vulnerability.Vulnerability{
			Advisories: []vulnerability.Advisory{
				{ID: "release-identifier:ubuntu"},
			},
		})
		assert.NoError(t, err)
		assert.True(t, matched)
		assert.Empty(t, reason)
	})

	t.Run("ubuntu stock variant rejects release-identifier:rf (variant mismatch)", func(t *testing.T) {
		criteria := byReleaseIdentifier(pkg.Package{
			Name:    "libc6",
			Version: "2.39-0ubuntu8.3",
			Distro:  distro.New(distro.RapidFortUbuntu, "20.04", ""),
		})

		matched, reason, err := criteria.MatchesVulnerability(vulnerability.Vulnerability{
			Advisories: []vulnerability.Advisory{
				{ID: "release-identifier:rf"},
			},
		})
		assert.NoError(t, err)
		assert.False(t, matched)
		assert.Equal(t, reasonReleaseIdentifierMismatch, reason)
	})
}

// TestByReleaseIdentifier_FallsBackToUbuntu_WhenInstalledIdentifierUnknown
// verifies the distro-scoped fallback: an unmarkered Ubuntu package accepts
// a release-identifier:ubuntu advisory (conservative safety net) but rejects
// an el9-only advisory with the Ubuntu-specific reason string.
func TestByReleaseIdentifier_FallsBackToUbuntu_WhenInstalledIdentifierUnknown(t *testing.T) {
	criteria := byReleaseIdentifier(pkg.Package{
		Name:    "curl",
		Version: "3.14.5",
		Distro:  distro.New(distro.RapidFortUbuntu, "20.04", ""),
	})

	// legacy (untagged) ubuntu advisory — accept via fallback
	matched, reason, err := criteria.MatchesVulnerability(vulnerability.Vulnerability{
		Advisories: []vulnerability.Advisory{
			{ID: "release-identifier:ubuntu"},
		},
	})
	assert.NoError(t, err)
	assert.True(t, matched)
	assert.Empty(t, reason)

	// el9-only advisory — reject with the Ubuntu-specific fallback reason
	matched, reason, err = criteria.MatchesVulnerability(vulnerability.Vulnerability{
		Advisories: []vulnerability.Advisory{
			{ID: "release-identifier:el9"},
		},
	})
	assert.NoError(t, err)
	assert.False(t, matched)
	assert.Contains(t, reason, "no ubuntu release identifier")
}

// TestReleasePolicies_Gate documents that adding a new RF-curated distro
// requires exactly one addition to releasePolicies (and nothing else in this
// file). If this test starts asserting on more distros than are actually
// registered, someone regressed the registry.
func TestReleasePolicies_Gate(t *testing.T) {
	// Every entry in releasePolicies must gate byReleaseIdentifier (see
	// matchPackageByDistro). Missing entries mean the filter silently doesn't
	// run for that distro.
	assert.Contains(t, releasePolicies, distro.RapidFortRedHat)
	assert.Contains(t, releasePolicies, distro.RapidFortUbuntu)

	// Non-RF distros must NOT be registered — the filter should stay
	// specific to RF-curated content.
	assert.NotContains(t, releasePolicies, distro.RedHat)
	assert.NotContains(t, releasePolicies, distro.Ubuntu)
}

func TestRapidfortDistroVersion(t *testing.T) {
	tests := []struct {
		name        string
		baseDistro  distro.Distro
		rfDistro    distro.Type
		expectedVer string
	}{
		{
			name:        "rapidfort redhat uses major version only",
			baseDistro:  *distro.New(distro.RedHat, "9.5", ""),
			rfDistro:    distro.RapidFortRedHat,
			expectedVer: "9",
		},
		{
			name:        "rapidfort redhat keeps major only when already major",
			baseDistro:  *distro.New(distro.RedHat, "9", ""),
			rfDistro:    distro.RapidFortRedHat,
			expectedVer: "9",
		},
		{
			name:        "rapidfort ubuntu keeps full version",
			baseDistro:  *distro.New(distro.Ubuntu, "20.04", ""),
			rfDistro:    distro.RapidFortUbuntu,
			expectedVer: "20.04",
		},
		{
			name:        "rapidfort alpine keeps full version",
			baseDistro:  *distro.New(distro.Alpine, "3.15", ""),
			rfDistro:    distro.RapidFortAlpine,
			expectedVer: "3.15",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectedVer, rapidfortDistroVersion(test.baseDistro, test.rfDistro))
		})
	}
}

func TestFilterAlreadyFixed_KeepsVulnBeforeFixVersionAcrossReleases(t *testing.T) {
	installed := "1.7.2-1.fc41"
	format := version.RpmFormat

	matches := []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-TEST-FC-CROSS-RELEASE",
				},
				Fix: vulnerability.Fix{
					State:    vulnerability.FixStateFixed,
					Versions: []string{"1.7.5-1.fc45"},
				},
			},
		},
	}

	filtered := filterAlreadyFixed(matches, installed, format)

	// Installed version is before the fixed version in a later Fedora release,
	// so the match must be kept and fix metadata preserved for reporting.
	if assert.Len(t, filtered, 1) {
		assert.Equal(t, matches[0].Vulnerability.Fix, filtered[0].Vulnerability.Fix)
	}
}
