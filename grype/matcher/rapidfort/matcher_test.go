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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, installedReleaseIdentifier(test.pkg))
		})
	}
}

func TestByRPMReleaseIdentifier(t *testing.T) {
	criteria := byRPMReleaseIdentifier(pkg.Package{
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

func TestByRPMReleaseIdentifier_FallsBackToELWhenInstalledIdentifierUnknown(t *testing.T) {
	criteria := byRPMReleaseIdentifier(pkg.Package{
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
