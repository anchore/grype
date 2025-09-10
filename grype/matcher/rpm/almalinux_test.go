package rpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

func TestShouldUseAlmaLinuxMatching(t *testing.T) {
	tests := []struct {
		name     string
		distro   *distro.Distro
		expected bool
	}{
		{
			name:     "nil distro",
			distro:   nil,
			expected: false,
		},
		{
			name: "AlmaLinux distro",
			distro: &distro.Distro{
				Type: distro.AlmaLinux,
			},
			expected: true,
		},
		{
			name: "RHEL distro",
			distro: &distro.Distro{
				Type: distro.RedHat,
			},
			expected: false,
		},
		{
			name: "Ubuntu distro",
			distro: &distro.Distro{
				Type: distro.Ubuntu,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldUseAlmaLinuxMatching(tt.distro)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterDisclosuresByUnaffected(t *testing.T) {
	// Create test version
	testVersion := version.New("1.2.3-1.el8", version.RpmFormat)

	tests := []struct {
		name              string
		disclosures       result.Set
		unaffectedResults result.Set
		expectedVulnCount int
		expectedVulnIDs   []string
	}{
		{
			name: "no unaffected results",
			disclosures: result.Set{
				"test-key": []result.Result{
					{
						ID: "test-result-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
							{Reference: vulnerability.Reference{ID: "CVE-2023-5678"}},
						},
					},
				},
			},
			unaffectedResults: result.Set{},
			expectedVulnCount: 2,
			expectedVulnIDs:   []string{"CVE-2023-1234", "CVE-2023-5678"},
		},
		{
			name: "one vulnerability filtered out by unaffected",
			disclosures: result.Set{
				"test-key": []result.Result{
					{
						ID: "test-result-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
							{Reference: vulnerability.Reference{ID: "CVE-2023-5678"}},
						},
					},
				},
			},
			unaffectedResults: result.Set{
				"unaffected-key": []result.Result{
					{
						ID: "unaffected-result-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:  vulnerability.Reference{ID: "CVE-2023-1234"},
								Constraint: createConstraint(t, ">= 1.2.0", version.RpmFormat), // our version 1.2.3 is >= 1.2.0, so unaffected
							},
						},
					},
				},
			},
			expectedVulnCount: 1,
			expectedVulnIDs:   []string{"CVE-2023-5678"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterDisclosuresByUnaffected(tt.disclosures, tt.unaffectedResults, testVersion)

			// Count total vulnerabilities
			totalVulns := 0
			var foundVulnIDs []string
			for _, resultList := range result {
				for _, disclosure := range resultList {
					totalVulns += len(disclosure.Vulnerabilities)
					for _, vuln := range disclosure.Vulnerabilities {
						foundVulnIDs = append(foundVulnIDs, vuln.ID)
					}
				}
			}

			assert.Equal(t, tt.expectedVulnCount, totalVulns)
			assert.ElementsMatch(t, tt.expectedVulnIDs, foundVulnIDs)
		})
	}
}

func TestIsVersionUnaffected(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		expected   bool
	}{
		{
			name:       "version satisfies unaffected constraint",
			version:    "1.5.0-1.el8",
			constraint: ">= 1.5.0",
			expected:   true,
		},
		{
			name:       "version does not satisfy unaffected constraint",
			version:    "1.4.0-1.el8",
			constraint: ">= 1.5.0",
			expected:   false,
		},
		{
			name:       "exact version match",
			version:    "1.5.0-1.el8",
			constraint: "= 1.5.0-1.el8",
			expected:   true,
		},
		{
			name:       "complex constraint satisfied",
			version:    "2.1.0-1.el8",
			constraint: ">= 1.0.0, < 3.0.0",
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := version.New(tt.version, version.RpmFormat)
			constraint := createConstraint(t, tt.constraint, version.RpmFormat)

			result := isVersionUnaffected(v, constraint, "test-vuln-id")
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper functions for tests

func createConstraint(t *testing.T, constraintStr string, format version.Format) version.Constraint {
	constraint, err := version.GetConstraint(constraintStr, format)
	require.NoError(t, err)
	return constraint
}
