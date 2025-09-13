package rpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// MockProvider is a simple mock implementation of result.Provider for testing
type MockProvider struct {
	results         map[string]result.Set
	findResultsFunc func(criteria ...vulnerability.Criteria) (result.Set, error)
}

func (m *MockProvider) FindResults(criteria ...vulnerability.Criteria) (result.Set, error) {
	if m.findResultsFunc != nil {
		return m.findResultsFunc(criteria...)
	}
	// Default behavior - return empty set
	return result.Set{}, nil
}

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

func TestResultSetRemoveFiltering(t *testing.T) {
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
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
						},
					},
				},
				"CVE-2023-5678": []result.Result{
					{
						ID: "CVE-2023-5678",
						Vulnerabilities: []vulnerability.Vulnerability{
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
			name: "one vulnerability filtered out by exact ID match",
			disclosures: result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
						},
					},
				},
				"CVE-2023-5678": []result.Result{
					{
						ID: "CVE-2023-5678",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-5678"}},
						},
					},
				},
			},
			unaffectedResults: result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
						},
					},
				},
			},
			expectedVulnCount: 1,
			expectedVulnIDs:   []string{"CVE-2023-5678"},
		},
		{
			name: "ALSA advisory filters out CVE by alias",
			disclosures: result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
						},
					},
				},
				"CVE-2023-5678": []result.Result{
					{
						ID: "CVE-2023-5678",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-5678"}},
						},
					},
				},
			},
			unaffectedResults: result.Set{
				"ALSA-2023:1234": []result.Result{
					{
						ID: "ALSA-2023:1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "ALSA-2023:1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-1234"}, // ALSA has CVE as alias
								},
							},
						},
					},
				},
			},
			expectedVulnCount: 1,
			expectedVulnIDs:   []string{"CVE-2023-5678"}, // CVE-2023-1234 should be filtered out
		},
		{
			name: "CVE disclosure filters out ALSA by alias",
			disclosures: result.Set{
				"ALSA-2023:1234": []result.Result{
					{
						ID: "ALSA-2023:1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "ALSA-2023:1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-1234"},
								},
							},
						},
					},
				},
				"CVE-2023-5678": []result.Result{
					{
						ID: "CVE-2023-5678",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-5678"}},
						},
					},
				},
			},
			unaffectedResults: result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
						},
					},
				},
			},
			expectedVulnCount: 1,
			expectedVulnIDs:   []string{"CVE-2023-5678"}, // ALSA-2023:1234 should be filtered out by alias
		},
		{
			name: "multiple aliases - complex filtering",
			disclosures: result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "CVE-2023-1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "GHSA-abcd-1234"},
								},
							},
						},
					},
				},
				"CVE-2023-5678": []result.Result{
					{
						ID: "CVE-2023-5678",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-5678"}},
						},
					},
				},
			},
			unaffectedResults: result.Set{
				"ALSA-2023:1234": []result.Result{
					{
						ID: "ALSA-2023:1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "ALSA-2023:1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "GHSA-abcd-1234"}, // matches alias of CVE-2023-1234
								},
							},
						},
					},
				},
			},
			expectedVulnCount: 1,
			expectedVulnIDs:   []string{"CVE-2023-5678"}, // CVE-2023-1234 filtered by alias match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := tt.disclosures.Remove(tt.unaffectedResults)

			// Count total vulnerabilities
			totalVulns := 0
			var foundVulnIDs []string
			for _, resultList := range filtered {
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

func TestAlmaLinuxMatchingWithAliases(t *testing.T) {
	// This integration test verifies that AlmaLinux matching properly handles
	// the case where RHEL disclosures (with CVE IDs) are filtered by AlmaLinux
	// unaffected records (with ALSA IDs that alias to the same CVEs)

	mockProvider := &MockProvider{}

	// Setup test package
	almaDistro := &distro.Distro{
		Type:    distro.AlmaLinux,
		Version: "8.7",
	}
	testPkg := pkg.Package{
		Name:    "httpd",
		Version: "2.4.37-47.module_el8.6.0+1111+ce6a2ac1.1.alma",
		Type:    syftPkg.RpmPkg,
		Distro:  almaDistro,
	}

	// Mock RHEL disclosures that would match the package
	rhelDisclosures := result.Set{
		"CVE-2023-1234": []result.Result{
			{
				ID: "CVE-2023-1234",
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Reference: vulnerability.Reference{ID: "CVE-2023-1234"},
					},
				},
				Package: &testPkg,
			},
		},
		"CVE-2023-5678": []result.Result{
			{
				ID: "CVE-2023-5678",
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Reference: vulnerability.Reference{ID: "CVE-2023-5678"},
					},
				},
				Package: &testPkg,
			},
		},
	}

	// Mock AlmaLinux unaffected records with ALSA IDs that alias to CVEs
	almaUnaffected := result.Set{
		"ALSA-2023:1234": []result.Result{
			{
				ID: "ALSA-2023:1234",
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Reference: vulnerability.Reference{ID: "ALSA-2023:1234"},
						RelatedVulnerabilities: []vulnerability.Reference{
							{ID: "CVE-2023-1234"}, // ALSA aliases CVE
						},
						Constraint: createConstraint(t, ">= 0", version.RpmFormat), // any version is unaffected
					},
				},
				Package: &testPkg,
			},
		},
	}

	// Set up expectations for provider calls
	callCount := 0
	mockProvider.findResultsFunc = func(criteria ...vulnerability.Criteria) (result.Set, error) {
		callCount++
		switch callCount {
		case 1:
			// First call: RHEL disclosures
			return rhelDisclosures, nil
		case 2:
			// Second call: AlmaLinux unaffected
			return almaUnaffected, nil
		default:
			// Subsequent calls: related package lookups
			return result.Set{}, nil
		}
	}

	// Execute AlmaLinux matching
	matches, err := almaLinuxMatches(mockProvider, testPkg)
	require.NoError(t, err)

	// Verify results - both vulnerabilities should be present, but CVE-2023-1234 should have AlmaLinux fix info
	assert.Len(t, matches, 2, "Should have 2 matches - both vulnerabilities should be reported")

	// Find the matches by vulnerability ID
	var cve1234Match, cve5678Match *match.Match
	for i := range matches {
		if matches[i].Vulnerability.ID == "CVE-2023-1234" {
			cve1234Match = &matches[i]
		} else if matches[i].Vulnerability.ID == "CVE-2023-5678" {
			cve5678Match = &matches[i]
		}
	}

	// CVE-2023-1234 should be present with AlmaLinux fix information
	require.NotNil(t, cve1234Match, "CVE-2023-1234 should be present")
	assert.Equal(t, vulnerability.FixStateFixed, cve1234Match.Vulnerability.Fix.State, "CVE-2023-1234 should show as fixed")
	assert.NotEmpty(t, cve1234Match.Vulnerability.Fix.Versions, "CVE-2023-1234 should have AlmaLinux fix version")
	assert.Equal(t, "0", cve1234Match.Vulnerability.Fix.Versions[0], "CVE-2023-1234 should show correct AlmaLinux fix version")

	// CVE-2023-5678 should be present with original (RHEL) fix information
	require.NotNil(t, cve5678Match, "CVE-2023-5678 should be present")
}

func TestVersionConstraintFiltering(t *testing.T) {
	tests := []struct {
		name             string
		packageVersion   string
		disclosures      result.Set
		unaffected       result.Set
		expectedFiltered bool
		description      string
	}{
		{
			name:           "version satisfies unaffected constraint - should filter",
			packageVersion: "1.5.0-1.el8",
			disclosures: result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
						},
					},
				},
			},
			unaffected: result.Set{
				"ALSA-2023:1234": []result.Result{
					{
						ID: "ALSA-2023:1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "ALSA-2023:1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-1234"},
								},
								Constraint: createConstraint(t, ">= 1.5.0", version.RpmFormat), // our version 1.5.0 satisfies this
							},
						},
					},
				},
			},
			expectedFiltered: true,
			description:      "vulnerability should be filtered when version satisfies unaffected constraint",
		},
		{
			name:           "version does not satisfy unaffected constraint - should not filter",
			packageVersion: "1.4.0-1.el8",
			disclosures: result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
						},
					},
				},
			},
			unaffected: result.Set{
				"ALSA-2023:1234": []result.Result{
					{
						ID: "ALSA-2023:1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "ALSA-2023:1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-1234"},
								},
								Constraint: createConstraint(t, ">= 1.5.0", version.RpmFormat), // our version 1.4.0 does NOT satisfy this
							},
						},
					},
				},
			},
			expectedFiltered: false,
			description:      "vulnerability should NOT be filtered when version does not satisfy unaffected constraint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgVersion := version.New(tt.packageVersion, version.RpmFormat)

			// Apply AlmaLinux fix processing
			updated := updateDisclosuresWithAlmaLinuxFixes(tt.disclosures, tt.unaffected, pkgVersion)

			// Check results - vulnerability should always be present, but with different fix info
			assert.Len(t, updated, 1, "vulnerability should always be reported")
			assert.Contains(t, updated, "CVE-2023-1234")

			// Check if fix information was updated based on constraint satisfaction
			vuln := updated["CVE-2023-1234"][0].Vulnerabilities[0]
			if tt.expectedFiltered {
				// Version satisfied constraint, so AlmaLinux fix should be applied
				assert.Equal(t, vulnerability.FixStateFixed, vuln.Fix.State, tt.description)
				assert.NotEmpty(t, vuln.Fix.Versions, tt.description)
			} else {
				// Version didn't satisfy constraint, so original (empty) fix info remains
				assert.Empty(t, vuln.Fix.Versions, tt.description)
			}
		})
	}
}

func TestAlmaLinuxAliasEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		disclosures   result.Set
		unaffected    result.Set
		expectedCount int
		expectedIDs   []string
		description   string
	}{
		{
			name: "ALSA with multiple CVE aliases",
			disclosures: result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-1234"}},
						},
					},
				},
				"CVE-2023-5678": []result.Result{
					{
						ID: "CVE-2023-5678",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-5678"}},
						},
					},
				},
				"CVE-2023-9999": []result.Result{
					{
						ID: "CVE-2023-9999",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-9999"}},
						},
					},
				},
			},
			unaffected: result.Set{
				"ALSA-2023:1234": []result.Result{
					{
						ID: "ALSA-2023:1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "ALSA-2023:1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-1234"},
									{ID: "CVE-2023-5678"}, // Multiple CVEs in one ALSA
								},
							},
						},
					},
				},
			},
			expectedCount: 1,
			expectedIDs:   []string{"CVE-2023-9999"},
			description:   "Single ALSA should filter multiple CVEs",
		},
		{
			name: "Partial alias overlap",
			disclosures: result.Set{
				"GHSA-abcd-1234": []result.Result{
					{
						ID: "GHSA-abcd-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "GHSA-abcd-1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-1234"},
								},
							},
						},
					},
				},
				"CVE-2023-5678": []result.Result{
					{
						ID: "CVE-2023-5678",
						Vulnerabilities: []vulnerability.Vulnerability{
							{Reference: vulnerability.Reference{ID: "CVE-2023-5678"}},
						},
					},
				},
			},
			unaffected: result.Set{
				"ALSA-2023:1234": []result.Result{
					{
						ID: "ALSA-2023:1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "ALSA-2023:1234"},
								RelatedVulnerabilities: []vulnerability.Reference{
									{ID: "CVE-2023-1234"}, // Matches alias of GHSA
								},
							},
						},
					},
				},
			},
			expectedCount: 1,
			expectedIDs:   []string{"CVE-2023-5678"},
			description:   "ALSA should filter GHSA by transitive alias",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := tt.disclosures.Remove(tt.unaffected)

			var foundIDs []string
			totalCount := 0
			for _, resultList := range filtered {
				for _, result := range resultList {
					totalCount += len(result.Vulnerabilities)
					for _, vuln := range result.Vulnerabilities {
						foundIDs = append(foundIDs, vuln.ID)
					}
				}
			}

			assert.Equal(t, tt.expectedCount, totalCount, tt.description)
			assert.ElementsMatch(t, tt.expectedIDs, foundIDs, tt.description)
		})
	}
}

// Helper functions for tests

func createConstraint(t *testing.T, constraintStr string, format version.Format) version.Constraint {
	constraint, err := version.GetConstraint(constraintStr, format)
	require.NoError(t, err)
	return constraint
}
