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
						Constraint: createConstraint(t, ">= 2.4.37-40.module_el8.6.0+1000+ce6a2ac1", version.RpmFormat), // older versions unaffected
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

	// Verify results - CVE-2023-1234 should be filtered out because package version is >= fix version
	// Only CVE-2023-5678 should remain (no unaffected record for it)
	assert.Len(t, matches, 1, "Should have 1 match - CVE-2023-1234 should be filtered out as fixed")

	// Find the remaining match
	require.Len(t, matches, 1, "Should have exactly one match")
	remainingMatch := matches[0]

	// CVE-2023-5678 should be present with original (RHEL) fix information
	assert.Equal(t, "CVE-2023-5678", remainingMatch.Vulnerability.ID, "CVE-2023-5678 should be the only remaining vulnerability")

	// CVE-2023-1234 should NOT be present because the package version (47+1111) is greater than
	// the AlmaLinux fix version (40+1000), so it's completely fixed
	for _, match := range matches {
		assert.NotEqual(t, "CVE-2023-1234", match.Vulnerability.ID, "CVE-2023-1234 should be filtered out as the package is >= fix version")
	}
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
						ID:      "CVE-2023-1234",
						Package: &pkg.Package{Name: "test-package"},
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
						ID:      "CVE-2023-1234",
						Package: &pkg.Package{Name: "test-package"},
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
			updated := applyAlmaLinuxUnaffectedFiltering(tt.disclosures, tt.unaffected, pkgVersion)

			if tt.expectedFiltered {
				// Version satisfied unaffected constraint >= fix version, so vulnerability should be completely filtered out
				assert.Empty(t, updated, tt.description)
				assert.NotContains(t, updated, "CVE-2023-1234", "vulnerability should be filtered out when package >= fix version")
			} else {
				// Version didn't satisfy constraint, so vulnerability should remain with original fix info
				assert.Len(t, updated, 1, "vulnerability should be reported when package < fix version")
				assert.Contains(t, updated, "CVE-2023-1234")
				vuln := updated["CVE-2023-1234"][0].Vulnerabilities[0]
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

func TestCVE202232084UnaffectedFiltering(t *testing.T) {
	// Test verifies that AlmaLinux unaffected records properly exclude vulnerabilities
	// when the package version satisfies the unaffected constraint.

	mockProvider := &MockProvider{}

	almaDistro := &distro.Distro{
		Type:    distro.AlmaLinux,
		Version: "8",
	}
	testPkg := pkg.Package{
		Name:    "mariadb",
		Version: "3:10.3.39-1.module_el8.8.0+3609+204d4ab0",
		Type:    syftPkg.RpmPkg,
		Distro:  almaDistro,
	}

	// RHEL reports this package as vulnerable (3609 < 19673 in module build numbers)
	rhelDisclosures := result.Set{
		"CVE-2022-32084": []result.Result{
			{
				ID: "CVE-2022-32084",
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Reference:  vulnerability.Reference{ID: "CVE-2022-32084"},
						Constraint: createConstraint(t, "< 3:10.3.39-1.module+el8.8.0+19673+72b0d35f", version.RpmFormat),
						Fix: vulnerability.Fix{
							Versions: []string{"3:10.3.39-1.module+el8.8.0+19673+72b0d35f"},
							State:    vulnerability.FixStateFixed,
						},
					},
				},
				Package: &testPkg,
			},
		},
	}

	// AlmaLinux marks this exact package version as unaffected
	almaUnaffected := result.Set{
		"ALSA-2023:5259": []result.Result{
			{
				ID: "ALSA-2023:5259",
				Vulnerabilities: []vulnerability.Vulnerability{
					{
						Reference: vulnerability.Reference{ID: "ALSA-2023:5259"},
						RelatedVulnerabilities: []vulnerability.Reference{
							{ID: "CVE-2022-32084"},
						},
						Constraint: createConstraint(t, ">= 3:10.3.39-1.module_el8.8.0+3609+204d4ab0", version.RpmFormat),
						Fix: vulnerability.Fix{
							Versions: []string{"3:10.3.39-1.module_el8.8.0+3609+204d4ab0"},
							State:    vulnerability.FixStateFixed,
						},
					},
				},
				Package: &testPkg,
			},
		},
	}

	callCount := 0
	mockProvider.findResultsFunc = func(criteria ...vulnerability.Criteria) (result.Set, error) {
		callCount++
		switch callCount {
		case 1:
			return rhelDisclosures, nil
		case 2:
			return almaUnaffected, nil
		default:
			return result.Set{}, nil
		}
	}

	matches, err := almaLinuxMatches(mockProvider, testPkg)
	require.NoError(t, err)

	var cve202232084Match *match.Match
	for i := range matches {
		if matches[i].Vulnerability.ID == "CVE-2022-32084" {
			cve202232084Match = &matches[i]
			break
		}
	}

	if cve202232084Match != nil {
		t.Errorf("CVE-2022-32084 should not be reported for package %s "+
			"because AlmaLinux unaffected record excludes it",
			testPkg.Version)
	}

	assert.Empty(t, matches, "No vulnerabilities should be reported when unaffected records exclude them")
}

// Helper functions for tests

func createConstraint(t *testing.T, constraintStr string, format version.Format) version.Constraint {
	constraint, err := version.GetConstraint(constraintStr, format)
	require.NoError(t, err)
	return constraint
}
