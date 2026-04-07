package rpm

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmmodularity"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/file"
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

// this should be called "TestModularityQualifiersPassedToVulnProvider"
func TestModularityExcludesDisclosure(t *testing.T) {
	// Test that OnlyQualifiedPackages is used to filter both RHEL disclosures and AlmaLinux advisories
	mockProvider := &MockProvider{}

	almaDistro := &distro.Distro{
		Type:    distro.AlmaLinux,
		Version: "8",
	}
	testPkg := pkg.Package{
		Name:    "nodejs",
		Version: "1:20.8.0-1.module_el8.9.0+3775+d8460d29",
		Type:    syftPkg.RpmPkg,
		Distro:  almaDistro,
		Metadata: pkg.RpmMetadata{
			ModularityLabel: strRef("nodejs:20"),
		},
	}

	var capturedCriteria [][]vulnerability.Criteria
	callCount := 0
	mockProvider.findResultsFunc = func(criteria ...vulnerability.Criteria) (result.Set, error) {
		capturedCriteria = append(capturedCriteria, criteria)
		callCount++
		// First call: return a disclosure so the matcher continues to fetch unaffected records
		if callCount == 1 {
			return result.Set{
				"CVE-2023-1234": []result.Result{
					{
						ID: "CVE-2023-1234",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:         vulnerability.Reference{ID: "CVE-2023-1234"},
								Constraint:        createConstraint(t, "< 1:20.9.0-1.module_el8.9.0+1234+abcd", version.RpmFormat),
								PackageQualifiers: []qualifier.Qualifier{rpmmodularity.New("nodejs:20")},
							},
						},
						Package: &testPkg,
					},
				},
			}, nil
		}
		// All other calls: return empty
		return result.Set{}, nil
	}

	_, err := almaLinuxMatchesWithUpstreams(mockProvider, testPkg)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(capturedCriteria), 2, "FindResults should be called for both RHEL disclosures and AlmaLinux advisories")

	// Helper to check if a criteria set includes OnlyQualifiedPackages
	hasQualifierCriterion := func(criteriaSet []vulnerability.Criteria) bool {
		for _, criterion := range criteriaSet {
			// Test if this criterion filters by qualifiers
			matches, _, err := criterion.MatchesVulnerability(vulnerability.Vulnerability{
				PackageQualifiers: []qualifier.Qualifier{rpmmodularity.New("nodejs:22")},
			})
			require.NoError(t, err)
			if !matches {
				// This criterion rejected nodejs:22 when package has nodejs:20
				return true
			}
		}
		return false
	}

	// Call 1: RHEL disclosures for binary package
	assert.True(t, hasQualifierCriterion(capturedCriteria[0]),
		"RHEL disclosure fetch should include OnlyQualifiedPackages criterion")

	// Call 2: AlmaLinux unaffected records
	assert.True(t, hasQualifierCriterion(capturedCriteria[1]),
		"AlmaLinux advisory fetch should include OnlyQualifiedPackages criterion")
}

// Comprehensive table-driven test for AlmaLinux matching
func TestAlmaLinuxMatching(t *testing.T) {
	tests := []struct {
		name        string
		description string

		// Input data
		pkg       pkg.Package
		rhelVulns []vulnerability.Vulnerability
		almaVulns []vulnerability.Vulnerability

		// Expected behavior
		expectedMatches []match.Match
	}{
		{
			name:        "simple vulnerability match: disclosure without unaffected record",
			description: "Package version satisfies RHEL vulnerability constraint, no AlmaLinux unaffected record",

			pkg: pkg.Package{
				Name:    "httpd",
				Version: "2.4.37-10.el8",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8",
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-1234",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, ">= 0", version.RpmFormat),
					Fix: vulnerability.Fix{
						State: vulnerability.FixStateNotFixed,
					},
				},
			},

			// No AlmaLinux unaffected records
			almaVulns: []vulnerability.Vulnerability{},

			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "httpd",
						Reference: vulnerability.Reference{
							ID:        "CVE-2023-1234",
							Namespace: "redhat:distro:redhat:8",
						},
						Constraint: createConstraint(t, ">= 0", version.RpmFormat),
						Fix: vulnerability.Fix{
							State: vulnerability.FixStateNotFixed,
						},
					},
					Package: pkg.Package{
						Name:    "httpd",
						Version: "2.4.37-10.el8",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8",
						},
					},
					Details: createExpectedDetails(pkg.Package{
						Name:    "httpd",
						Version: "2.4.37-10.el8",
						Distro:  &distro.Distro{Type: distro.AlmaLinux, Version: "8"},
					}, vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2023-1234",
							Namespace: "redhat:distro:redhat:8",
						},
						Constraint: createConstraint(t, ">= 0", version.RpmFormat),
					}),
				},
			},
		},
		{
			name:        "simple vulnerability filtered by AlmaLinux unaffected record",
			description: "Package version satisfies AlmaLinux unaffected constraint, should be filtered out",

			pkg: pkg.Package{
				Name:    "httpd",
				Version: "2.4.37-51.el8",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8",
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-1234",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 2.4.37-50.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"2.4.37-50.el8"},
						State:    vulnerability.FixStateFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2023:1234",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2023-1234"},
					},
					Constraint: createConstraint(t, ">= 2.4.37-51.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"2.4.37-51.el8"},
						State:    vulnerability.FixStateFixed,
					},
					Unaffected: true,
				},
			},

			// Package version >= fix version, so vulnerability should be filtered
			expectedMatches: nil,
		},
		{
			name:        "fix replacement: simple non-modular package",
			description: "Non-modular package is vulnerable, RHEL fix info replaced by AlmaLinux fix info",

			pkg: pkg.Package{
				Name:    "httpd",
				Version: "2.4.37-10.el8",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8",
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "CVE-2021-44790",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 2.4.37-50.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"2.4.37-50.el8"},
						State:    vulnerability.FixStateFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2022:0123",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2021-44790"},
					},
					// Package 2.4.37-10.el8 < fix 2.4.37-43.el8, so it's still vulnerable
					Constraint: createConstraint(t, ">= 2.4.37-43.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"2.4.37-43.el8"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "ALSA-2022:0123",
							Link: "https://errata.almalinux.org/8/ALSA-2022-0123.html",
						},
					},
					Unaffected: true,
				},
			},

			// Package is vulnerable but fix info should be from AlmaLinux
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "httpd",
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-44790",
							Namespace: "redhat:distro:redhat:8",
						},
						// Constraint should be updated to match AlmaLinux fix version
						Constraint: createConstraint(t, "< 2.4.37-43.el8", version.RpmFormat),
						// Fix version should be replaced with AlmaLinux version
						Fix: vulnerability.Fix{
							Versions: []string{"2.4.37-43.el8"},
							State:    vulnerability.FixStateFixed,
						},
						// Advisory should be from AlmaLinux
						Advisories: []vulnerability.Advisory{
							{
								ID:   "ALSA-2022:0123",
								Link: "https://errata.almalinux.org/8/ALSA-2022-0123.html",
							},
						},
					},
					Package: pkg.Package{
						Name:    "httpd",
						Version: "2.4.37-10.el8",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8",
						},
					},
					Details: createExpectedDetails(pkg.Package{
						Name:    "httpd",
						Version: "2.4.37-10.el8",
						Distro:  &distro.Distro{Type: distro.AlmaLinux, Version: "8"},
					}, vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2021-44790",
							Namespace: "redhat:distro:redhat:8",
						},
						// Details should reflect the AlmaLinux constraint
						Constraint: createConstraint(t, "< 2.4.37-43.el8", version.RpmFormat),
					}),
				},
			},
		},
		{
			name:        "fix replacement: modular package with qualifiers",
			description: "Modular package with modularity qualifiers - RHEL fix replaced by AlmaLinux fix, ALSA maps to multiple CVEs",

			pkg: pkg.Package{
				ID:      pkg.ID("httpd-scenario1"),
				Name:    "httpd",
				Version: "2.4.37-50.module_el8.7.0+3405+9516b832",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.7",
				},
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strPtr("httpd:2.4:8070020220920142155:f8e95b4e"),
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "CVE-2006-20001",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 0:2.4.37-51.module+el8.7.0+18026+7b169787.1", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"0:2.4.37-51.module+el8.7.0+18026+7b169787.1"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "RHSA-2023:0852",
							Link: "https://access.redhat.com/errata/RHSA-2023:0852",
						},
					},
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.New("httpd:2.4")},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2023:0852",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2006-20001"},
						{ID: "CVE-2022-36760"},
						{ID: "CVE-2022-37436"},
					},
					Constraint: createConstraint(t, ">= 2.4.37-51.module_el8.7.0+3405+9516b832.1", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"2.4.37-51.module_el8.7.0+3405+9516b832.1"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "ALSA-2023:0852",
							Link: "https://errata.almalinux.org/8/ALSA-2023-0852.html",
						},
					},
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.New("httpd:2.4")},
					Unaffected:        true,
				},
			},

			// Package version 2.4.37-50 < fix 2.4.37-51, vulnerable but with AlmaLinux fix info
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "httpd",
						Reference: vulnerability.Reference{
							ID:        "CVE-2006-20001",
							Namespace: "redhat:distro:redhat:8",
						},
						// Constraint should be updated to match AlmaLinux fix version
						Constraint: createConstraint(t, "< 2.4.37-51.module_el8.7.0+3405+9516b832.1", version.RpmFormat),
						// Fix version should be from AlmaLinux (not RHEL)
						Fix: vulnerability.Fix{
							Versions: []string{"2.4.37-51.module_el8.7.0+3405+9516b832.1"},
							State:    vulnerability.FixStateFixed,
						},
						// Advisory should be from AlmaLinux (not RHEL)
						Advisories: []vulnerability.Advisory{
							{
								ID:   "ALSA-2023:0852",
								Link: "https://errata.almalinux.org/8/ALSA-2023-0852.html",
							},
						},
						// PackageQualifiers ignored in comparison
					},
					Package: pkg.Package{
						ID:      pkg.ID("httpd-scenario1"),
						Name:    "httpd",
						Version: "2.4.37-50.module_el8.7.0+3405+9516b832",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8.7",
						},
						Metadata: pkg.RpmMetadata{
							ModularityLabel: strPtr("httpd:2.4:8070020220920142155:f8e95b4e"),
						},
					},
					Details: createExpectedDetails(pkg.Package{
						Name:    "httpd",
						Version: "2.4.37-50.module_el8.7.0+3405+9516b832",
						Distro:  &distro.Distro{Type: distro.AlmaLinux, Version: "8.7"},
					}, vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2006-20001",
							Namespace: "redhat:distro:redhat:8",
						},
						// Details should reflect the AlmaLinux constraint
						Constraint: createConstraint(t, "< 2.4.37-51.module_el8.7.0+3405+9516b832.1", version.RpmFormat),
					}),
				},
			},
		},
		{
			name:        "Scenario 2A: A-advisory filters vulnerability when package at fix version",
			description: "RHEL has no fix, AlmaLinux A-advisory has fix, package version >= fix",

			pkg: pkg.Package{
				ID:      pkg.ID("open-vm-tools-scenario2a"),
				Name:    "open-vm-tools",
				Version: "12.3.5-2.el8.alma.1",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.0",
				},
				Metadata: pkg.RpmMetadata{
					ModularityLabel: nil,
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "open-vm-tools",
					Reference: vulnerability.Reference{
						ID:        "CVE-2025-22247",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, ">= 0", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{},
						State:    vulnerability.FixStateNotFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "open-vm-tools",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2025:A001",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2025-22247"},
					},
					Constraint: createConstraint(t, ">= 12.3.5-2.el8.alma.1", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"12.3.5-2.el8.alma.1"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "ALSA-2025:A001",
							Link: "https://errata.almalinux.org/8/ALSA-2025-A001.html",
						},
					},
					Unaffected: true,
				},
			},

			// Package version >= fix, should be filtered out
			expectedMatches: nil,
		},
		{
			name:        "Scenario 2B: A-advisory reports vulnerability with fix when package below fix version",
			description: "RHEL has no fix, AlmaLinux A-advisory has fix, package version < fix",

			pkg: pkg.Package{
				ID:      pkg.ID("open-vm-tools-scenario2b"),
				Name:    "open-vm-tools",
				Version: "12.3.5-1.el8",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.0",
				},
				Metadata: pkg.RpmMetadata{
					ModularityLabel: nil,
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "open-vm-tools",
					Reference: vulnerability.Reference{
						ID:        "CVE-2025-22247",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, ">= 0", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{},
						State:    vulnerability.FixStateNotFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "open-vm-tools",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2025:A001",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2025-22247"},
					},
					Constraint: createConstraint(t, ">= 12.3.5-2.el8.alma.1", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"12.3.5-2.el8.alma.1"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "ALSA-2025:A001",
							Link: "https://errata.almalinux.org/8/ALSA-2025-A001.html",
						},
					},
					Unaffected: true,
				},
			},

			// Package version < fix, should report with AlmaLinux fix info
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "open-vm-tools",
						Reference: vulnerability.Reference{
							ID:        "CVE-2025-22247",
							Namespace: "redhat:distro:redhat:8",
						},
						// Constraint should be updated to match AlmaLinux fix version
						Constraint: createConstraint(t, "< 12.3.5-2.el8.alma.1", version.RpmFormat),
						// Fix should be from AlmaLinux A-advisory (RHEL has no fix)
						Fix: vulnerability.Fix{
							Versions: []string{"12.3.5-2.el8.alma.1"},
							State:    vulnerability.FixStateFixed,
						},
						Advisories: []vulnerability.Advisory{
							{
								ID:   "ALSA-2025:A001",
								Link: "https://errata.almalinux.org/8/ALSA-2025-A001.html",
							},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("open-vm-tools-scenario2b"),
						Name:    "open-vm-tools",
						Version: "12.3.5-1.el8",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8.0",
						},
						Metadata: pkg.RpmMetadata{
							ModularityLabel: nil,
						},
					},
					Details: createExpectedDetails(pkg.Package{
						Name:    "open-vm-tools",
						Version: "12.3.5-1.el8",
						Distro:  &distro.Distro{Type: distro.AlmaLinux, Version: "8.0"},
					}, vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2025-22247",
							Namespace: "redhat:distro:redhat:8",
						},
						// Details should reflect the AlmaLinux constraint
						Constraint: createConstraint(t, "< 12.3.5-2.el8.alma.1", version.RpmFormat),
					}),
				},
			},
		},
		{
			name:        "Scenario 3A: Module build number mismatch - AlmaLinux lower build filters vulnerability",
			description: "python38 with modularity - AlmaLinux build 3633 vs RHEL build 19642, package at AlmaLinux fix",

			pkg: pkg.Package{
				ID:      pkg.ID("python38-scenario3a"),
				Name:    "python38",
				Version: "3.8.17-2.module_el8.9.0+3633+e453b53a",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.9",
				},
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strPtr("python38:3.8:8090020230810123456:3b72e4d2"),
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "python38",
					Reference: vulnerability.Reference{
						ID:        "CVE-2007-4559",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 0:3.8.17-2.module+el8.9.0+19642+a12b4af6", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"0:3.8.17-2.module+el8.9.0+19642+a12b4af6"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "RHSA-2023:7050",
							Link: "https://access.redhat.com/errata/RHSA-2023:7050",
						},
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "python38",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2023:7050",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2007-4559"},
						{ID: "CVE-2023-32681"},
					},
					Constraint: createConstraint(t, ">= 3.8.17-2.module_el8.9.0+3633+e453b53a", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"3.8.17-2.module_el8.9.0+3633+e453b53a"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "ALSA-2023:7050",
							Link: "https://errata.almalinux.org/8/ALSA-2023-7050.html",
						},
					},
					Unaffected: true,
				},
			},

			// Package has AlmaLinux build 3633, despite being < RHEL's 19642, should be filtered
			expectedMatches: nil,
		},
		{
			name:        "Scenario 3B: Module build number mismatch - vulnerable version still reported",
			description: "python38 with modularity - package version below AlmaLinux fix (despite lower build number)",

			pkg: pkg.Package{
				ID:      pkg.ID("python38-scenario3b"),
				Name:    "python38",
				Version: "3.8.17-1.module_el8.9.0+3633+e453b53a",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.9",
				},
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strPtr("python38:3.8:8090020230810123456:3b72e4d2"),
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "python38",
					Reference: vulnerability.Reference{
						ID:        "CVE-2007-4559",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 0:3.8.17-2.module+el8.9.0+19642+a12b4af6", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"0:3.8.17-2.module+el8.9.0+19642+a12b4af6"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "RHSA-2023:7050",
							Link: "https://access.redhat.com/errata/RHSA-2023:7050",
						},
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "python38",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2023:7050",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2007-4559"},
						{ID: "CVE-2023-32681"},
					},
					Constraint: createConstraint(t, ">= 3.8.17-2.module_el8.9.0+3633+e453b53a", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"3.8.17-2.module_el8.9.0+3633+e453b53a"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "ALSA-2023:7050",
							Link: "https://errata.almalinux.org/8/ALSA-2023-7050.html",
						},
					},
					Unaffected: true,
				},
			},

			// Package version 3.8.17-1 < fix 3.8.17-2, should report with AlmaLinux fix
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "python38",
						Reference: vulnerability.Reference{
							ID:        "CVE-2007-4559",
							Namespace: "redhat:distro:redhat:8",
						},
						// Constraint should be updated to match AlmaLinux fix version
						Constraint: createConstraint(t, "< 3.8.17-2.module_el8.9.0+3633+e453b53a", version.RpmFormat),
						// Fix should be from AlmaLinux (lower build number 3633, not RHEL's 19642)
						Fix: vulnerability.Fix{
							Versions: []string{"3.8.17-2.module_el8.9.0+3633+e453b53a"},
							State:    vulnerability.FixStateFixed,
						},
						Advisories: []vulnerability.Advisory{
							{
								ID:   "ALSA-2023:7050",
								Link: "https://errata.almalinux.org/8/ALSA-2023-7050.html",
							},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("python38-scenario3b"),
						Name:    "python38",
						Version: "3.8.17-1.module_el8.9.0+3633+e453b53a",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8.9",
						},
						Metadata: pkg.RpmMetadata{
							ModularityLabel: strPtr("python38:3.8:8090020230810123456:3b72e4d2"),
						},
					},
					Details: createExpectedDetails(pkg.Package{
						Name:    "python38",
						Version: "3.8.17-1.module_el8.9.0+3633+e453b53a",
						Distro:  &distro.Distro{Type: distro.AlmaLinux, Version: "8.9"},
					}, vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2007-4559",
							Namespace: "redhat:distro:redhat:8",
						},
						// Details should reflect the AlmaLinux constraint
						Constraint: createConstraint(t, "< 3.8.17-2.module_el8.9.0+3633+e453b53a", version.RpmFormat),
					}),
				},
			},
		},
		{
			name:        "Scenario 4: Wont-fix vulnerability reported when no AlmaLinux unaffected record",
			description: "tar package - RHEL wont-fix, no AlmaLinux unaffected record, vulnerability reported",

			pkg: pkg.Package{
				ID:      pkg.ID("tar-scenario4"),
				Name:    "tar",
				Version: "2:1.30-5.el8",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.0",
				},
				Metadata: pkg.RpmMetadata{
					ModularityLabel: nil,
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "tar",
					Reference: vulnerability.Reference{
						ID:        "CVE-2005-2541",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, ">= 0", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{},
						State:    vulnerability.FixStateWontFix,
					},
				},
			},

			// NO AlmaLinux unaffected record - AlmaLinux follows RHEL's wont-fix
			almaVulns: []vulnerability.Vulnerability{},

			// Vulnerability should be reported with RHEL wont-fix state
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "tar",
						Reference: vulnerability.Reference{
							ID:        "CVE-2005-2541",
							Namespace: "redhat:distro:redhat:8",
						},
						Constraint: createConstraint(t, ">= 0", version.RpmFormat),
						Fix: vulnerability.Fix{
							Versions: []string{},
							State:    vulnerability.FixStateWontFix,
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("tar-scenario4"),
						Name:    "tar",
						Version: "2:1.30-5.el8",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8.0",
						},
						Metadata: pkg.RpmMetadata{
							ModularityLabel: nil,
						},
					},
					Details: createExpectedDetails(pkg.Package{
						Name:    "tar",
						Version: "2:1.30-5.el8",
						Distro:  &distro.Distro{Type: distro.AlmaLinux, Version: "8.0"},
					}, vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2005-2541",
							Namespace: "redhat:distro:redhat:8",
						},
						Constraint: createConstraint(t, ">= 0", version.RpmFormat),
					}),
				},
			},
		},
		{
			name:        "Upstream match: binary package vulnerable via source package with fix replacement",
			description: "Binary package python3-tkinter with upstream python3 - RHEL disclosure for source, AlmaLinux fixes binary",

			pkg: pkg.Package{
				ID:      pkg.ID("python3-tkinter-upstream"),
				Name:    "python3-tkinter",
				Version: "3.6.8-40.el8_6",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.10",
				},
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "python3",
						Version: "3.6.8-40.el8_6",
					},
				},
				Metadata: pkg.RpmMetadata{
					Epoch: intPtr(0),
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "python3",
					Reference: vulnerability.Reference{
						ID:        "CVE-2007-4559",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 0:3.6.8-56.el8_9", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"0:3.6.8-56.el8_9"},
						State:    vulnerability.FixStateFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "python3-tkinter",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2023:7151",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2007-4559"},
					},
					Constraint: createConstraint(t, ">= 3.6.8-56.el8_9.alma.1", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"3.6.8-56.el8_9.alma.1"},
						State:    vulnerability.FixStateFixed,
					},
					Unaffected: true,
				},
			},

			// Package version 3.6.8-40 < fix 3.6.8-56, vulnerable with AlmaLinux fix info
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "python3",
						Reference: vulnerability.Reference{
							ID:        "CVE-2007-4559",
							Namespace: "redhat:distro:redhat:8",
						},
						// Constraint should be updated to match AlmaLinux fix version
						Constraint: createConstraint(t, "< 3.6.8-56.el8_9.alma.1", version.RpmFormat),
						Fix: vulnerability.Fix{
							Versions: []string{"3.6.8-56.el8_9.alma.1"},
							State:    vulnerability.FixStateFixed,
						},
						Advisories: []vulnerability.Advisory{
							{
								ID:   "ALSA-2023:7151",
								Link: "https://errata.almalinux.org/8/ALSA-2023-7151.html",
							},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("python3-tkinter-upstream"),
						Name:    "python3-tkinter",
						Version: "3.6.8-40.el8_6",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8.10",
						},
						Upstreams: []pkg.UpstreamPackage{
							{
								Name:    "python3",
								Version: "3.6.8-40.el8_6",
							},
						},
						Metadata: pkg.RpmMetadata{
							Epoch: intPtr(0),
						},
					},
					// Details should show ExactIndirectMatch since vulnerability is via upstream
					Details: []match.Detail{{
						Type:    match.ExactIndirectMatch,
						Matcher: match.RpmMatcher,
						SearchedBy: match.DistroParameters{
							Distro: match.DistroIdentification{
								Type:    "almalinux",
								Version: "8.10",
							},
							Package: match.PackageParameter{
								Name:    "python3-tkinter",
								Version: "3.6.8-40.el8_6",
							},
							Namespace: "redhat:distro:redhat:8",
						},
						Found: match.DistroResult{
							VulnerabilityID:   "CVE-2007-4559",
							VersionConstraint: "< 3.6.8-56.el8_9.alma.1 (rpm)",
						},
						Confidence: 1.0,
					}},
				},
			},
		},
		{
			name:        "Alias handling: RHEL CVEs filtered by AlmaLinux ALSA with related vulnerabilities",
			description: "RHEL has 2 CVEs, AlmaLinux ALSA relates to one, package >= fix filters that CVE",

			pkg: pkg.Package{
				Name:    "httpd",
				Version: "2.4.37-47.el8.alma",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.7",
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-1234",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 2.4.37-50.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"2.4.37-50.el8"},
						State:    vulnerability.FixStateFixed,
					},
				},
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-5678",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 2.4.37-50.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"2.4.37-50.el8"},
						State:    vulnerability.FixStateFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2023:1234",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2023-1234"}, // ALSA aliases CVE
					},
					// Package version 47 >= fix version 40, so CVE-2023-1234 is filtered
					Constraint: createConstraint(t, ">= 2.4.37-40.el8.alma", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"2.4.37-40.el8.alma"},
						State:    vulnerability.FixStateFixed,
					},
					Unaffected: true,
				},
			},

			// CVE-2023-1234 filtered by AlmaLinux unaffected record
			// Only CVE-2023-5678 should remain (no AlmaLinux unaffected record for it)
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "httpd",
						Reference: vulnerability.Reference{
							ID:        "CVE-2023-5678",
							Namespace: "redhat:distro:redhat:8",
						},
						Constraint: createConstraint(t, "< 2.4.37-50.el8", version.RpmFormat),
						Fix: vulnerability.Fix{
							Versions: []string{"2.4.37-50.el8"},
							State:    vulnerability.FixStateFixed,
						},
					},
					Package: pkg.Package{
						Name:    "httpd",
						Version: "2.4.37-47.el8.alma",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8.7",
						},
					},
					Details: createExpectedDetails(pkg.Package{
						Name:    "httpd",
						Version: "2.4.37-47.el8.alma",
						Distro:  &distro.Distro{Type: distro.AlmaLinux, Version: "8.7"},
					}, vulnerability.Vulnerability{
						Reference: vulnerability.Reference{
							ID:        "CVE-2023-5678",
							Namespace: "redhat:distro:redhat:8",
						},
						Constraint: createConstraint(t, "< 2.4.37-50.el8", version.RpmFormat),
					}),
				},
			},
		},
		{
			name:        "Epoch mismatch regression: no false positive from binary/source epoch difference",
			description: "Binary package epoch 0, upstream source package version without epoch, RHEL constraint has epoch 4",

			pkg: pkg.Package{
				ID:      pkg.ID("perl-errno-epoch"),
				Name:    "perl-Errno",
				Version: "0:1.28-422.el8.0.1",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.10",
				},
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "perl",
						Version: "5.26.3-422.el8.0.1", // No epoch in sourceRPM metadata
					},
				},
				Metadata: pkg.RpmMetadata{
					Epoch: intPtr(0),
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "perl",
					Reference: vulnerability.Reference{
						ID:        "CVE-2020-10543",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 4:5.26.3-419.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"4:5.26.3-419.el8"},
						State:    vulnerability.FixStateFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{},

			// Package version 5.26.3-422 > fix 5.26.3-419, NOT vulnerable
			// This is a regression test: the bug was comparing binary epoch (0) against constraint with source epoch (4),
			// causing false positive: 0:1.28-422.el8.0.1 < 4:5.26.3-419.el8 = true (WRONG!)
			// Correct behavior: Don't add binary epoch to source version, compare without epochs
			expectedMatches: nil,
		},
		{
			name:        "Epoch handling: upstream vulnerable, no AlmaLinux advisory",
			description: "Binary package with upstream source, source version < RHEL fix, no AlmaLinux advisory → match",

			pkg: pkg.Package{
				ID:      pkg.ID("perl-errno-vulnerable"),
				Name:    "perl-Errno",
				Version: "0:1.28-416.el8",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.10",
				},
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "perl",
						Version: "5.26.3-416.el8", // No epoch, version 416 < fix 419
					},
				},
				Metadata: pkg.RpmMetadata{
					Epoch: intPtr(0),
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "perl",
					Reference: vulnerability.Reference{
						ID:        "CVE-2020-10543",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 4:5.26.3-419.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"4:5.26.3-419.el8"},
						State:    vulnerability.FixStateFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{},

			// Package version 5.26.3-416 < fix 5.26.3-419, IS vulnerable
			// No AlmaLinux advisory, so RHEL disclosure should be reported
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "perl",
						Reference: vulnerability.Reference{
							ID:        "CVE-2020-10543",
							Namespace: "redhat:distro:redhat:8",
						},
						Constraint: createConstraint(t, "< 4:5.26.3-419.el8", version.RpmFormat),
						Fix: vulnerability.Fix{
							Versions: []string{"4:5.26.3-419.el8"},
							State:    vulnerability.FixStateFixed,
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("perl-errno-vulnerable"),
						Name:    "perl-Errno",
						Version: "0:1.28-416.el8",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8.10",
						},
						Upstreams: []pkg.UpstreamPackage{
							{
								Name:    "perl",
								Version: "5.26.3-416.el8",
							},
						},
						Metadata: pkg.RpmMetadata{
							Epoch: intPtr(0),
						},
					},
					// Details should show ExactIndirectMatch since vulnerability is via upstream
					Details: []match.Detail{{
						Type:    match.ExactIndirectMatch,
						Matcher: match.RpmMatcher,
						SearchedBy: match.DistroParameters{
							Distro: match.DistroIdentification{
								Type:    "almalinux",
								Version: "8.10",
							},
							Package: match.PackageParameter{
								Name:    "perl-Errno",
								Version: "0:1.28-416.el8",
							},
							Namespace: "redhat:distro:redhat:8",
						},
						Found: match.DistroResult{
							VulnerabilityID:   "CVE-2020-10543",
							VersionConstraint: "< 4:5.26.3-419.el8 (rpm)",
						},
						Confidence: 1.0,
					}},
				},
			},
		},
		{
			name:        "Epoch handling: upstream vulnerable, AlmaLinux fixes binary package",
			description: "Binary package with upstream source, source version < RHEL fix, AlmaLinux fixes binary → filtered",

			pkg: pkg.Package{
				ID:      pkg.ID("perl-errno-alma-fixed"),
				Name:    "perl-Errno",
				Version: "0:1.28-416.el8",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.10",
				},
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "perl",
						Version: "5.26.3-416.el8", // No epoch, version 416 < RHEL fix 419
					},
				},
				Metadata: pkg.RpmMetadata{
					Epoch: intPtr(0),
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "perl",
					Reference: vulnerability.Reference{
						ID:        "CVE-2020-10543",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 4:5.26.3-419.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"4:5.26.3-419.el8"},
						State:    vulnerability.FixStateFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "perl-Errno",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2020:4514",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2020-10543"},
					},
					// AlmaLinux fixes at binary package version 1.28-416.el8, marking it unaffected
					Constraint: createConstraint(t, ">= 1.28-416.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"1.28-416.el8"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "ALSA-2020:4514",
							Link: "https://errata.almalinux.org/8/ALSA-2020-4514.html",
						},
					},
					Unaffected: true,
				},
			},

			// Even though upstream source is vulnerable per RHEL,
			// AlmaLinux marks this binary package version as unaffected
			// Package version 1.28-416.el8 >= AlmaLinux fix 1.28-416.el8 → filtered
			expectedMatches: nil,
		},
		{
			name:        "Epoch handling: upstream vulnerable, AlmaLinux fix on binary, package below fix",
			description: "Binary package with upstream source, source version < RHEL fix, AlmaLinux has fix but package < fix → match with AlmaLinux fix",

			pkg: pkg.Package{
				ID:      pkg.ID("perl-errno-needs-alma-fix"),
				Name:    "perl-Errno",
				Version: "0:1.28-415.el8",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.AlmaLinux,
					Version: "8.10",
				},
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "perl",
						Version: "5.26.3-415.el8", // No epoch, version 415 < RHEL fix 419
					},
				},
				Metadata: pkg.RpmMetadata{
					Epoch: intPtr(0),
				},
			},

			rhelVulns: []vulnerability.Vulnerability{
				{
					PackageName: "perl",
					Reference: vulnerability.Reference{
						ID:        "CVE-2020-10543",
						Namespace: "redhat:distro:redhat:8",
					},
					Constraint: createConstraint(t, "< 4:5.26.3-419.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"4:5.26.3-419.el8"},
						State:    vulnerability.FixStateFixed,
					},
				},
			},

			almaVulns: []vulnerability.Vulnerability{
				{
					PackageName: "perl-Errno",
					Reference: vulnerability.Reference{
						ID:        "ALSA-2020:4514",
						Namespace: "almalinux:distro:almalinux:8",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "CVE-2020-10543"},
					},
					// AlmaLinux fixes at binary package version 1.28-418.el8
					Constraint: createConstraint(t, ">= 1.28-418.el8", version.RpmFormat),
					Fix: vulnerability.Fix{
						Versions: []string{"1.28-418.el8"},
						State:    vulnerability.FixStateFixed,
					},
					Advisories: []vulnerability.Advisory{
						{
							ID:   "ALSA-2020:4514",
							Link: "https://errata.almalinux.org/8/ALSA-2020-4514.html",
						},
					},
					Unaffected: true,
				},
			},

			// Upstream source is vulnerable per RHEL (415 < 419)
			// Binary package version 1.28-415.el8 < AlmaLinux fix 1.28-418.el8
			// Should report vulnerability with AlmaLinux fix info (fix replacement)
			expectedMatches: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						PackageName: "perl",
						Reference: vulnerability.Reference{
							ID:        "CVE-2020-10543",
							Namespace: "redhat:distro:redhat:8",
						},
						// Constraint should be updated to match AlmaLinux fix version
						Constraint: createConstraint(t, "< 1.28-418.el8", version.RpmFormat),
						Fix: vulnerability.Fix{
							Versions: []string{"1.28-418.el8"},
							State:    vulnerability.FixStateFixed,
						},
						Advisories: []vulnerability.Advisory{
							{
								ID:   "ALSA-2020:4514",
								Link: "https://errata.almalinux.org/8/ALSA-2020-4514.html",
							},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("perl-errno-needs-alma-fix"),
						Name:    "perl-Errno",
						Version: "0:1.28-415.el8",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.AlmaLinux,
							Version: "8.10",
						},
						Upstreams: []pkg.UpstreamPackage{
							{
								Name:    "perl",
								Version: "5.26.3-415.el8",
							},
						},
						Metadata: pkg.RpmMetadata{
							Epoch: intPtr(0),
						},
					},
					// Details should show ExactIndirectMatch since vulnerability is via upstream
					Details: []match.Detail{{
						Type:    match.ExactIndirectMatch,
						Matcher: match.RpmMatcher,
						SearchedBy: match.DistroParameters{
							Distro: match.DistroIdentification{
								Type:    "almalinux",
								Version: "8.10",
							},
							Package: match.PackageParameter{
								Name:    "perl-Errno",
								Version: "0:1.28-415.el8",
							},
							Namespace: "redhat:distro:redhat:8",
						},
						Found: match.DistroResult{
							VulnerabilityID:   "CVE-2020-10543",
							VersionConstraint: "< 1.28-418.el8 (rpm)",
						},
						Confidence: 1.0,
					}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock provider with all vulnerabilities
			allVulns := append(tt.rhelVulns, tt.almaVulns...)
			mockProvider := &MockProvider{
				findResultsFunc: func(criteria ...vulnerability.Criteria) (result.Set, error) {
					// Use the mock vulnerability provider to filter
					vulnProvider := mock.VulnerabilityProvider(allVulns...)
					vulns, err := vulnProvider.FindVulnerabilities(criteria...)
					if err != nil {
						return nil, err
					}

					// Convert to result.Set with Details fully populated
					resultSet := make(result.Set)
					for _, vuln := range vulns {
						r := result.Result{
							ID:              vuln.ID,
							Vulnerabilities: []vulnerability.Vulnerability{vuln},
							Package:         &tt.pkg,
							// Details must be fully populated per the matcher contract
							Details: []match.Detail{{
								Type:    match.ExactDirectMatch,
								Matcher: match.RpmMatcher,
								SearchedBy: match.DistroParameters{
									Distro: match.DistroIdentification{
										Type:    tt.pkg.Distro.Type.String(),
										Version: tt.pkg.Distro.Version,
									},
									Package: match.PackageParameter{
										Name:    tt.pkg.Name,
										Version: tt.pkg.Version,
									},
									Namespace: vuln.Namespace,
								},
								Found: match.DistroResult{
									VulnerabilityID:   vuln.ID,
									VersionConstraint: vuln.Constraint.String(),
								},
								Confidence: 1.0,
							}},
						}
						resultSet[vuln.ID] = append(resultSet[vuln.ID], r)
					}
					return resultSet, nil
				},
			}

			// Call the matcher
			matches, err := almaLinuxMatchesWithUpstreams(mockProvider, tt.pkg)
			require.NoError(t, err)

			// Compare matches using cmp.Diff
			// Only ignore:
			// - PackageQualifiers (tested separately, have unexported fields in implementations)
			// - Unexported fields within structs
			if diff := cmp.Diff(tt.expectedMatches, matches,
				cmpopts.IgnoreUnexported(match.Match{}, match.Detail{}, pkg.Package{}, pkg.RpmMetadata{}, file.LocationSet{}, distro.Distro{}),
				cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "PackageQualifiers")); diff != "" {
				t.Errorf("matches mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Helper functions for tests

func createConstraint(t *testing.T, constraintStr string, format version.Format) version.Constraint {
	constraint, err := version.GetConstraint(constraintStr, format)
	require.NoError(t, err)
	return constraint
}

func createExpectedDetails(pkg pkg.Package, vuln vulnerability.Vulnerability) []match.Detail {
	return []match.Detail{{
		Type:    match.ExactDirectMatch,
		Matcher: match.RpmMatcher,
		SearchedBy: match.DistroParameters{
			Distro: match.DistroIdentification{
				Type:    pkg.Distro.Type.String(),
				Version: pkg.Distro.Version,
			},
			Package: match.PackageParameter{
				Name:    pkg.Name,
				Version: pkg.Version,
			},
			Namespace: vuln.Reference.Namespace,
		},
		Found: match.DistroResult{
			VulnerabilityID:   vuln.Reference.ID,
			VersionConstraint: vuln.Constraint.String(),
		},
		Confidence: 1.0,
	}}
}

func strPtr(s string) *string {
	return &s
}
