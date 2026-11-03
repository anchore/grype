package dbsearch

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
)

func TestGetFixStateFromBlob(t *testing.T) {
	tests := []struct {
		name     string
		blob     *v6.PackageBlob
		expected string
	}{
		{
			name:     "nil blob returns unknown",
			blob:     nil,
			expected: "unknown",
		},
		{
			name:     "empty blob returns unknown",
			blob:     &v6.PackageBlob{},
			expected: "unknown",
		},
		{
			name: "blob with fixed status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   v6.FixedStatus,
							Version: "1.2.3",
						},
					},
				},
			},
			expected: "fixed",
		},
		{
			name: "blob with not-fixed status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotFixedStatus,
						},
					},
				},
			},
			expected: "not-fixed",
		},
		{
			name: "blob with wont-fix status",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.WontFixStatus,
						},
					},
				},
			},
			expected: "wont-fix",
		},
		{
			name: "blob with no fix returns unknown",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: nil,
					},
				},
			},
			expected: "unknown",
		},
		{
			name: "blob with mixed statuses prefers fixed",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotFixedStatus,
						},
					},
					{
						Fix: &v6.Fix{
							State:   v6.FixedStatus,
							Version: "2.0.0",
						},
					},
				},
			},
			expected: "fixed",
		},
		{
			name: "blob with wont-fix and not-fixed prefers wont-fix",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotFixedStatus,
						},
					},
					{
						Fix: &v6.Fix{
							State: v6.WontFixStatus,
						},
					},
				},
			},
			expected: "wont-fix",
		},
		{
			name: "not-affected is a record type, not a blob fix state",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotAffectedFixStatus,
						},
					},
				},
			},
			expected: "unknown",
		},
		{
			name: "blob with fixed and not-affected prefers fixed",
			blob: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State: v6.NotAffectedFixStatus,
						},
					},
					{
						Fix: &v6.Fix{
							State:   v6.FixedStatus,
							Version: "2.0.0",
						},
					},
				},
			},
			expected: "fixed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFixStateFromPackageBlob(tt.blob)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterByFixedState(t *testing.T) {
	tests := []struct {
		name         string
		packages     []affectedPackageWithDecorations
		fixedStates  []string
		expectedLen  int
		expectedStrs []string
	}{
		{
			name:         "empty fixed states returns all packages",
			packages:     makeTestPackages(3),
			fixedStates:  []string{},
			expectedLen:  3,
			expectedStrs: nil,
		},
		{
			name: "filter by fixed state",
			packages: []affectedPackageWithDecorations{
				makePackageWithFixState(v6.FixedStatus),
				makePackageWithFixState(v6.NotFixedStatus),
				makePackageWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"fixed"},
			expectedLen:  1,
			expectedStrs: []string{"fixed"},
		},
		{
			name: "filter by multiple states",
			packages: []affectedPackageWithDecorations{
				makePackageWithFixState(v6.FixedStatus),
				makePackageWithFixState(v6.NotFixedStatus),
				makePackageWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"fixed", "wont-fix"},
			expectedLen:  2,
			expectedStrs: []string{"fixed", "wont-fix"},
		},
		{
			name: "filter with no matches",
			packages: []affectedPackageWithDecorations{
				makePackageWithFixState(v6.NotFixedStatus),
				makePackageWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"fixed"},
			expectedLen:  0,
			expectedStrs: nil,
		},
		{
			name: "packages with nil blob are filtered out",
			packages: []affectedPackageWithDecorations{
				makePackageWithFixState(v6.FixedStatus),
				{AffectedPackageHandle: v6.AffectedPackageHandle{BlobValue: nil}},
			},
			fixedStates:  []string{"fixed", "unknown"},
			expectedLen:  1,
			expectedStrs: []string{"fixed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterByFixedStateForPackages(tt.packages, tt.fixedStates)
			assert.Equal(t, tt.expectedLen, len(result))

			if tt.expectedStrs != nil {
				var resultStates []string
				for _, pkg := range result {
					resultStates = append(resultStates, getFixStateFromPackageBlob(pkg.BlobValue))
				}
				assert.ElementsMatch(t, tt.expectedStrs, resultStates)
			}
		})
	}
}

func TestFilterCPEsByFixedState(t *testing.T) {
	tests := []struct {
		name         string
		cpes         []affectedCPEWithDecorations
		fixedStates  []string
		expectedLen  int
		expectedStrs []string
	}{
		{
			name:         "empty fixed states returns all CPEs",
			cpes:         makeTestCPEs(3),
			fixedStates:  []string{},
			expectedLen:  3,
			expectedStrs: nil,
		},
		{
			name: "filter by fixed state",
			cpes: []affectedCPEWithDecorations{
				makeCPEWithFixState(v6.FixedStatus),
				makeCPEWithFixState(v6.NotFixedStatus),
				makeCPEWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"fixed"},
			expectedLen:  1,
			expectedStrs: []string{"fixed"},
		},
		{
			name: "filter by multiple states",
			cpes: []affectedCPEWithDecorations{
				makeCPEWithFixState(v6.FixedStatus),
				makeCPEWithFixState(v6.NotFixedStatus),
				makeCPEWithFixState(v6.WontFixStatus),
			},
			fixedStates:  []string{"not-fixed", "wont-fix"},
			expectedLen:  2,
			expectedStrs: []string{"not-fixed", "wont-fix"},
		},
		{
			name: "CPEs with nil blob are filtered out",
			cpes: []affectedCPEWithDecorations{
				makeCPEWithFixState(v6.FixedStatus),
				{AffectedCPEHandle: v6.AffectedCPEHandle{BlobValue: nil}},
			},
			fixedStates:  []string{"fixed", "unknown"},
			expectedLen:  1,
			expectedStrs: []string{"fixed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterByFixedStateForCPEs(tt.cpes, tt.fixedStates)
			assert.Equal(t, tt.expectedLen, len(result))

			if tt.expectedStrs != nil {
				var resultStates []string
				for _, cpe := range result {
					resultStates = append(resultStates, getFixStateFromPackageBlob(cpe.BlobValue))
				}
				assert.ElementsMatch(t, tt.expectedStrs, resultStates)
			}
		})
	}
}

func makeTestPackages(count int) []affectedPackageWithDecorations {
	packages := make([]affectedPackageWithDecorations, count)
	for i := range count {
		packages[i] = affectedPackageWithDecorations{
			AffectedPackageHandle: v6.AffectedPackageHandle{
				BlobValue: &v6.PackageBlob{},
			},
		}
	}
	return packages
}

func makePackageWithFixState(state v6.FixStatus) affectedPackageWithDecorations {
	return affectedPackageWithDecorations{
		AffectedPackageHandle: v6.AffectedPackageHandle{
			BlobValue: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   state,
							Version: "1.0.0",
						},
					},
				},
			},
		},
	}
}

func makeTestCPEs(count int) []affectedCPEWithDecorations {
	cpes := make([]affectedCPEWithDecorations, count)
	for i := range count {
		cpes[i] = affectedCPEWithDecorations{
			AffectedCPEHandle: v6.AffectedCPEHandle{
				BlobValue: &v6.PackageBlob{},
			},
		}
	}
	return cpes
}

func makeCPEWithFixState(state v6.FixStatus) affectedCPEWithDecorations {
	return affectedCPEWithDecorations{
		AffectedCPEHandle: v6.AffectedCPEHandle{
			BlobValue: &v6.PackageBlob{
				Ranges: []v6.Range{
					{
						Fix: &v6.Fix{
							State:   state,
							Version: "1.0.0",
						},
					},
				},
			},
		},
	}
}

func TestNewMatchesRows_Unaffected(t *testing.T) {
	vuln := &v6.VulnerabilityHandle{ID: 1, Name: "CVE-2024-0001", Provider: &v6.Provider{ID: "provider1"}, BlobValue: &v6.VulnerabilityBlob{ID: "CVE-2024-0001"}}
	unaffectedOnlyVuln := &v6.VulnerabilityHandle{ID: 2, Name: "CVE-2024-0002", Provider: &v6.Provider{ID: "provider1"}, BlobValue: &v6.VulnerabilityBlob{ID: "CVE-2024-0002"}}

	unaffectedBlob := &v6.PackageBlob{Ranges: []v6.Range{{Version: v6.Version{Constraint: ">= 1.0.0"}, Fix: &v6.Fix{State: v6.FixedStatus, Version: "1.0.0"}}}}

	records := packageRecords{
		affectedPkgs: []affectedPackageWithDecorations{
			{
				AffectedPackageHandle: v6.AffectedPackageHandle{
					Vulnerability: vuln,
					Package:       &v6.Package{Name: "affected-pkg", Ecosystem: "npm"},
				},
			},
		},
		unaffectedPkgs: []affectedPackageWithDecorations{
			{
				AffectedPackageHandle: v6.AffectedPackageHandle{
					Vulnerability: vuln,
					Package:       &v6.Package{Name: "unaffected-pkg", Ecosystem: "npm"},
					BlobValue:     unaffectedBlob,
				},
			},
			{
				AffectedPackageHandle: v6.AffectedPackageHandle{
					Vulnerability: unaffectedOnlyVuln,
					Package:       &v6.Package{Name: "unaffected-pkg", Ecosystem: "npm"},
				},
			},
		},
		unaffectedCPEs: []affectedCPEWithDecorations{
			{
				AffectedCPEHandle: v6.AffectedCPEHandle{
					Vulnerability: vuln,
					CPE:           &v6.Cpe{Part: "a", Vendor: "vendor", Product: "unaffected-product"},
				},
			},
		},
	}

	rows, err := newMatchesRows(records)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	// unaffected records are kept in a separate list, and stored details are not modified
	row := rows[0]
	assert.Equal(t, "CVE-2024-0001", row.Vulnerability.ID)
	require.Len(t, row.AffectedPackages, 1)
	assert.Equal(t, "affected-pkg", row.AffectedPackages[0].Package.Name)

	require.Len(t, row.Unaffected, 2)
	assert.Equal(t, "unaffected-pkg", row.Unaffected[0].Package.Name)
	assert.Equal(t, *unaffectedBlob, row.Unaffected[0].Detail)
	assert.Equal(t, "unaffected-product", row.Unaffected[1].CPE.Product)
	assert.Empty(t, row.Unaffected[1].Detail.Ranges)

	// packages is always present, even when there are only unaffected records
	row = rows[1]
	assert.Equal(t, "CVE-2024-0002", row.Vulnerability.ID)
	assert.NotNil(t, row.AffectedPackages)
	assert.Empty(t, row.AffectedPackages)
	require.Len(t, row.Unaffected, 1)

	by, err := json.Marshal(rows)
	require.NoError(t, err)
	var doc []struct {
		Packages   *[]json.RawMessage `json:"packages"`
		Unaffected []json.RawMessage  `json:"unaffected"`
	}
	require.NoError(t, json.Unmarshal(by, &doc))
	require.Len(t, doc, 2)
	require.NotNil(t, doc[1].Packages)
	assert.Empty(t, *doc[1].Packages)
	assert.Len(t, doc[1].Unaffected, 1)
}

func TestFindMatches_FixStatesWithUnaffectedRecords(t *testing.T) {
	vuln := func(id v6.ID, name string) *v6.VulnerabilityHandle {
		return &v6.VulnerabilityHandle{ID: id, Name: name, Provider: &v6.Provider{ID: "provider1"}}
	}
	blob := func(state v6.FixStatus) *v6.PackageBlob {
		return &v6.PackageBlob{Ranges: []v6.Range{{Fix: &v6.Fix{State: state}}}}
	}
	fixedVuln := vuln(1, "CVE-2024-0001")
	notFixedVuln := vuln(2, "CVE-2024-0002")
	unaffectedOnlyVuln := vuln(3, "CVE-2024-0003")

	reader := func() *affectedMockReader {
		m := new(affectedMockReader)
		m.On("GetAffectedPackages", mock.Anything, mock.Anything).Return([]v6.AffectedPackageHandle{
			{Vulnerability: fixedVuln, BlobValue: blob(v6.FixedStatus)},
			{Vulnerability: notFixedVuln, BlobValue: blob(v6.NotFixedStatus)},
		}, nil)
		m.On("GetAffectedCPEs", mock.Anything, mock.Anything).Return([]v6.AffectedCPEHandle{}, nil)
		m.On("GetUnaffectedPackages", mock.Anything, mock.Anything).Return([]v6.UnaffectedPackageHandle{
			{Vulnerability: fixedVuln, BlobValue: blob(v6.NotAffectedFixStatus)},
			{Vulnerability: unaffectedOnlyVuln, BlobValue: blob(v6.FixedStatus)},
		}, nil)
		m.On("GetUnaffectedCPEs", mock.Anything, mock.Anything).Return([]v6.UnaffectedCPEHandle{}, nil)
		m.On("GetKnownExploitedVulnerabilities", mock.Anything).Return([]v6.KnownExploitedVulnerabilityHandle{}, nil)
		m.On("GetEpss", mock.Anything).Return([]v6.EpssHandle{}, nil)
		return m
	}

	// counts returns the affected and unaffected record counts of each vulnerability in the matches
	counts := func(matches Matches) map[string][2]int {
		got := make(map[string][2]int)
		for _, m := range matches {
			got[m.Vulnerability.Model.Name] = [2]int{len(m.AffectedPackages), len(m.Unaffected)}
		}
		return got
	}

	tests := []struct {
		name     string
		criteria AffectedPackagesOptions
		want     map[string][2]int
	}{
		{
			name:     "unaffected records are kept only for vulnerabilities with affected records left after the fix state filter",
			criteria: AffectedPackagesOptions{IncludeUnaffected: true, FixedStates: []string{"fixed"}},
			want:     map[string][2]int{"CVE-2024-0001": {1, 1}},
		},
		{
			name:     "not-affected with another state keeps every unaffected record, regardless of the stored fix state",
			criteria: AffectedPackagesOptions{FixedStates: []string{"not-affected", "fixed"}},
			want: map[string][2]int{
				"CVE-2024-0001": {1, 1},
				"CVE-2024-0003": {0, 1},
			},
		},
		{
			name:     "unaffected records without a fix state filter",
			criteria: AffectedPackagesOptions{IncludeUnaffected: true},
			want: map[string][2]int{
				"CVE-2024-0001": {1, 1},
				"CVE-2024-0002": {1, 0},
				"CVE-2024-0003": {0, 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.criteria.Vulnerability = v6.VulnerabilitySpecifiers{{Name: "CVE-2024"}}
			matches, err := FindMatches(reader(), tt.criteria)
			require.NoError(t, err)
			assert.Equal(t, tt.want, counts(matches))
		})
	}
}

func TestFindMatches_IncludeAliases(t *testing.T) {
	m := new(affectedMockReader)
	defer m.AssertExpectations(t)
	m.On("GetVulnerabilityAliases", []string{"GHSA-aaaa-aaaa-aaaa"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
		{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
	}, nil).Once()
	m.On("GetVulnerabilityAliases", []string{"CVE-2024-0001"}, maxAliasRows).Return([]v6.VulnerabilityAlias{
		{Name: "GHSA-aaaa-aaaa-aaaa", Alias: "CVE-2024-0001"},
	}, nil).Once()

	// the aliases are resolved once, and every query sees the expanded names with the original filters
	expanded := []v6.VulnerabilitySpecifier{
		{Name: "GHSA-aaaa-aaaa-aaaa", Providers: []string{"github"}},
		{Name: "CVE-2024-0001", Providers: []string{"github"}},
	}
	m.On("GetAffectedPackages", mock.Anything, mock.MatchedBy(func(o *v6.GetPackageOptions) bool {
		return assert.ObjectsAreEqual(expanded, []v6.VulnerabilitySpecifier(o.Vulnerabilities))
	})).Return([]v6.AffectedPackageHandle{}, nil).Once()
	m.On("GetAffectedCPEs", mock.Anything, mock.MatchedBy(func(o *v6.GetCPEOptions) bool {
		return assert.ObjectsAreEqual(expanded, o.Vulnerabilities)
	})).Return([]v6.AffectedCPEHandle{}, nil).Once()

	_, err := FindMatches(m, AffectedPackagesOptions{
		Vulnerability:  v6.VulnerabilitySpecifiers{{Name: "GHSA-aaaa-aaaa-aaaa", Providers: []string{"github"}}},
		IncludeAliases: true,
	})
	require.NoError(t, err)
}
