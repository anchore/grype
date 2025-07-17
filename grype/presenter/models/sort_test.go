package models

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSortStrategies(t *testing.T) {
	strategies := SortStrategies()
	expected := []SortStrategy{
		SortByPackage,
		SortBySeverity,
		SortByThreat,
		SortByRisk,
		SortByKEV,
		SortByVulnerability,
	}
	assert.Equal(t, expected, strategies)
}

func TestSortStrategyString(t *testing.T) {
	assert.Equal(t, "package", SortByPackage.String())
	assert.Equal(t, "severity", SortBySeverity.String())
	assert.Equal(t, "epss", SortByThreat.String())
	assert.Equal(t, "risk", SortByRisk.String())
	assert.Equal(t, "kev", SortByKEV.String())
	assert.Equal(t, "vulnerability", SortByVulnerability.String())
}

func TestGetSortStrategy(t *testing.T) {
	tests := []struct {
		name         string
		strategyName SortStrategy
		expected     bool
	}{
		{
			name:         "Valid strategy",
			strategyName: SortByPackage,
			expected:     true,
		},
		{
			name:         "Invalid strategy",
			strategyName: "invalid",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := getSortStrategy(tt.strategyName)
			validStrategy, _ := matchSortStrategy[tt.strategyName]

			if tt.expected {
				require.NotNil(t, strategy)
				assert.Equal(t, validStrategy, strategy)
			} else {
				// Should fallback to default strategy
				assert.NotNil(t, strategy)
				assert.Equal(t, matchSortStrategy[DefaultSortStrategy], strategy)
			}
		})
	}
}

func TestEPSSPercentile(t *testing.T) {
	tests := []struct {
		name     string
		epss     []EPSS
		expected float64
	}{
		{
			name:     "Empty slice",
			epss:     []EPSS{},
			expected: 0.0,
		},
		{
			name: "Single item",
			epss: []EPSS{
				{Percentile: 0.75},
			},
			expected: 0.75,
		},
		{
			name: "Multiple items, already sorted",
			epss: []EPSS{
				{Percentile: 0.95},
				{Percentile: 0.75},
				{Percentile: 0.50},
			},
			expected: 0.95,
		},
		{
			name: "Multiple items, unsorted",
			epss: []EPSS{
				{Percentile: 0.50},
				{Percentile: 0.95},
				{Percentile: 0.75},
			},
			expected: 0.95,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := epssPercentile(tt.epss)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSeverityPriority(t *testing.T) {
	tests := []struct {
		severity string
		expected int
	}{
		{"critical", 1},
		{"CRITICAL", 1},
		{"high", 2},
		{"HIGH", 2},
		{"medium", 3},
		{"MEDIUM", 3},
		{"low", 4},
		{"LOW", 4},
		{"negligible", 5},
		{"NEGLIGIBLE", 5},
		{"unknown", 100},
		{"", 100},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := severityPriority(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func createTestMatches() []Match {
	return []Match{
		{
			// match 0: medium severity, high risk, high EPSS, no KEV
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-1111",
					Severity: "medium",
					EPSS: []EPSS{
						{Percentile: 0.90},
					},
					KnownExploited: []KnownExploited{}, // empty KEV
				},
				Risk: 75.0,
			},
			Artifact: Package{
				Name:    "package-b",
				Version: "1.2.0",
				Type:    "npm",
			},
		},
		{
			// match 1: critical severity, medium risk, medium EPSS, no KEV
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-2222",
					Severity: "critical",
					EPSS: []EPSS{
						{Percentile: 0.70},
					},
					KnownExploited: []KnownExploited{}, // empty KEV
				},
				Risk: 50.0,
			},
			Artifact: Package{
				Name:    "package-a",
				Version: "2.0.0",
				Type:    "docker",
			},
		},
		{
			// match 2: high severity, low risk, low EPSS, has KEV
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-3333",
					Severity: "high",
					EPSS: []EPSS{
						{Percentile: 0.30},
					},
					KnownExploited: []KnownExploited{
						{CVE: "CVE-2023-3333", KnownRansomwareCampaignUse: "No"},
					}, // has KEV
				},
				Risk: 25.0,
			},
			Artifact: Package{
				Name:    "package-a",
				Version: "1.0.0",
				Type:    "npm",
			},
		},
		{
			// match 3: low severity, very low risk, very low EPSS, no KEV
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-4444",
					Severity: "low",
					EPSS: []EPSS{
						{Percentile: 0.10},
					},
					KnownExploited: []KnownExploited{}, // empty KEV
				},
				Risk: 10.0,
			},
			Artifact: Package{
				Name:    "package-c",
				Version: "3.1.0",
				Type:    "gem",
			},
		},
		{
			// match 4: critical severity, very low risk, medium EPSS, has KEV with ransomware
			Vulnerability: Vulnerability{
				VulnerabilityMetadata: VulnerabilityMetadata{
					ID:       "CVE-2023-5555",
					Severity: "critical",
					EPSS: []EPSS{
						{Percentile: 0.50},
					},
					KnownExploited: []KnownExploited{
						{CVE: "CVE-2023-5555", KnownRansomwareCampaignUse: "Known"},
						{CVE: "CVE-2023-5555", KnownRansomwareCampaignUse: "Known", Product: "Different Product"},
					}, // has multiple KEV entries with ransomware
				},
				Risk: 5.0,
			},
			Artifact: Package{
				Name:    "package-a",
				Version: "1.0.0",
				Type:    "docker",
			},
		},
	}
}

func TestAllSortStrategies(t *testing.T) {
	matches := createTestMatches()

	tests := []struct {
		strategy SortStrategy
		expected []int // indexes into the original matches slice
	}{
		{
			strategy: SortByPackage,
			expected: []int{4, 2, 1, 0, 3}, // sorted by package name, version, type
		},
		{
			strategy: SortByVulnerability,
			expected: []int{0, 1, 2, 3, 4}, // sorted by vulnerability ID
		},
		{
			strategy: SortBySeverity,
			expected: []int{1, 4, 2, 0, 3}, // sorted by severity: critical, critical, high, medium, low
		},
		{
			strategy: SortByThreat,
			expected: []int{0, 1, 4, 2, 3}, // sorted by EPSS percentile: 0.90, 0.70, 0.50, 0.30, 0.10
		},
		{
			strategy: SortByRisk,
			expected: []int{0, 1, 2, 3, 4}, // sorted by risk: 75.0, 50.0, 25.0, 10.0, 5.0
		},
		{
			strategy: SortByKEV,
			expected: []int{4, 2, 0, 1, 3}, // sorted by KEV count: 2, 1, 0, 0, 0 (with ties broken by risk)
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.strategy), func(t *testing.T) {
			testMatches := deepCopyMatches(matches)
			SortMatches(testMatches, tt.strategy)

			expected := make([]Match, len(tt.expected))
			for i, idx := range tt.expected {
				expected[i] = matches[idx]
			}

			if diff := cmp.Diff(expected, testMatches); diff != "" {
				t.Errorf("%s mismatch (-want +got):\n%s", tt.strategy, diff)
			}
		})
	}
}

func TestIndividualCompareFunctions(t *testing.T) {
	ms := createTestMatches()
	m0 := ms[0] // medium severity, high risk, high EPSS, no KEV
	m1 := ms[1] // critical severity, medium risk, medium EPSS, no KEV
	m2 := ms[2] // high severity, low risk, low EPSS, has KEV
	m3 := ms[3] // low severity, very low risk, very low EPSS, no KEV
	m4 := ms[4] // critical severity, very low risk, medium EPSS, has KEV with ransomware

	tests := []struct {
		name        string
		compareFunc compareFunc
		pairs       []struct {
			a, b     Match
			expected int
		}
	}{
		{
			name:        "compareByVulnerabilityID",
			compareFunc: compareByVulnerabilityID,
			pairs: []struct {
				a, b     Match
				expected int
			}{
				{m0, m1, -1}, // CVE-2023-1111 < CVE-2023-2222
				{m1, m0, 1},  // CVE-2023-2222 > CVE-2023-1111
				{m0, m0, 0},  // Same ID
			},
		},
		{
			name:        "compareBySeverity",
			compareFunc: compareBySeverity,
			pairs: []struct {
				a, b     Match
				expected int
			}{
				{m0, m1, 1},  // medium > critical
				{m1, m0, -1}, // critical < medium
				{m1, m4, 0},  // both critical
				{m2, m3, -1}, // high < low
			},
		},
		{
			name:        "compareByEPSSPercentile",
			compareFunc: compareByEPSSPercentile,
			pairs: []struct {
				a, b     Match
				expected int
			}{
				{m0, m1, -1}, // 0.90 > 0.70
				{m1, m0, 1},  // 0.70 < 0.90
				{m1, m4, -1}, // 0.70 > 0.50
				{m4, m1, 1},  // 0.50 < 0.70
			},
		},
		{
			name:        "compareByPackageName",
			compareFunc: compareByPackageName,
			pairs: []struct {
				a, b     Match
				expected int
			}{
				{m0, m1, 1},  // package-b > package-a
				{m1, m0, -1}, // package-a < package-b
				{m1, m2, 0},  // both package-a
			},
		},
		{
			name:        "compareByPackageVersion",
			compareFunc: compareByPackageVersion,
			pairs: []struct {
				a, b     Match
				expected int
			}{
				{m1, m2, 1},  // 2.0.0 > 1.0.0
				{m2, m1, -1}, // 1.0.0 < 2.0.0
				{m2, m4, 0},  // both 1.0.0
			},
		},
		{
			name:        "compareByPackageType",
			compareFunc: compareByPackageType,
			pairs: []struct {
				a, b     Match
				expected int
			}{
				{m0, m1, 1},  // npm > docker
				{m1, m0, -1}, // docker < npm
				{m0, m2, 0},  // both npm
			},
		},
		{
			name:        "compareByRisk",
			compareFunc: compareByRisk,
			pairs: []struct {
				a, b     Match
				expected int
			}{
				{m0, m1, -1}, // 75.0 > 50.0
				{m1, m0, 1},  // 50.0 < 75.0
				{m3, m4, -1}, // 10.0 > 5.0
			},
		},
		{
			name:        "compareByKEV",
			compareFunc: compareByKEV,
			pairs: []struct {
				a, b     Match
				expected int
			}{
				{m0, m2, 1},  // 0 < 1 KEV entry
				{m2, m0, -1}, // 1 > 0 KEV entry
				{m2, m4, 1},  // 1 < 2 KEV entries
				{m4, m2, -1}, // 2 > 1 KEV entry
				{m0, m1, 0},  // both 0 KEV entries
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, pair := range tt.pairs {
				result := tt.compareFunc(pair.a, pair.b)
				assert.Equal(t, pair.expected, result, "comparing %v and %v", pair.a.Vulnerability.ID, pair.b.Vulnerability.ID)
			}
		})
	}
}

func TestCombinedCompareFunctions(t *testing.T) {
	ms := createTestMatches()
	m0 := ms[0] // medium severity, high risk, high EPSS, no KEV, package-b
	m1 := ms[1] // critical severity, medium risk, medium EPSS, no KEV, package-a
	m2 := ms[2] // high severity, low risk, low EPSS, has KEV, package-a

	t.Run("compareVulnerabilityAttributes", func(t *testing.T) {
		result := compareVulnerabilityAttributes(m0, m1)
		assert.Equal(t, -1, result, "CVE-2023-1111 should come before CVE-2023-2222")

		result = compareVulnerabilityAttributes(m1, m0)
		assert.Equal(t, 1, result, "CVE-2023-2222 should come after CVE-2023-1111")
	})

	t.Run("comparePackageAttributes", func(t *testing.T) {
		result := comparePackageAttributes(m0, m1)
		assert.Equal(t, 1, result, "package-b should come after package-a")

		result = comparePackageAttributes(m1, m2)
		assert.Equal(t, 1, result, "package-a 2.0.0 should come after package-a 1.0.0")

		result = comparePackageAttributes(m1, m1)
		assert.Equal(t, 0, result, "same package should be equal")
	})

	t.Run("combine function", func(t *testing.T) {
		// create a combined function that first compares by severity, then by risk if severity is equal
		combined := combine(compareBySeverity, compareByRisk)

		result := combined(m0, m1)
		assert.Equal(t, 1, result, "medium should come after critical regardless of risk")

		// create two matches with the same severity but different risk
		m5 := m1 // critical severity, risk 50.0
		m6 := m1
		m6.Vulnerability.Risk = 60.0 // critical severity, risk 60.0

		result = combined(m5, m6)
		assert.Equal(t, 1, result, "with equal severity, lower risk (50.0) should come after higher risk (60.0)")

		result = combined(m6, m5)
		assert.Equal(t, -1, result, "with equal severity, higher risk (60.0) should come before lower risk (50.0)")
	})
}

func TestSortWithStrategy(t *testing.T) {
	matches := createTestMatches()

	// create a custom strategy that sorts only by vulnerability ID
	customStrategy := sortStrategyImpl{compareByVulnerabilityID}

	expected := []Match{
		matches[0], // CVE-2023-1111
		matches[1], // CVE-2023-2222
		matches[2], // CVE-2023-3333
		matches[3], // CVE-2023-4444
		matches[4], // CVE-2023-5555
	}

	testMatches := deepCopyMatches(matches)
	sortWithStrategy(testMatches, customStrategy)

	if diff := cmp.Diff(expected, testMatches); diff != "" {
		t.Errorf("sortWithStrategy mismatch (-want +got):\n%s", diff)
	}

	// create an empty strategy (should not change the order)
	emptyStrategy := sortStrategyImpl{}
	originalMatches := deepCopyMatches(matches)
	sortWithStrategy(originalMatches, emptyStrategy)

	if diff := cmp.Diff(matches, originalMatches); diff != "" {
		t.Errorf("Empty strategy should not change order (-original +after):\n%s", diff)
	}
}

func deepCopyMatches(matches []Match) []Match {
	result := make([]Match, len(matches))
	copy(result, matches)
	return result
}
