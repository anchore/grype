package cyclonedx

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	vexStatus "github.com/anchore/grype/grype/vex/status"
	"github.com/anchore/grype/grype/vulnerability"
)

const (
	testDataDir = "../../vex/testdata/vex-docs"
)

func TestIsCycloneDX(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		expected bool
	}{
		{
			name:     "cdx-demo1.json is a CycloneDX document",
			file:     testDataDir + "/cdx-demo1.json",
			expected: true,
		},
		{
			name:     "cdx-alpine.json is a CycloneDX document",
			file:     testDataDir + "/cdx-alpine.json",
			expected: true,
		},
		{
			name:     "openvex document is not CycloneDX",
			file:     testDataDir + "/openvex-demo1.json",
			expected: false,
		},
		{
			name:     "nonexistent file is not CycloneDX",
			file:     testDataDir + "/does-not-exist.json",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsCycloneDX(tt.file))
		})
	}
}

func TestReadVexDocuments(t *testing.T) {
	p := New()

	t.Run("reads cdx-demo1.json successfully", func(t *testing.T) {
		result, err := p.ReadVexDocuments([]string{testDataDir + "/cdx-demo1.json"})
		require.NoError(t, err)
		require.NotNil(t, result)
		boms, ok := result.([]*cdx.BOM)
		require.True(t, ok)
		require.Len(t, boms, 1)
		require.NotNil(t, boms[0].Vulnerabilities)
		assert.Len(t, *boms[0].Vulnerabilities, 1)
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		_, err := p.ReadVexDocuments([]string{testDataDir + "/does-not-exist.json"})
		require.Error(t, err)
	})
}

func TestFilterMatches_NotAffected(t *testing.T) {
	// cdx-demo1.json has CVE-2026-12345 with state "not_affected" for pkg:generic/sample-app@1.0.0
	p := New()

	docRaw, err := p.ReadVexDocuments([]string{testDataDir + "/cdx-demo1.json"})
	require.NoError(t, err)

	affectedMatch := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2026-12345"},
		},
		Package: pkg.Package{
			Name: "sample-app",
			PURL: "pkg:generic/sample-app@1.0.0",
		},
	}
	unrelatedMatch := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2026-99999"},
		},
		Package: pkg.Package{
			Name: "other-app",
			PURL: "pkg:generic/other-app@2.0.0",
		},
	}

	matches := match.NewMatches()
	matches.Add(affectedMatch)
	matches.Add(unrelatedMatch)

	remaining, ignored, err := p.FilterMatches(docRaw, nil, &pkg.Context{}, &matches, nil)
	require.NoError(t, err)

	// The not_affected match should be in the ignored list
	require.Len(t, ignored, 1)
	assert.Equal(t, "CVE-2026-12345", ignored[0].Vulnerability.ID)
	assert.Equal(t, string(vexStatus.NotAffected), ignored[0].AppliedIgnoreRules[0].VexStatus)

	// The unrelated match should remain
	assert.Len(t, remaining.Sorted(), 1)
	assert.Equal(t, "CVE-2026-99999", remaining.Sorted()[0].Vulnerability.ID)
}

func TestFilterMatches_Fixed(t *testing.T) {
	// Build an in-memory BOM with a "resolved" (fixed) vulnerability
	bom := &cdx.BOM{
		BOMFormat: cdx.BOMFormat,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2024-1111",
				Analysis: &cdx.VulnerabilityAnalysis{
					State: cdx.IASResolved,
				},
				Affects: &[]cdx.Affects{
					{Ref: "pkg:npm/example@1.0.0"},
				},
			},
		},
	}

	p := New()

	fixedMatch := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-1111"},
		},
		Package: pkg.Package{
			Name: "example",
			PURL: "pkg:npm/example@1.0.0",
		},
	}

	matches := match.NewMatches()
	matches.Add(fixedMatch)

	remaining, ignored, err := p.FilterMatches([]*cdx.BOM{bom}, nil, &pkg.Context{}, &matches, nil)
	require.NoError(t, err)

	require.Len(t, ignored, 1)
	assert.Equal(t, string(vexStatus.Fixed), ignored[0].AppliedIgnoreRules[0].VexStatus)
	assert.Empty(t, remaining.Sorted())
}

func TestFilterMatches_NoAnalysis(t *testing.T) {
	// Vulnerability without analysis state should NOT be filtered
	bom := &cdx.BOM{
		BOMFormat: cdx.BOMFormat,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID:      "CVE-2024-2222",
				Affects: &[]cdx.Affects{{Ref: "pkg:npm/example@1.0.0"}},
			},
		},
	}

	p := New()

	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-2222"},
		},
		Package: pkg.Package{PURL: "pkg:npm/example@1.0.0"},
	}

	matches := match.NewMatches()
	matches.Add(m)

	remaining, ignored, err := p.FilterMatches([]*cdx.BOM{bom}, nil, &pkg.Context{}, &matches, nil)
	require.NoError(t, err)

	assert.Empty(t, ignored)
	assert.Len(t, remaining.Sorted(), 1)
}

func TestFilterMatches_ExploitableNotFiltered(t *testing.T) {
	// Exploitable vulnerability should NOT be filtered (only augmented)
	bom := &cdx.BOM{
		BOMFormat: cdx.BOMFormat,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2024-3333",
				Analysis: &cdx.VulnerabilityAnalysis{
					State: cdx.IASExploitable,
				},
				Affects: &[]cdx.Affects{{Ref: "pkg:npm/example@1.0.0"}},
			},
		},
	}

	p := New()

	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-3333"},
		},
		Package: pkg.Package{PURL: "pkg:npm/example@1.0.0"},
	}

	matches := match.NewMatches()
	matches.Add(m)

	remaining, ignored, err := p.FilterMatches([]*cdx.BOM{bom}, nil, &pkg.Context{}, &matches, nil)
	require.NoError(t, err)

	assert.Empty(t, ignored)
	assert.Len(t, remaining.Sorted(), 1)
}

func TestFilterMatches_WithIgnoreRules(t *testing.T) {
	bom := &cdx.BOM{
		BOMFormat: cdx.BOMFormat,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2024-5555",
				Analysis: &cdx.VulnerabilityAnalysis{
					State:         cdx.IASNotAffected,
					Justification: cdx.IAJCodeNotPresent,
				},
				Affects: &[]cdx.Affects{{Ref: "pkg:npm/example@1.0.0"}},
			},
		},
	}

	p := New()

	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-5555"},
		},
		Package: pkg.Package{PURL: "pkg:npm/example@1.0.0"},
	}

	t.Run("matching ignore rule causes filtering", func(t *testing.T) {
		matches := match.NewMatches()
		matches.Add(m)

		ignoreRules := []match.IgnoreRule{
			{
				VexStatus:        string(vexStatus.NotAffected),
				VexJustification: string(cdx.IAJCodeNotPresent),
				Namespace:        "vex",
			},
		}

		remaining, ignored, err := p.FilterMatches([]*cdx.BOM{bom}, ignoreRules, &pkg.Context{}, &matches, nil)
		require.NoError(t, err)
		require.Len(t, ignored, 1)
		assert.Empty(t, remaining.Sorted())
	})

	t.Run("non-matching ignore rule does not filter", func(t *testing.T) {
		matches := match.NewMatches()
		matches.Add(m)

		ignoreRules := []match.IgnoreRule{
			{
				VexStatus:        string(vexStatus.Fixed),
				VexJustification: "",
				Namespace:        "vex",
			},
		}

		remaining, ignored, err := p.FilterMatches([]*cdx.BOM{bom}, ignoreRules, &pkg.Context{}, &matches, nil)
		require.NoError(t, err)
		assert.Empty(t, ignored)
		assert.Len(t, remaining.Sorted(), 1)
	})
}

func TestAugmentMatches(t *testing.T) {
	bom := &cdx.BOM{
		BOMFormat: cdx.BOMFormat,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2024-7777",
				Analysis: &cdx.VulnerabilityAnalysis{
					State: cdx.IASExploitable,
				},
				Affects: &[]cdx.Affects{{Ref: "pkg:npm/example@1.0.0"}},
			},
		},
	}

	p := New()

	ignoredMatch := match.IgnoredMatch{
		Match: match.Match{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: "CVE-2024-7777"},
			},
			Package: pkg.Package{PURL: "pkg:npm/example@1.0.0"},
		},
		AppliedIgnoreRules: []match.IgnoreRule{{Namespace: "some-other-rule"}},
	}

	remaining := match.NewMatches()
	updatedMatches, remainingIgnored, err := p.AugmentMatches([]*cdx.BOM{bom}, nil, &pkg.Context{}, &remaining, []match.IgnoredMatch{ignoredMatch})
	require.NoError(t, err)

	// The exploitable match should be moved to active matches
	assert.Len(t, updatedMatches.Sorted(), 1)
	assert.Empty(t, remainingIgnored)
	assert.Equal(t, match.CycloneDXVexMatcher, updatedMatches.Sorted()[0].Details[0].Matcher)
}

func TestAnalysisState(t *testing.T) {
	tests := []struct {
		name     string
		vuln     *cdx.Vulnerability
		expected vexStatus.Status
	}{
		{
			name:     "not_affected",
			vuln:     &cdx.Vulnerability{Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASNotAffected}},
			expected: vexStatus.NotAffected,
		},
		{
			name:     "resolved maps to fixed",
			vuln:     &cdx.Vulnerability{Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved}},
			expected: vexStatus.Fixed,
		},
		{
			name:     "resolved_with_pedigree maps to fixed",
			vuln:     &cdx.Vulnerability{Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolvedWithPedigree}},
			expected: vexStatus.Fixed,
		},
		{
			name:     "exploitable maps to affected",
			vuln:     &cdx.Vulnerability{Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable}},
			expected: vexStatus.Affected,
		},
		{
			name:     "in_triage maps to under_investigation",
			vuln:     &cdx.Vulnerability{Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASInTriage}},
			expected: vexStatus.UnderInvestigation,
		},
		{
			name:     "no analysis returns empty",
			vuln:     &cdx.Vulnerability{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, analysisState(tt.vuln))
		})
	}
}

func TestFilterMatches_IDOnlyMatching(t *testing.T) {
	// Matching is always by CVE ID alone
	bom := &cdx.BOM{
		BOMFormat: cdx.BOMFormat,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2024-IDONLY",
				Analysis: &cdx.VulnerabilityAnalysis{
					State: cdx.IASResolved,
				},
				Affects: &[]cdx.Affects{{Ref: "some-arbitrary-bom-ref"}},
			},
		},
	}

	p := New()

	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-IDONLY"},
		},
		Package: pkg.Package{},
	}

	matches := match.NewMatches()
	matches.Add(m)

	remaining, ignored, err := p.FilterMatches([]*cdx.BOM{bom}, nil, &pkg.Context{}, &matches, nil)
	require.NoError(t, err)

	require.Len(t, ignored, 1)
	assert.Equal(t, "CVE-2024-IDONLY", ignored[0].Vulnerability.ID)
	assert.Equal(t, string(vexStatus.Fixed), ignored[0].AppliedIgnoreRules[0].VexStatus)
	assert.Empty(t, remaining.Sorted())
}
