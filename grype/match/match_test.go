package match

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

func TestMatch_Merge(t *testing.T) {
	tests := []struct {
		name        string
		m1          Match
		m2          Match
		expectedErr error
		expected    Match
	}{
		{
			name: "error on fingerprint mismatch",
			m1: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace1",
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
			},
			m2: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0002",
						Namespace: "namespace2",
					},
				},
				Package: pkg.Package{
					ID: "pkg2",
				},
			},
			expectedErr: ErrCannotMerge,
		},
		{
			name: "merge with unique values",
			m1: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
				},
			},
			m2: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns2",
							ID:        "ID2",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.1:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactIndirectMatch,
						SearchedBy: "attr2",
						Found:      "value2",
						Matcher:    "matcher2",
					},
				},
			},
			expectedErr: nil,
			expected: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
						{
							Namespace: "ns2",
							ID:        "ID2",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
						cpe.Must("cpe:2.3:a:example:example:1.1:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
					{
						Type:       ExactIndirectMatch,
						SearchedBy: "attr2",
						Found:      "value2",
						Matcher:    "matcher2",
					},
				},
			},
		},
		{
			name: "merges with duplicate values",
			m1: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
				},
			},
			m2: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
				},
			},
			expectedErr: nil,
			expected: Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-2023-0001",
						Namespace: "namespace",
					},
					RelatedVulnerabilities: []vulnerability.Reference{
						{
							Namespace: "ns1",
							ID:        "ID1",
						},
					},
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*", cpe.DeclaredSource),
					},
				},
				Package: pkg.Package{
					ID: "pkg1",
				},
				Details: Details{
					{
						Type:       ExactDirectMatch,
						SearchedBy: "attr1",
						Found:      "value1",
						Matcher:    "matcher1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m1.Merge(tt.m2)
			if tt.expectedErr != nil {
				require.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected.Vulnerability.RelatedVulnerabilities, tt.m1.Vulnerability.RelatedVulnerabilities)
				require.Equal(t, tt.expected.Details, tt.m1.Details)
				require.Equal(t, tt.expected.Vulnerability.CPEs, tt.m1.Vulnerability.CPEs)
			}
		})
	}
}

// TestMergeReferences_UncomparableInternal guards the reason mergeReferences projects onto
// referenceKey rather than keying on vulnerability.Reference itself: Reference.Internal is an `any`,
// and providers do put uncomparable values in it. Using Reference as a map key would compile fine
// and panic at runtime ("hash of unhashable type") the first time one showed up.
func TestMergeReferences_UncomparableInternal(t *testing.T) {
	withSlice := vulnerability.Reference{
		ID:        "CVE-2023-0001",
		Namespace: "nvd:cpe",
		Internal:  []string{"uncomparable"},
	}
	withMap := vulnerability.Reference{
		ID:        "CVE-2023-0002",
		Namespace: "nvd:cpe",
		Internal:  map[string]string{"also": "uncomparable"},
	}

	require.NotPanics(t, func() {
		got := mergeReferences([]vulnerability.Reference{withSlice}, []vulnerability.Reference{withMap, withSlice})

		// deduped on (id, namespace), ignoring Internal, and sorted
		require.Len(t, got, 2)
		assert.Equal(t, "CVE-2023-0001", got[0].ID)
		assert.Equal(t, "CVE-2023-0002", got[1].ID)
	})
}

// TestMergeAdvisories covers dedup and ordering for the set keyed directly on the (comparable)
// vulnerability.Advisory value.
func TestMergeAdvisories(t *testing.T) {
	a := vulnerability.Advisory{ID: "RHSA-2024:9371", Link: "https://example.com/a"}
	b := vulnerability.Advisory{ID: "RHSA-2024:6163", Link: "https://example.com/b"}
	// same ID, different link -- a distinct advisory, so both are kept
	aPrime := vulnerability.Advisory{ID: "RHSA-2024:9371", Link: "https://example.com/other"}

	got := mergeAdvisories([]vulnerability.Advisory{a, b}, []vulnerability.Advisory{a, aPrime})

	// sorted by ID, then Link
	assert.Equal(t, []vulnerability.Advisory{b, a, aPrime}, got)
}

// TestMergeFix_AvailableDedup covers the set keyed directly on the (comparable)
// vulnerability.FixAvailable value, including its time.Time field.
func TestMergeFix_AvailableDedup(t *testing.T) {
	when := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	base := vulnerability.Fix{
		Versions:  []string{"2.0.0", "1.0.0"},
		State:     vulnerability.FixStateFixed,
		Available: []vulnerability.FixAvailable{{Version: "1.0.0", Kind: "rpm", Date: when}},
	}
	other := vulnerability.Fix{
		Versions: []string{"1.0.0", "3.0.0"},
		Available: []vulnerability.FixAvailable{
			{Version: "1.0.0", Kind: "rpm", Date: when},  // exact duplicate, dropped
			{Version: "1.0.0", Kind: "rpm", Date: later}, // same version+kind, different date: kept
		},
	}

	got := mergeFix(base, other)

	assert.Equal(t, []string{"1.0.0", "2.0.0", "3.0.0"}, got.Versions, "versions should be sorted and deduped")
	assert.Equal(t, vulnerability.FixStateFixed, got.State)
	assert.Equal(t, []vulnerability.FixAvailable{
		{Version: "1.0.0", Kind: "rpm", Date: when},
		{Version: "1.0.0", Kind: "rpm", Date: later},
	}, got.Available)
}
