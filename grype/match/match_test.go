package match

import (
	"testing"

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
