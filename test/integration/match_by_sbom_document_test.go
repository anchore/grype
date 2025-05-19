package integration

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestMatchBySBOMDocument(t *testing.T) {
	tests := []struct {
		name            string
		fixture         string
		expectedIDs     []string
		expectedDetails []match.Detail
	}{
		{
			name:        "single KB package",
			fixture:     "test-fixtures/sbom/syft-sbom-with-kb-packages.json",
			expectedIDs: []string{"CVE-2016-3333"},
			expectedDetails: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    "windows",
							"version": "10816",
						},
						"namespace": "msrc:distro:windows:10816",
						"package": map[string]string{
							"name":    "10816",
							"version": "3200970",
						},
					},
					Found: map[string]interface{}{
						"versionConstraint": "3200970 || 878787 || base (kb)",
						"vulnerabilityID":   "CVE-2016-3333",
					},
					Matcher:    match.MsrcMatcher,
					Confidence: 1,
				},
			},
		},
		{
			name:        "unknown package type",
			fixture:     "test-fixtures/sbom/syft-sbom-with-unknown-packages.json",
			expectedIDs: []string{"CVE-bogus-my-package-2-idris"},
			expectedDetails: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: map[string]interface{}{
						"language":  "idris",
						"namespace": "github:language:idris",
						"package":   map[string]string{"name": "my-package", "version": "1.0.5"},
					},
					Found: map[string]interface{}{
						"versionConstraint": "< 2.0 (unknown)",
						"vulnerabilityID":   "CVE-bogus-my-package-2-idris",
					},
					Matcher:    match.StockMatcher,
					Confidence: 1,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vp := newMockDbProvider()
			matches, _, _, err := grype.FindVulnerabilities(vp, fmt.Sprintf("sbom:%s", test.fixture), source.SquashedScope, nil)
			assert.NoError(t, err)
			details := make([]match.Detail, 0)
			ids := strset.New()
			for _, m := range matches.Sorted() {
				details = append(details, m.Details...)
				ids.Add(m.Vulnerability.ID)
			}

			require.Len(t, details, len(test.expectedDetails))

			cmpOpts := []cmp.Option{
				cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
			}

			for i := range test.expectedDetails {
				if d := cmp.Diff(test.expectedDetails[i], details[i], cmpOpts...); d != "" {
					t.Errorf("unexpected match details (-want +got):\n%s", d)
				}
			}

			assert.ElementsMatch(t, test.expectedIDs, ids.List())
		})
	}
}
