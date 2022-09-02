package integration

import (
	"fmt"
	"testing"

	"github.com/go-test/deep"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/store"
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
					},
					Matcher:    match.MsrcMatcher,
					Confidence: 1,
				},
			},
		},
		{
			name:        "unknown package type",
			fixture:     "test-fixtures/sbom/syft-sbom-with-unknown-packages.json",
			expectedIDs: []string{"CVE-bogus-my-package-2-python"},
			expectedDetails: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					SearchedBy: map[string]interface{}{
						"language":  "python",
						"namespace": "github:language:python",
					},
					Found: map[string]interface{}{
						"versionConstraint": "< 2.0 (python)",
					},
					Matcher:    match.StockMatcher,
					Confidence: 1,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockStore := newMockDbStore()
			vp, err := db.NewVulnerabilityProvider(mockStore)
			require.NoError(t, err)
			ep := db.NewMatchExclusionProvider(mockStore)
			store := store.Store{
				Provider:          vp,
				MetadataProvider:  nil,
				ExclusionProvider: ep,
			}
			matches, _, _, err := grype.FindVulnerabilities(store, fmt.Sprintf("sbom:%s", test.fixture), source.SquashedScope, nil)
			assert.NoError(t, err)
			details := make([]match.Detail, 0)
			ids := strset.New()
			for _, m := range matches.Sorted() {
				details = append(details, m.Details...)
				ids.Add(m.Vulnerability.ID)
			}

			require.Len(t, details, len(test.expectedDetails))
			for i := range test.expectedDetails {
				for _, d := range deep.Equal(test.expectedDetails[i], details[i]) {
					t.Error(d)
				}
			}

			assert.ElementsMatch(t, test.expectedIDs, ids.List())
		})
	}
}
