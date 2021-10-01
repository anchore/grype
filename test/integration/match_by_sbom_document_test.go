package integration

import (
	"fmt"
	"testing"

	"github.com/anchore/grype/grype/matcher/common"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
	"github.com/go-test/deep"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
)

func TestMatchBySBOMDocument(t *testing.T) {
	tests := []struct {
		name            string
		fixture         string
		expectedIDs     []string
		expectedDetails []match.Details
	}{
		{
			name:        "single package",
			fixture:     "test-fixtures/sbom/syft-sbom-with-kb-packages.json",
			expectedIDs: []string{"CVE-2016-3333"},
			expectedDetails: []match.Details{
				{
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    "windows",
							"version": "10816",
						},
						"namespace": "msrc:10816",
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
			expectedIDs: []string{"CVE-bogus-my-package-1", "CVE-bogus-my-package-2-python"},
			expectedDetails: []match.Details{
				{
					SearchedBy: common.SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:a:bogus:my-package:1.0.5:*:*:*:*:*:*:*",
						},
					},
					Found: common.FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:a:bogus:my-package:*:*:*:*:*:*:something:*",
						},
					},
					Matcher:    match.StockMatcher,
					Confidence: 0.9,
				},
				{
					SearchedBy: map[string]interface{}{
						"language":  "python",
						"namespace": "github:python",
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
			provider := vulnerability.NewProviderFromStore(newMockDbStore())
			matches, _, _, err := grype.FindVulnerabilities(provider, fmt.Sprintf("sbom:%s", test.fixture), source.SquashedScope, nil)
			assert.NoError(t, err)
			details := make([]match.Details, 0)
			ids := strset.New()
			for _, m := range matches.Sorted() {
				details = append(details, m.MatchDetails...)
				ids.Add(m.Vulnerability.ID)
			}
			if !assert.Len(t, details, len(test.expectedDetails)) {
				t.Fatalf("mismatched lengths, will not compare")
			}

			for i := range test.expectedDetails {
				for _, d := range deep.Equal(test.expectedDetails[i], details[i]) {
					t.Error(d)
				}
			}

			assert.ElementsMatch(t, test.expectedIDs, ids.List())
		})
	}
}
