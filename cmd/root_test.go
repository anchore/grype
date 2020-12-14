package cmd

import (
	"testing"

	v1 "github.com/anchore/grype-db/pkg/db/v1"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockMetadataStore struct {
	data map[string]map[string]*v1.VulnerabilityMetadata
}

func newMockStore() *mockMetadataStore {
	d := mockMetadataStore{
		data: make(map[string]map[string]*v1.VulnerabilityMetadata),
	}
	d.stub()
	return &d
}

func (d *mockMetadataStore) stub() {
	d.data["CVE-2014-fake-1"] = map[string]*v1.VulnerabilityMetadata{
		"source-1": {
			Severity: "medium",
		},
	}
}

func (d *mockMetadataStore) GetVulnerabilityMetadata(id, recordSource string) (*v1.VulnerabilityMetadata, error) {
	return d.data[id][recordSource], nil
}

func TestAboveAllowableSeverity(t *testing.T) {
	thePkg := pkg.Package{
		Name:    "the-package",
		Version: "v0.1",
		Type:    syftPkg.RpmPkg,
	}

	matches := match.NewMatches()
	matches.Add(thePkg, match.Match{
		Type: match.ExactDirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:           "CVE-2014-fake-1",
			RecordSource: "source-1",
		},
		Package: thePkg,
	})

	tests := []struct {
		name           string
		failOnSeverity string
		matches        match.Matches
		expectedResult bool
	}{
		{
			name:           "no-severity-set",
			failOnSeverity: "",
			matches:        matches,
			expectedResult: false,
		},
		{
			name:           "below-threshold",
			failOnSeverity: "high",
			matches:        matches,
			expectedResult: false,
		},
		{
			name:           "at-threshold",
			failOnSeverity: "medium",
			matches:        matches,
			expectedResult: true,
		},
		{
			name:           "above-threshold",
			failOnSeverity: "low",
			matches:        matches,
			expectedResult: true,
		},
	}

	metadataProvider := vulnerability.NewMetadataStoreProvider(newMockStore())

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var failOnSeverity *vulnerability.Severity
			if test.failOnSeverity != "" {
				sev := vulnerability.ParseSeverity(test.failOnSeverity)
				if sev == vulnerability.UnknownSeverity {
					t.Fatalf("could not parse severity")
				}
				failOnSeverity = &sev
			}

			actual := hitSeverityThreshold(failOnSeverity, test.matches, metadataProvider)

			if test.expectedResult != actual {
				t.Errorf("expected: %v got : %v", test.expectedResult, actual)
			}
		})
	}
}
