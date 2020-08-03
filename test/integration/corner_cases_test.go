package integration

import (
	"fmt"
	"testing"

	v1 "github.com/anchore/grype-db/pkg/db/v1"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/scope"
)

func TestApkNoVersion(t *testing.T) {
	store := mockStore{
		backend: map[string]map[string][]v1.Vulnerability{
			"nvd": {
				"libvncserver": []v1.Vulnerability{
					{
						ID:                "CVE-2010-5304",
						VersionConstraint: "< 0.9.9",
						VersionFormat:     "unknown",
					},
				},
			},
		},
	}

	results, _, _, err := grype.FindVulnerabilities(
		vulnerability.NewProviderFromStore(&store),
		"dir://test-fixtures/corner-cases/apk",
		scope.AllLayersScope,
	)
	if err != nil {
		t.Fatalf("failed to find vulnerabilities: %+v", err)
	}

	for result := range results.Enumerate() {
		fmt.Printf("%v\n", result)
	}
	if len(results.Enumerate()) != 1 {
		t.Errorf("vulnerability count does not match '%d' != '%d'", len(results.Enumerate()), 1)
	}
}
