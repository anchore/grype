package integration

import (
	"testing"

	v1 "github.com/anchore/grype-db/pkg/db/v1"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
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
						VersionConstraint: "<= 0.9.9",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:libvncserver:libvncserver:*:*:*:*:*:*:*:*"},
					},
					{
						ID:                "CVE-2010-5305",
						VersionConstraint: "<= 0.9.8",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:libvncserver:libvncserver:*:*:*:*:*:*:*:*"},
					},
				},
			},
			"alpine:3.12": {
				"libvncserver": []v1.Vulnerability{
					{
						ID:                "CVE-2010-5304",
						VersionConstraint: "0.9.9",
						VersionFormat:     "apk",
					},
				},
			},
		},
	}

	results, _, _, err := grype.FindVulnerabilities(
		vulnerability.NewProviderFromStore(&store),
		"dir://test-fixtures/corner-cases/apk/vnc",
		scope.AllLayersScope,
	)
	if err != nil {
		t.Fatalf("failed to find vulnerabilities: %+v", err)
	}
	vulnerabilities := make([]match.Match, 0)
	for result := range results.Enumerate() {
		// would it be useful to have a results.Count() method? this seems too much extra work
		vulnerabilities = append(vulnerabilities, result)
	}
	if len(vulnerabilities) != 1 {
		t.Errorf("vulnerability count does not match '%d' != '%d'", len(results.Enumerate()), 1)
	}

	actual := vulnerabilities[0]
	expectedSearchKey := "cpe[cpe:2.3:*:libvncserver:libvncserver:0.9.9-r3:*:*:*:*:*:*:*] constraint[< 0.9.9 (unknown)]"

	if actual.SearchKey != expectedSearchKey {
		t.Errorf("unexpected Searchkey: '%s' != '%s'", actual.SearchKey, expectedSearchKey)
	}

	if actual.Package.Name != "libvncserver" {
		t.Errorf("expected libvncserver Package, but got: %s", actual.Package.Name)
	}
}
