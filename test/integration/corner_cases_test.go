package integration

import (
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/grype-db/pkg/db"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/vulnerability"
)

func TestApkMatch(t *testing.T) {
	store := mockStore{
		backend: map[string]map[string][]db.Vulnerability{
			"nvd": {
				"libvncserver": []db.Vulnerability{
					{
						ID:                "CVE-GOOD",
						VersionConstraint: "<= 0.9.11",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
					},
					{
						ID:                "CVE-BAD",
						VersionConstraint: "<= 0.9.10",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:libvncserver:libvncserver:*:*:*:*:*:*:*:*"},
					},
				},
			},
			"alpine:3.12": {
				"libvncserver": []db.Vulnerability{
					{
						ID:                "CVE-GOOD",
						VersionConstraint: "< 0.9.11",
						VersionFormat:     "apk",
					},
					{
						ID:                "CVE-ALSO-BAD",
						VersionConstraint: "< 0.9.11",
						VersionFormat:     "apk",
					},
				},
			},
		},
	}

	results, _, _, err := grype.FindVulnerabilities(
		vulnerability.NewProviderFromStore(&store),
		"dir:test-fixtures/corner-cases/apk/vnc",
		source.AllLayersScope,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to find vulnerabilities: %+v", err)
	}

	if results.Count() != 1 {
		t.Errorf("vulnerability count does not match '%d' != '%d'", len(results.Enumerate()), 1)
	}

	// implies a single result, as verified by the previous check
	for result := range results.Enumerate() {
		if result.Package.Name != "libvncserver" {
			t.Errorf("expected libvncserver Package, but got: %s", result.Package.Name)
		}

		if result.Vulnerability.ID != "CVE-GOOD" {
			t.Errorf("unexpected Vulnerability ID found: '%s' != 'CVE-GOOD'", result.Vulnerability.ID)
		}
	}

}
