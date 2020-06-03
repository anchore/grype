package distro

import (
	"testing"

	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/internal"
	"github.com/anchore/vulnscan/vulnscan/match"
)

func TestMatcher_ExactPackageNameMatch(t *testing.T) {

	p := pkg.Package{
		Name:    "neutron",
		Version: "2014.1.3-6",
		Type:    pkg.DebPkg,
		Metadata: pkg.DpkgMetadata{
			Source: "neutron-devel",
		},
	}

	d, err := distro.NewDistro(distro.Debian, "8")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	store := newMockProvider()
	actual, err := ExactPackageNameMatch(store, d, &p, "SOME_OTHER_MATCHER")

	if len(actual) != 1 {
		t.Fatalf("unexpected direct matches count: %d", len(actual))
	}

	foundCVEs := internal.NewStringSet()

	for _, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		if a.Type != match.ExactDirectMatch {
			t.Error("direct match not indicated")
		}

		if a.Package.Name != p.Name {
			t.Errorf("failed to capture correct original package: %s", a.Package.Name)
		}

		if a.Matcher != "SOME_OTHER_MATCHER" {
			t.Errorf("failed to capture matcher name: %s", a.Matcher)
		}

		if a.IndirectPackage != nil {
			t.Fatalf("should not have captured indirect package")
		}
	}

	for _, id := range []string{"CVE-2014-fake-1"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}

}
