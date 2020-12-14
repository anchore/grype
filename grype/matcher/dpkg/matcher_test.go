package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherDpkg_matchBySourceIndirection(t *testing.T) {
	matcher := Matcher{}
	p := pkg.Package{
		Name:    "neutron",
		Version: "2014.1.3-6",
		Type:    syftPkg.DebPkg,
		Metadata: pkg.DpkgMetadata{
			Source: "neutron-devel",
		},
	}

	d, err := distro.NewDistro(distro.Debian, "8", "")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	store := newMockProvider()
	actual, err := matcher.matchBySourceIndirection(store, &d, p)

	if len(actual) != 2 {
		t.Fatalf("unexpected indirect matches count: %d", len(actual))
	}

	foundCVEs := internal.NewStringSet()

	for _, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		if a.Type != match.ExactIndirectMatch {
			t.Error("indirect match not indicated")
		}

		if a.Package.Name != p.Name {
			t.Errorf("failed to capture correct original package: %s", a.Package.Name)
		}

		if a.Matcher != matcher.Type() {
			t.Errorf("failed to capture matcher type: %s", a.Matcher)
		}

	}

	for _, id := range []string{"CVE-2014-fake-2", "CVE-2013-fake-3"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}
	if t.Failed() {
		t.Logf("discovered CVES: %+v", foundCVEs)
	}

}
