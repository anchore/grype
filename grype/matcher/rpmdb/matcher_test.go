package rpmdb

import (
	"strings"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
)

func TestMatcherDpkg_matchBySourceIndirection(t *testing.T) {
	matcher := Matcher{}
	p := pkg.Package{
		Name:    "neutron-libs",
		Version: "7.1.3-6",
		Type:    pkg.RpmPkg,
		Metadata: pkg.RpmMetadata{
			SourceRpm: "neutron-7.1.3-6.el8.src.rpm",
		},
	}

	d, err := distro.NewDistro(distro.CentOS, "8")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	store := newMockProvider()
	actual, err := matcher.matchBySourceIndirection(store, d, &p)

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

		if a.IndirectPackage == nil {
			t.Fatalf("failed to capture correct indirect package")
		}

		if a.IndirectPackage.Name != strings.TrimSuffix(p.Name, "-libs") {
			t.Errorf("failed to capture correct indirect package name: %s", a.IndirectPackage.Name)
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

func TestMatcherDpkg_matchBySourceIndirection_ignoreSource(t *testing.T) {
	matcher := Matcher{}
	p := pkg.Package{
		Name:    "neutron",
		Version: "7.1.3-6",
		Type:    pkg.RpmPkg,
		Metadata: pkg.RpmMetadata{
			SourceRpm: "neutron-7.1.3-6.el8.src.rpm",
		},
	}

	d, err := distro.NewDistro(distro.CentOS, "8")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	store := newMockProvider()
	actual, err := matcher.matchBySourceIndirection(store, d, &p)

	if len(actual) != 0 {
		t.Fatalf("unexpected indirect matches count: %d", len(actual))
	}

}
