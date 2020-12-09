package common

import (
	"strings"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockDistroProvider struct {
	data map[string]map[string][]*vulnerability.Vulnerability
}

func newMockProviderByDistro() *mockDistroProvider {
	pr := mockDistroProvider{
		data: make(map[string]map[string][]*vulnerability.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockDistroProvider) stub() {
	pr.data["debian:8"] = map[string][]*vulnerability.Vulnerability{
		// direct...
		"neutron": {
			{
				Constraint: version.MustGetConstraint("< 2014.1.5-6", version.DebFormat),
				ID:         "CVE-2014-fake-1",
			},
		},
		// indirect...
		"neutron-devel": {
			// expected...
			{
				Constraint: version.MustGetConstraint("< 2014.1.4-5", version.DebFormat),
				ID:         "CVE-2014-fake-2",
			},
			{
				Constraint: version.MustGetConstraint("< 2015.0.0-1", version.DebFormat),
				ID:         "CVE-2013-fake-3",
			},
			// unexpected...
			{
				Constraint: version.MustGetConstraint("< 2014.0.4-1", version.DebFormat),
				ID:         "CVE-2013-fake-BAD",
			},
		},
	}
}

func (pr *mockDistroProvider) GetByDistro(d distro.Distro, p pkg.Package) ([]*vulnerability.Vulnerability, error) {
	return pr.data[strings.ToLower(d.Type.String())+":"+d.FullVersion()][p.Name], nil
}

func TestFindMatchesByPackageDistro(t *testing.T) {
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

	store := newMockProviderByDistro()
	actual, err := FindMatchesByPackageDistro(store, &d, p, match.PythonMatcher)
	if err != nil {
		t.Fatalf("error while finding matches: %+v", err)
	}

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

		if a.Matcher != match.PythonMatcher {
			t.Errorf("failed to capture matcher name: %s", a.Matcher)
		}

	}

	for _, id := range []string{"CVE-2014-fake-1"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}

}
