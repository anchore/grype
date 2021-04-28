package common

import (
	"strings"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
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
				Namespace:  "debian:8",
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

	expected := []match.Match{
		{
			Type: match.ExactDirectMatch,
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2014-fake-1",
			},
			Confidence: 1,
			Package:    p,
			SearchKey: map[string]interface{}{
				"distro": map[string]string{
					"type":    "debian",
					"version": "8",
				},
			},
			SearchMatches: map[string]interface{}{
				"namespace":         "debian:8",
				"versionConstraint": "< 2014.1.5-6 (deb)",
			},
			Matcher: match.PythonMatcher,
		},
	}

	store := newMockProviderByDistro()
	actual, err := FindMatchesByPackageDistro(store, &d, p, match.PythonMatcher)
	assert.NoError(t, err)
	assertMatchesUsingIDsForVulnerabilities(t, expected, actual)
}
