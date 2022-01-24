package search

import (
	"strings"
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

type mockDistroProvider struct {
	data map[string]map[string][]vulnerability.Vulnerability
}

func newMockProviderByDistro() *mockDistroProvider {
	pr := mockDistroProvider{
		data: make(map[string]map[string][]vulnerability.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockDistroProvider) stub() {
	pr.data["debian:8"] = map[string][]vulnerability.Vulnerability{
		// direct...
		"neutron": {
			{
				Constraint: version.MustGetConstraint("< 2014.1.5-6", version.DebFormat),
				ID:         "CVE-2014-fake-1",
				Namespace:  "debian:8",
			},
		},
	}
	pr.data["sles:12.5"] = map[string][]vulnerability.Vulnerability{
		// direct...
		"sles_test_package": {
			{
				Constraint: version.MustGetConstraint("< 2014.1.5-6", version.RpmFormat),
				ID:         "CVE-2014-fake-4",
				Namespace:  "sles:12.5",
			},
		},
	}
}

func (pr *mockDistroProvider) GetByDistro(d *distro.Distro, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return pr.data[strings.ToLower(d.Type.String())+":"+d.FullVersion()][p.Name], nil
}

func TestFindMatchesByPackageDistro(t *testing.T) {
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "neutron",
		Version: "2014.1.3-6",
		Type:    syftPkg.DebPkg,
		Metadata: pkg.DpkgMetadata{
			Source: "neutron-devel",
		},
	}

	d, err := distro.New(distro.Debian, "8", "")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	expected := []match.Match{
		{

			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2014-fake-1",
			},
			Package: p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    "debian",
							"version": "8",
						},
						"package": map[string]string{
							"name":    "neutron",
							"version": "2014.1.3-6",
						},
						"namespace": "debian:8",
					},
					Found: map[string]interface{}{
						"versionConstraint": "< 2014.1.5-6 (deb)",
					},
					Matcher: match.PythonMatcher,
				},
			},
		},
	}

	store := newMockProviderByDistro()
	actual, err := ByPackageDistro(store, d, p, match.PythonMatcher)
	assert.NoError(t, err)
	assertMatchesUsingIDsForVulnerabilities(t, expected, actual)
}

func TestFindMatchesByPackageDistroSles(t *testing.T) {
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "sles_test_package",
		Version: "2014.1.3-6",
		Type:    syftPkg.RpmPkg,
		Metadata: pkg.DpkgMetadata{
			Source: "sles_test_package",
		},
	}

	d, err := distro.New(distro.SLES, "12.5", "")
	if err != nil {
		t.Fatal("could not create distro: ", err)
	}

	expected := []match.Match{
		{

			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-2014-fake-4",
			},
			Package: p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    "sles",
							"version": "12.5",
						},
						"package": map[string]string{
							"name":    "sles_test_package",
							"version": "2014.1.3-6",
						},
						"namespace": "sles:12.5",
					},
					Found: map[string]interface{}{
						"versionConstraint": "< 2014.1.5-6 (rpm)",
					},
					Matcher: match.PythonMatcher,
				},
			},
		},
	}

	store := newMockProviderByDistro()
	actual, err := ByPackageDistro(store, d, p, match.PythonMatcher)
	assert.NoError(t, err)
	assertMatchesUsingIDsForVulnerabilities(t, expected, actual)
}
