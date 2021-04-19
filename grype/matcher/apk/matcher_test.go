package apk

import (
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/grype/grype/match"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype-db/pkg/db"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func must(c syftPkg.CPE, e error) syftPkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

type mockStore struct {
	backend map[string]map[string][]db.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, name string) ([]db.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}

func TestSecDBOnlyMatch(t *testing.T) {

	secDbVuln := db.Vulnerability{
		// ID doesn't match - this is the key for comparison in the matcher
		ID:                "CVE-2020-2",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
	}
	store := mockStore{
		backend: map[string]map[string][]db.Vulnerability{
			"alpine:3.12": {
				"libvncserver": []db.Vulnerability{secDbVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.9",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{
			Type:          match.ExactDirectMatch,
			Confidence:    1.0,
			Vulnerability: *vulnFound,
			Package:       p,
			SearchKey: map[string]interface{}{
				"distro": map[string]string{
					"type":    d.Type.String(),
					"version": d.RawVersion,
				},
			},
			SearchMatches: map[string]interface{}{
				"constraint": vulnFound.Constraint.String(),
			},
			Matcher: match.ApkMatcher,
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}

func TestBothSecdbAndNvdMatches(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := db.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
	}

	secDbVuln := db.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
	}
	store := mockStore{
		backend: map[string]map[string][]db.Vulnerability{
			"nvd": {
				"libvncserver": []db.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []db.Vulnerability{secDbVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.9",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	// ensure the SECDB record is preferred over the NVD record
	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{
			Type:          match.ExactDirectMatch,
			Confidence:    1.0,
			Vulnerability: *vulnFound,
			Package:       p,
			SearchKey: map[string]interface{}{
				"distro": map[string]string{
					"type":    d.Type.String(),
					"version": d.RawVersion,
				},
			},
			SearchMatches: map[string]interface{}{
				"constraint": vulnFound.Constraint.String(),
			},
			Matcher: match.ApkMatcher,
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestNvdOnlyMatches(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := db.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
	}
	store := mockStore{
		backend: map[string]map[string][]db.Vulnerability{
			"nvd": {
				"libvncserver": []db.Vulnerability{nvdVuln},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "libvncserver",
		Version: "0.9.9",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []syftPkg.CPE{must(syftPkg.NewCPE(nvdVuln.CPEs[0]))}

	expected := []match.Match{
		{
			Type:          match.FuzzyMatch,
			Confidence:    0.9,
			Vulnerability: *vulnFound,
			Package:       p,
			SearchKey: map[string]interface{}{
				"cpe": "cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*",
			},
			SearchMatches: map[string]interface{}{
				"cpes":       []string{vulnFound.CPEs[0].BindToFmtString()},
				"constraint": vulnFound.Constraint.String(),
			},
			Matcher: match.ApkMatcher,
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}
