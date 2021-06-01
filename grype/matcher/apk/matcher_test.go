package apk

import (
	"testing"

	"github.com/anchore/grype/grype/matcher/common"

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
		Namespace:         "secdb",
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
			Vulnerability: *vulnFound,
			Package:       p,
			MatchDetails: []match.Details{
				{
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"namespace": "secdb",
					},
					MatchedOn: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
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
		Namespace:         "nvd",
	}

	secDbVuln := db.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
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
			Vulnerability: *vulnFound,
			Package:       p,
			MatchDetails: []match.Details{
				{
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"namespace": "secdb",
					},
					MatchedOn: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestBothSecdbAndNvdMatches_DifferentPackageName(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := db.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		// Note: the product name is NOT the same as the target package name
		CPEs:      []string{"cpe:2.3:a:lib_vnc_project-(server):libvncumbrellaproject:*:*:*:*:*:*:*:*"},
		Namespace: "nvd",
	}

	secDbVuln := db.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}
	store := mockStore{
		backend: map[string]map[string][]db.Vulnerability{
			"nvd": {
				"libvncumbrellaproject": []db.Vulnerability{nvdVuln},
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
			// Note: the product name is NOT the same as the package name
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncumbrellaproject:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	// ensure the SECDB record is preferred over the NVD record
	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{
			Type:          match.ExactDirectMatch,
			Vulnerability: *vulnFound,
			Package:       p,
			MatchDetails: []match.Details{
				{
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"namespace": "secdb",
					},
					MatchedOn: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestNvdOnlyMatches(t *testing.T) {
	nvdVuln := db.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd",
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
			Vulnerability: *vulnFound,
			Package:       p,
			MatchDetails: []match.Details{
				{
					Confidence: 0.9,
					SearchedBy: common.SearchedByCPEs{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd",
					},
					MatchedOn: common.MatchedOnCPEs{
						CPEs:              []string{vulnFound.CPEs[0].BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}

func TestNvdMatchesWithSecDBFix(t *testing.T) {
	nvdVuln := db.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "> 0.9.0, < 0.10.0", // note: this is not normal NVD configuration, but has the desired effect of a "wide net" for vulnerable indication
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd",
	}

	secDbVuln := db.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11", // note: this does NOT include 0.9.11, so NVD and SecDB mismatch here... secDB should trump in this case
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
		Version: "0.9.11",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestNvdMatchesNoConstraintWithSecDBFix(t *testing.T) {
	nvdVuln := db.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "", // note: empty value indicates that all versions are vulnerable
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd",
	}

	secDbVuln := db.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
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
		Version: "0.9.11",
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, &d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}
