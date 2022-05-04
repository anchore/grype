package apk

import (
	"testing"

	"github.com/go-test/deep"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/db"
	grypeDB "github.com/anchore/grype/grype/db/v4"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func must(c syftPkg.CPE, e error) syftPkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

type mockStore struct {
	backend map[string]map[string][]grypeDB.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, name string) ([]grypeDB.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}

func TestSecDBOnlyMatch(t *testing.T) {

	secDbVuln := grypeDB.Vulnerability{
		// ID doesn't match - this is the key for comparison in the matcher
		ID:                "CVE-2020-2",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}

func TestBothSecdbAndNvdMatches(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd",
	}

	secDbVuln := grypeDB.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	// ensure the SECDB record is preferred over the NVD record
	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestBothSecdbAndNvdMatches_DifferentPackageName(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		// Note: the product name is NOT the same as the target package name
		CPEs:      []string{"cpe:2.3:a:lib_vnc_project-(server):libvncumbrellaproject:*:*:*:*:*:*:*:*"},
		Namespace: "nvd",
	}

	secDbVuln := grypeDB.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncumbrellaproject": []grypeDB.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
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

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "libvncserver",
							"version": "0.9.9",
						},
						"namespace": "secdb",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestNvdOnlyMatches(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []syftPkg.CPE{must(syftPkg.NewCPE(nvdVuln.CPEs[0]))}

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: search.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd",
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}

func TestNvdMatchesWithSecDBFix(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "> 0.9.0, < 0.10.0", // note: this is not normal NVD configuration, but has the desired effect of a "wide net" for vulnerable indication
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd",
	}

	secDbVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11", // note: this does NOT include 0.9.11, so NVD and SecDB mismatch here... secDB should trump in this case
		VersionFormat:     "apk",
	}

	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11",
		Type:    syftPkg.ApkPkg,
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestNvdMatchesNoConstraintWithSecDBFix(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "", // note: empty value indicates that all versions are vulnerable
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd",
	}

	secDbVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}

	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11",
		Type:    syftPkg.ApkPkg,
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*")),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}
}

func TestDistroMatchBySourceIndirection(t *testing.T) {

	secDbVuln := grypeDB.Vulnerability{
		// ID doesn't match - this is the key for comparison in the matcher
		ID:                "CVE-2020-2",
		VersionConstraint: "<= 1.3.3-r0",
		VersionFormat:     "apk",
		Namespace:         "secdb",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"alpine:3.12": {
				"musl": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactIndirectMatch,
					Confidence: 1.0,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    d.Type.String(),
							"version": d.RawVersion,
						},
						"package": map[string]string{
							"name":    "musl",
							"version": p.Version,
						},
						"namespace": "secdb",
					},
					Found: map[string]interface{}{
						"versionConstraint": vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}

func TestNVDMatchBySourceIndirection(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 1.3.3-r0",
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:musl:musl:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd": {
				"musl": []grypeDB.Vulnerability{nvdVuln},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		CPEs: []syftPkg.CPE{
			must(syftPkg.NewCPE("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*")),
			must(syftPkg.NewCPE("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*")),
		},
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []syftPkg.CPE{must(syftPkg.NewCPE(nvdVuln.CPEs[0]))}

	expected := []match.Match{
		{
			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: search.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:musl:musl:*:*:*:*:*:*:*:*"},
						Namespace: "nvd",
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	for _, diff := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", diff)
	}

}
