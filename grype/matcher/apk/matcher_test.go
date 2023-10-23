package apk

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockStore struct {
	backend map[string]map[string][]grypeDB.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, id string) ([]grypeDB.Vulnerability, error) {
	//TODO implement me
	panic("implement me")
}

func (s *mockStore) SearchForVulnerabilities(namespace, name string) ([]grypeDB.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}

func (s *mockStore) GetAllVulnerabilities() (*[]grypeDB.Vulnerability, error) {
	return nil, nil
}

func (s *mockStore) GetVulnerabilityNamespaces() ([]string, error) {
	keys := make([]string, 0, len(s.backend))
	for k := range s.backend {
		keys = append(keys, k)
	}

	return keys, nil
}

// TODO include case where fixed version don't match and it's not fixed
func TestSecdbFixesNvdMatches(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	// NVD represents the presence of a vulnerability
	// SECDB data represents that for a given version that CVE has been fixed
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		PackageName:       "libvncserver",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}

	secDbVuln := grypeDB.Vulnerability{
		ID: "CVE-2020-1",
		Fix: grypeDB.Fix{
			Versions: []string{"0.9.11"},
		},
		VersionFormat: "apk",
		Namespace:     "distro:alpine:3.12",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := db.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11", // has to match the fixed version of secDB to be turned off
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"),
		},
	}

	assert.NoError(t, err)

	// We expect the secdb entry to remove the match
	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

// TODO include case where fixed version don't match and it's not fixed
func TestNvdMatches_DifferentPackageName_Removed(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		// Note: the product name is NOT the same as the target package name
		CPEs:      []string{"cpe:2.3:a:lib_vnc_project-(server):libvncumbrellaproject:*:*:*:*:*:*:*:*"},
		Namespace: "nvd:cpe",
	}

	secDbVuln := grypeDB.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID: "CVE-2020-1",
		Fix: grypeDB.Fix{
			Versions: []string{"0.9.11"},
		},
		VersionFormat: "apk",
		Namespace:     "secdb:distro:alpine:3.12",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd:cpe": {
				"libvncumbrellaproject": []grypeDB.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := db.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

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
		CPEs: []cpe.CPE{
			// Note: the product name is NOT the same as the package name
			cpe.Must("cpe:2.3:a:*:libvncumbrellaproject:0.9.9:*:*:*:*:*:*:*"),
		},
	}

	// when a related vulnerability fix is found in secdb
	// ensure the SECDB record is included with the NVD record
	_, err = vulnerability.NewVulnerability(secDbVuln)
	assert.NoError(t, err)

	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdOnlyMatches(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
		},
	}

	provider, err := db.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

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
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"),
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []cpe.CPE{cpe.Must(nvdVuln.CPEs[0])}

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
						Namespace: "nvd:cpe",
						Package: search.CPEPackageParameter{
							Name:    "libvncserver",
							Version: "0.9.9",
						},
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesProperVersionFiltering(t *testing.T) {
	nvdVulnMatch := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}
	nvdVulnNoMatch := grypeDB.Vulnerability{
		ID:                "CVE-2020-2",
		VersionConstraint: "< 0.9.11",
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []grypeDB.Vulnerability{nvdVulnMatch, nvdVulnNoMatch},
			},
		},
	}

	provider, err := db.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11-r10",
		Type:    syftPkg.ApkPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.11:*:*:*:*:*:*:*"),
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(nvdVulnMatch)
	assert.NoError(t, err)
	vulnFound.CPEs = []cpe.CPE{cpe.Must(nvdVulnMatch.CPEs[0])}

	expected := []match.Match{
		{

			Vulnerability: *vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: search.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.11:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: search.CPEPackageParameter{
							Name:    "libvncserver",
							Version: "0.9.11-r10",
						},
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesRemovedWithSecDBFix(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "> 0.9.0, < 0.10.0", // note: this is not normal NVD configuration, but has the desired effect of a "wide net" for vulnerable indication
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}

	secDbVuln := grypeDB.Vulnerability{
		// ID *does* match - this is the key for comparison in the matcher
		ID: "CVE-2020-1",
		Fix: grypeDB.Fix{
			Versions: []string{"0.9.11"},
		},
		VersionFormat: "apk",
		Namespace:     "secdb:distro:alpine:3.12",
	}

	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := db.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

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
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesNoConstraintWithSecDBFix(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "", // note: empty value indicates that all versions are vulnerable
		VersionFormat:     "unknown",
		CPEs:              []string{`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`},
		Namespace:         "nvd:cpe",
	}

	secDbVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "< 0.9.11",
		Fix: grypeDB.Fix{
			Versions: []string{"0.9.11"},
		},
		VersionFormat: "apk",
		Namespace:     "secdb:distro:alpine:3.12",
	}

	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd:cpe": {
				"libvncserver": []grypeDB.Vulnerability{nvdVuln},
			},
			"secdb:distro:alpine:3.12": {
				"libvncserver": []grypeDB.Vulnerability{secDbVuln},
			},
		},
	}

	provider, err := db.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

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
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"),
		},
	}

	expected := []match.Match{}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNVDMatchBySourceIndirection(t *testing.T) {
	nvdVuln := grypeDB.Vulnerability{
		ID:                "CVE-2020-1",
		VersionConstraint: "<= 1.3.3-r0",
		VersionFormat:     "unknown",
		CPEs:              []string{"cpe:2.3:a:musl:musl:*:*:*:*:*:*:*:*"},
		Namespace:         "nvd:cpe",
	}
	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{
			"nvd:cpe": {
				"musl": []grypeDB.Vulnerability{nvdVuln},
			},
		},
	}

	provider, err := db.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

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
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*"),
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*"),
		},
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
	}

	vulnFound, err := vulnerability.NewVulnerability(nvdVuln)
	assert.NoError(t, err)
	vulnFound.CPEs = []cpe.CPE{cpe.Must(nvdVuln.CPEs[0])}

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
						Namespace: "nvd:cpe",
						Package: search.CPEPackageParameter{
							Name:    "musl",
							Version: "1.3.2-r0",
						},
					},
					Found: search.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].BindToFmtString()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func assertMatches(t *testing.T, expected, actual []match.Match) {
	t.Helper()
	var opts = []cmp.Option{
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
