package apk

import (
	"testing"

	v1 "github.com/anchore/grype-db/pkg/db/v1"
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
	backend map[string]map[string][]v1.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, name string) ([]v1.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}

func TestNoSecDBMatch(t *testing.T) {
	// SecDB (matchesByPackageDistro) doesn't have a corresponding match to nvd, so no matches are returned
	store := mockStore{
		backend: map[string]map[string][]v1.Vulnerability{
			"nvd": {
				"libvncserver": []v1.Vulnerability{
					{
						ID:                "CVE-2020-1",
						VersionConstraint: "<= 0.9.11",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
					},
				},
			},
			"alpine:3.12": {
				"libvncserver": []v1.Vulnerability{
					{
						// ID doesn't match - this is the key for comparison in the matcher
						ID:                "CVE-2020-2",
						VersionConstraint: "<= 0.9.11",
						VersionFormat:     "apk",
					},
				},
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
	matches, err := m.Match(provider, &d, p)

	if err != nil {
		t.Fatalf("failed to get matches: %+v", err)
	}

	if len(matches) != 0 {
		t.Errorf("expected 0 matches but got: %d", len(matches))
	}

}

func TestMatches(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package so it matches
	store := mockStore{
		backend: map[string]map[string][]v1.Vulnerability{
			"nvd": {
				"libvncserver": []v1.Vulnerability{
					{
						ID:                "CVE-2020-1",
						VersionConstraint: "<= 0.9.11",
						VersionFormat:     "unknown",
						CPEs:              []string{"cpe:2.3:a:lib_vnc_project-(server):libvncserver:*:*:*:*:*:*:*:*"},
					},
				},
			},
			"alpine:3.12": {
				"libvncserver": []v1.Vulnerability{
					{
						// ID *does* match - this is the key for comparison in the matcher
						ID:                "CVE-2020-1",
						VersionConstraint: "<= 0.9.11",
						VersionFormat:     "apk",
					},
				},
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
	matches, err := m.Match(provider, &d, p)

	if err != nil {
		t.Fatalf("failed to get matches: %+v", err)
	}

	if len(matches) != 1 {
		t.Errorf("expected 1 matches but got: %d", len(matches))
	}

}
