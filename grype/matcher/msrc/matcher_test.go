package msrc

import (
	"testing"

	"github.com/anchore/grype-db/pkg/db"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

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

func TestMatches(t *testing.T) {
	store := mockStore{
		backend: map[string]map[string][]db.Vulnerability{
			"microsoft": {
				"Windows 10 Versions 1903 for ARM64-based Systems": []db.Vulnerability{
					{
						ID:                "CVE-2020-1",
						VersionConstraint: "878786 || 878787",
						VersionFormat:     "kb",
					},
					{
						// Does not match, version constraints do not apply
						ID:                "CVE-2020-1",
						VersionConstraint: "778786 || 778787",
						VersionFormat:     "kb",
					},
				},
				// Does not match, the package is Windows 10, not 11
				"Windows 11 Versions 1903 for ARM64-based Systems": []db.Vulnerability{
					{
						ID:                "CVE-2020-1",
						VersionConstraint: "878786 || 878787",
						VersionFormat:     "kb",
					},
				},
			},
		},
	}

	provider := vulnerability.NewProviderFromStore(&store)

	m := Matcher{}
	d, err := distro.NewDistro(distro.Windows, "878787", "Windows 10 Versions 1903 for ARM64-based Systems")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		Name:    "Windows 10 Versions 1903 for ARM64-based Systems",
		Version: "878787",
		Type:    syftPkg.KbPkg,
	}
	matches, err := m.Match(provider, &d, p)

	if err != nil {
		t.Fatalf("failed to get matches: %+v", err)
	}

	assert.Len(t, matches, 1)
}
