package msrc

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/nextlinux/griffon/griffon/db"
	griffonDB "github.com/nextlinux/griffon/griffon/db/v5"
	"github.com/nextlinux/griffon/griffon/distro"
	"github.com/nextlinux/griffon/griffon/pkg"
)

type mockStore struct {
	backend map[string]map[string][]griffonDB.Vulnerability
}

func (s *mockStore) GetVulnerability(namespace, id string) ([]griffonDB.Vulnerability, error) {
	//TODO implement me
	panic("implement me")
}

func (s *mockStore) SearchForVulnerabilities(namespace, name string) ([]griffonDB.Vulnerability, error) {
	namespaceMap := s.backend[namespace]
	if namespaceMap == nil {
		return nil, nil
	}
	return namespaceMap[name], nil
}

func (s *mockStore) GetAllVulnerabilities() (*[]griffonDB.Vulnerability, error) {
	return nil, nil
}

func (s *mockStore) GetVulnerabilityNamespaces() ([]string, error) {
	keys := make([]string, 0, len(s.backend))
	for k := range s.backend {
		keys = append(keys, k)
	}

	return keys, nil
}

func TestMatches(t *testing.T) {
	d, err := distro.New(distro.Windows, "10816", "Windows Server 2016")
	assert.NoError(t, err)

	store := mockStore{
		backend: map[string]map[string][]griffonDB.Vulnerability{

			// TODO: it would be ideal to test against something that constructs the namespace based on griffon-db
			// and not break the adaption of griffon-db
			fmt.Sprintf("msrc:distro:windows:%s", d.RawVersion): {
				d.RawVersion: []griffonDB.Vulnerability{
					{
						ID:                "CVE-2016-3333",
						VersionConstraint: "3200970 || 878787 || base",
						VersionFormat:     "kb",
					},
					{
						// Does not match, version constraints do not apply
						ID:                "CVE-2020-made-up",
						VersionConstraint: "778786 || 878787 || base",
						VersionFormat:     "kb",
					},
				},
				// Does not match the product ID
				"something-else": []griffonDB.Vulnerability{
					{
						ID:                "CVE-2020-also-made-up",
						VersionConstraint: "3200970 || 878787 || base",
						VersionFormat:     "kb",
					},
				},
			},
		},
	}

	provider, err := db.NewVulnerabilityProvider(&store)
	require.NoError(t, err)

	tests := []struct {
		name            string
		pkg             pkg.Package
		expectedVulnIDs []string
	}{
		{
			name: "direct KB match",
			pkg: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    d.RawVersion,
				Version: "3200970",
				Type:    syftPkg.KbPkg,
			},
			expectedVulnIDs: []string{
				"CVE-2016-3333",
			},
		},
		{
			name: "multiple direct KB match",
			pkg: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    d.RawVersion,
				Version: "878787",
				Type:    syftPkg.KbPkg,
			},
			expectedVulnIDs: []string{
				"CVE-2016-3333",
				"CVE-2020-made-up",
			},
		},
		{
			name: "no KBs found",
			pkg: pkg.Package{
				ID:   pkg.ID(uuid.NewString()),
				Name: d.RawVersion,
				// this is the assumed version if no KBs are found
				Version: "base",
				Type:    syftPkg.KbPkg,
			},
			expectedVulnIDs: []string{
				"CVE-2016-3333",
				"CVE-2020-made-up",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := Matcher{}
			matches, err := m.Match(provider, d, test.pkg)
			assert.NoError(t, err)
			var actualVulnIDs []string
			for _, a := range matches {
				actualVulnIDs = append(actualVulnIDs, a.Vulnerability.ID)
			}
			assert.ElementsMatch(t, test.expectedVulnIDs, actualVulnIDs)
		})
	}

}
