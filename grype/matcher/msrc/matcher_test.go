package msrc

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/db"
	grypeDB "github.com/anchore/grype/grype/db/v4"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

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

func TestMatches(t *testing.T) {
	d, err := distro.New(distro.Windows, "10816", "Windows Server 2016")
	assert.NoError(t, err)

	store := mockStore{
		backend: map[string]map[string][]grypeDB.Vulnerability{

			// TODO: it would be ideal to test against something that constructs the namespace based on grype-db
			// and not break the adaption of grype-db
			fmt.Sprintf("msrc:%s", d.RawVersion): {
				d.RawVersion: []grypeDB.Vulnerability{
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
				"something-else": []grypeDB.Vulnerability{
					{
						ID:                "CVE-2020-also-made-up",
						VersionConstraint: "3200970 || 878787 || base",
						VersionFormat:     "kb",
					},
				},
			},
		},
	}

	provider := db.NewVulnerabilityProvider(&store)

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
