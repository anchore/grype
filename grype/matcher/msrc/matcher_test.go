package msrc

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatches(t *testing.T) {
	d, err := distro.New(distro.Windows, "10816", "Windows Server 2016")
	require.NoError(t, err)

	// TODO: it would be ideal to test against something that constructs the namespace based on grype-db
	// and not break the adaption of grype-db
	msrcNamespace := fmt.Sprintf("msrc:distro:windows:%s", d.RawVersion)

	vp := mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2016-3333",
				Namespace: msrcNamespace,
			},
			PackageName: d.RawVersion,
			Constraint:  version.MustGetConstraint("3200970 || 878787 || base", version.KBFormat),
		},
		{
			Reference: vulnerability.Reference{
				// Does not match, version constraints do not apply
				ID:        "CVE-2020-made-up",
				Namespace: msrcNamespace,
			},
			PackageName: d.RawVersion,
			Constraint:  version.MustGetConstraint("778786 || 878787 || base", version.KBFormat),
		},
		// Does not match the product ID
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2020-also-made-up",
				Namespace: msrcNamespace,
			},
			PackageName: "something-else",
			Constraint:  version.MustGetConstraint("3200970 || 878787 || base", version.KBFormat),
		},
	}...)

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
				Distro:  d,
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
				Distro:  d,
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
				Distro:  d,
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
			matches, _, err := m.Match(vp, test.pkg)
			require.NoError(t, err)
			var actualVulnIDs []string
			for _, a := range matches {
				actualVulnIDs = append(actualVulnIDs, a.Vulnerability.ID)
			}
			require.ElementsMatch(t, test.expectedVulnIDs, actualVulnIDs)
		})
	}

}
