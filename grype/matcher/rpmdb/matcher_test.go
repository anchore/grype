package rpmdb

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherRpmdb(t *testing.T) {
	tests := []struct {
		name    string
		p       pkg.Package
		setup   func() (vulnerability.Provider, distro.Distro, Matcher)
		wantErr bool
	}{
		{
			name: "Rpmdb Match matches by source indirection",
			p: pkg.Package{
				Name:    "neutron-libs",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{
					SourceRpm: "neutron-7.1.3-6.el8.src.rpm",
				},
			},
			setup: func() (vulnerability.Provider, distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider()

				return store, d, matcher
			},
			wantErr: false,
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(test.name, func(t *testing.T) {
			store, d, matcher := tt.setup()
			actual, err := matcher.Match(store, &d, tt.p)
			if tt.wantErr {
				assert.Equal(t, "", err) //TODO: error case
			}

			assert.Len(t, actual, 3, "unexpected indirect matches count")

			foundCVEs := internal.NewStringSet()

			for _, a := range actual {
				foundCVEs.Add(a.Vulnerability.ID)
				assert.Equal(t, match.ExactIndirectMatch, a.Type, "indirect match not indicated") // TODO: Ask about tool case here
				assert.Equal(t, tt.p.Name, a.Package.Name, "failed to capture original package name")
				for _, detail := range a.MatchDetails {
					assert.Equal(t, matcher.Type(), detail.Matcher, "failed to capture matcher type")
				}
			}

			for _, id := range []string{"CVE-2014-fake-2", "CVE-2013-fake-3"} {
				if !foundCVEs.Contains(id) {
					t.Errorf("missing discovered CVE: %s", id)
				}
			}

			if t.Failed() {
				t.Logf("discovered CVES: %+v", foundCVEs)
			}
		})
	}
}
