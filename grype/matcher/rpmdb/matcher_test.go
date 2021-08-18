package rpmdb

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherRpmdb(t *testing.T) {
	tests := []struct {
		name            string
		p               pkg.Package
		setup           func() (vulnerability.Provider, distro.Distro, Matcher)
		expectedMatches map[string]match.Type
		wantErr         bool
	}{
		{
			name: "Rpmdb Match matches by direct and by source indirection",
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
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
				"CVE-2014-fake-2": match.ExactIndirectMatch,
				"CVE-2013-fake-3": match.ExactIndirectMatch,
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
				return
			}

			assert.Len(t, actual, len(tt.expectedMatches), "unexpected matches count")

			for _, a := range actual {
				if val, ok := tt.expectedMatches[a.Vulnerability.ID]; !ok {
					t.Errorf("return unkown match CVE: %s", a.Vulnerability.ID)
					continue
				} else {
					assert.Equal(t, val, a.Type)
				}

				assert.Equal(t, tt.p.Name, a.Package.Name, "failed to capture original package name")
				for _, detail := range a.MatchDetails {
					assert.Equal(t, matcher.Type(), detail.Matcher, "failed to capture matcher type")
				}
			}

			if t.Failed() {
				t.Logf("discovered CVES: %+v", actual)
			}
		})
	}
}
