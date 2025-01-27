package rpm

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func intRef(x int) *int {
	return &x
}

func TestMatcherRpm(t *testing.T) {
	tests := []struct {
		name            string
		p               pkg.Package
		setup           func() (vulnerability.Provider, *distro.Distro, Matcher)
		expectedMatches map[string]match.Type
		wantErr         bool
	}{
		{
			name: "Rpm Match matches by direct and by source indirection",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron-libs",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "neutron",
						Version: "7.1.3-6.el8",
					},
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("neutron-libs", "neutron", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
				"CVE-2014-fake-2": match.ExactIndirectMatch,
				"CVE-2013-fake-3": match.ExactIndirectMatch,
			},
		},
		{
			name: "Rpm Match matches by direct and ignores the source rpm when the package names are the same",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "neutron",
						Version: "7.1.3-6.el8",
					},
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("neutron", "neutron-devel", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			// Regression against https://github.com/anchore/grype/issues/376
			name: "Rpm Match matches by direct and by source indirection when the SourceRpm version is desynced from package version",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron-libs",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "neutron",
						Version: "17.16.3-229.el8",
					},
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("neutron-libs", "neutron", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			// Epoch in pkg but not in src package version, epoch found in the vuln record
			// Regression: https://github.com/anchore/grype/issues/437
			name: "Rpm Match should not occur due to source match even though source has no epoch",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "perl-Errno",
				Version: "0:1.28-419.el8_4.1",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					Epoch: intRef(0),
				},
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "perl",
						Version: "5.26.3-419.el8_4.1",
					},
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "perl", true, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-2": match.ExactDirectMatch,
				"CVE-2021-3": match.ExactIndirectMatch,
			},
		},
		{
			name: "package without epoch is assumed to be 0 - compared against vuln with NO epoch (direct match only)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "perl-Errno",
				Version:  "1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "doesn't-matter", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			name: "package without epoch is assumed to be 0 - compared against vuln WITH epoch (direct match only)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "perl-Errno",
				Version:  "1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "doesn't-matter", true, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-2": match.ExactDirectMatch,
			},
		},
		{
			name: "package WITH epoch - compared against vuln with NO epoch (direct match only)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "perl-Errno",
				Version:  "2:1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "doesn't-matter", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			name: "package WITH epoch - compared against vuln WITH epoch (direct match only)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "perl-Errno",
				Version:  "2:1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "doesn't-matter", true, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{},
		},
		{
			name: "package with modularity label 1",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "maniac",
				Version: "0.1",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strRef("containertools:3:1234:5678"),
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("maniac", "doesn't-matter", false, true)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-1": match.ExactDirectMatch,
				"CVE-2021-3": match.ExactDirectMatch,
			},
		},
		{
			name: "package with modularity label 2",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "maniac",
				Version: "0.1",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strRef("containertools:1:abc:123"),
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("maniac", "doesn't-matter", false, true)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-3": match.ExactDirectMatch,
			},
		},
		{
			name: "package without modularity label",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "maniac",
				Version: "0.1",
				Type:    syftPkg.RpmPkg,
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.New(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("maniac", "doesn't-matter", false, true)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-1": match.ExactDirectMatch,
				"CVE-2021-2": match.ExactDirectMatch,
				"CVE-2021-3": match.ExactDirectMatch,
				"CVE-2021-4": match.ExactDirectMatch,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, d, matcher := test.setup()
			if test.p.Distro == nil {
				test.p.Distro = d
			}
			actual, _, err := matcher.Match(store, test.p)
			if err != nil {
				t.Fatal("could not find match: ", err)
			}

			assert.Len(t, actual, len(test.expectedMatches), "unexpected matches count")

			for _, a := range actual {
				if val, ok := test.expectedMatches[a.Vulnerability.ID]; !ok {
					t.Errorf("return unknown match CVE: %s", a.Vulnerability.ID)
					continue
				} else {
					require.NotEmpty(t, a.Details)
					for _, de := range a.Details {
						assert.Equal(t, val, de.Type)
					}
				}

				assert.Equal(t, test.p.Name, a.Package.Name, "failed to capture original package name")
				for _, detail := range a.Details {
					assert.Equal(t, matcher.Type(), detail.Matcher, "failed to capture matcher type")
				}
			}

			if t.Failed() {
				t.Logf("discovered CVES: %+v", actual)
			}
		})
	}
}

func Test_addEpochIfApplicable(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected string
	}{
		{
			name: "assume 0 epoch",
			pkg: pkg.Package{
				Version: "3.26.0-6.el8",
			},
			expected: "0:3.26.0-6.el8",
		},
		{
			name: "epoch already exists in version string",
			pkg: pkg.Package{
				Version: "7:3.26.0-6.el8",
			},
			expected: "7:3.26.0-6.el8",
		},
		{
			name: "epoch only exists in metadata",
			pkg: pkg.Package{
				Version: "3.26.0-6.el8",
				Metadata: pkg.RpmMetadata{
					Epoch: intRef(7),
				},
			},
			expected: "7:3.26.0-6.el8",
		},
		{
			name: "epoch does not exist in metadata",
			pkg: pkg.Package{
				Version: "3.26.0-6.el8",
				Metadata: pkg.RpmMetadata{
					Epoch: nil,
				},
			},
			expected: "0:3.26.0-6.el8",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := test.pkg
			addEpochIfApplicable(&p)
			assert.Equal(t, test.expected, p.Version)
		})
	}
}

func strRef(s string) *string {
	return &s
}
