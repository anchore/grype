package rpmdb

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func intRef(x int) *int {
	return &x
}

func TestMatcherRpmdb(t *testing.T) {
	tests := []struct {
		name            string
		p               pkg.Package
		setup           func() (vulnerability.Provider, *distro.Distro, Matcher)
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
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("neutron-libs", "neutron", false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
				"CVE-2014-fake-2": match.ExactIndirectMatch,
				"CVE-2013-fake-3": match.ExactIndirectMatch,
			},
		},
		{
			name: "Rpmdb Match matches by direct and ignores the source rpm when the package names are the same",
			p: pkg.Package{
				Name:    "neutron",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{
					SourceRpm: "neutron-7.1.3-6.el8.src.rpm",
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("neutron", "neutron-devel", false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			// Regression against https://github.com/anchore/grype/issues/376
			name: "Rpmdb Match matches by direct and by source indirection when the SourceRpm version is desynced from package version",
			p: pkg.Package{
				Name:    "neutron-libs",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{
					SourceRpm: "neutron-17.16.3-229.el8.src.rpm",
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("neutron-libs", "neutron", false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			// Epoch in pkg but not in src package version, epoch found in the vuln record
			// Regression: https://github.com/anchore/grype/issues/437
			name: "Rpmdb Match should not occur due to source match even though source has no epoch",
			p: pkg.Package{
				Name:    "perl-Errno",
				Version: "0:1.28-419.el8_4.1",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{
					SourceRpm: "perl-5.26.3-419.el8_4.1.src.rpm",
					Epoch:     intRef(0),
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "perl", true)

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
				Name:     "perl-Errno",
				Version:  "1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "doesn't-matter", false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			name: "package without epoch is assumed to be 0 - compared against vuln WITH epoch (direct match only)",
			p: pkg.Package{
				Name:     "perl-Errno",
				Version:  "1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "doesn't-matter", true)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-2": match.ExactDirectMatch,
			},
		},
		{
			name: "package WITH epoch - compared against vuln with NO epoch (direct match only)",
			p: pkg.Package{
				Name:     "perl-Errno",
				Version:  "2:1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "doesn't-matter", false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			name: "package WITH epoch - compared against vuln WITH epoch (direct match only)",
			p: pkg.Package{
				Name:     "perl-Errno",
				Version:  "2:1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d, err := distro.NewDistro(distro.CentOS, "8", "")
				if err != nil {
					t.Fatal("could not create distro: ", err)
				}

				store := newMockProvider("perl-Errno", "doesn't-matter", true)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, d, matcher := test.setup()
			actual, err := matcher.Match(store, d, test.p)
			if err != nil {
				t.Fatal("could not find match: ", err)
			}

			assert.Len(t, actual, len(test.expectedMatches), "unexpected matches count")

			for _, a := range actual {
				if val, ok := test.expectedMatches[a.Vulnerability.ID]; !ok {
					t.Errorf("return unkown match CVE: %s", a.Vulnerability.ID)
					continue
				} else {
					assert.Equal(t, val, a.Type)
				}

				assert.Equal(t, test.p.Name, a.Package.Name, "failed to capture original package name")
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

func Test_getNameAndELVersion(t *testing.T) {
	epoch := 1
	tests := []struct {
		name            string
		metadata        pkg.RpmdbMetadata
		expectedName    string
		expectedVersion string
	}{
		{
			name: "sqlite-3.26.0-6.el8.src.rpm",
			metadata: pkg.RpmdbMetadata{
				SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
			},
			expectedName:    "sqlite",
			expectedVersion: "3.26.0-6.el8",
		},
		{
			name: "util-linux-ng-2.17.2-12.28.el6_9.src.rpm",
			metadata: pkg.RpmdbMetadata{
				SourceRpm: "util-linux-ng-2.17.2-12.28.el6_9.src.rpm",
			},
			expectedName:    "util-linux-ng",
			expectedVersion: "2.17.2-12.28.el6_9",
		},
		{
			name: "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm",
			metadata: pkg.RpmdbMetadata{
				SourceRpm: "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm",
			},
			expectedName:    "util-linux-ng",
			expectedVersion: "2.17.2-12.28.el6_9.2",
		},
		{
			name: "epoch 1 + sqlite-3.26.0-6.el8.src.rpm",
			metadata: pkg.RpmdbMetadata{
				SourceRpm: "sqlite-3.26.0-6.el8.src.rpm",
				Epoch:     &epoch,
			},
			expectedName:    "sqlite",
			expectedVersion: "3.26.0-6.el8",
		},
		{
			name: "sqlite-bin-3.26.0-6.el8.src.rpm",
			metadata: pkg.RpmdbMetadata{
				SourceRpm: "sqlite-1.26.0-6.el8.src.rpm",
				Epoch:     &epoch,
			},
			expectedName:    "sqlite",
			expectedVersion: "1.26.0-6.el8",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualName, actualVersion := getNameAndELVersion(test.metadata)
			assert.Equal(t, test.expectedName, actualName)
			assert.Equal(t, test.expectedVersion, actualVersion)
		})
	}
}

func Test_addZeroEpicIfApplicable(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{
			version:  "3.26.0-6.el8",
			expected: "0:3.26.0-6.el8",
		},
		{
			version:  "7:3.26.0-6.el8",
			expected: "7:3.26.0-6.el8",
		},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			actualVersion := addZeroEpicIfApplicable(test.version)
			assert.Equal(t, test.expected, actualVersion)
		})
	}
}
