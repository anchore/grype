package rpm

import (
	"errors"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
				d := distro.New(distro.CentOS, "8", "")

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
					Epoch: nil, // assume 0 epoch
				},
			},
			expected: "0:3.26.0-6.el8",
		},
		{
			name: "version is empty",
			pkg: pkg.Package{
				Version: "",
				Metadata: pkg.RpmMetadata{
					Epoch: nil, // assume 0 epoch
				},
			},
			expected: "",
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

func TestResolveDisclosures(t *testing.T) {
	tests := []struct {
		name            string
		packageVersion  string
		disclosures     []result.Result
		advisoryOverlay []result.Result
		want            []result.Result
	}{
		{
			name:           "disclosure with fix version - package version is vulnerable",
			packageVersion: "1.0.0", // vulnerable since 1.0.0 < 1.5.0
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.6.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{"1.6.0"}, // important! this is the fix version that we should not consider
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed, // important!
								Versions: []string{"1.5.0"},           // important!
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.CombineConstraints(
								version.MustGetConstraint("< 1.6.0", version.RpmFormat), // from disclosure
								version.MustGetConstraint("< 1.5.0", version.RpmFormat), // from advisory
							),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed, // important! from advisory
								Versions: []string{"1.5.0"},           // important! from advisory, not the disclosure
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "vulnerability not fixed - package version not vulnerable",
			packageVersion: "2.0.0", // not vulnerable since 2.0.0 > 1.5.0
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0"},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{},
		},
		{
			name:           "multiple advisories with multiple fix versions",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{ // advisory does not apply!
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 0.9", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"0.9"},
							},
						},
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0", "1.4.2"},
							},
						},
						{ // duplicate advisory, should already be counted from the first one
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0", "1.4.2"},
							},
						},
						{ // duplicate advisory, with different fix version
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.4.3"},
							},
						},
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"2.0.0"},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.CombineConstraints( // important! we are combining the constraints
								version.MustGetConstraint("< 1.5.0", version.RpmFormat),
								version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.4.2", "1.4.3", "1.5.0", "2.0.0"}, // important! we have all fixes for advisories that apply
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "advisory with wont-fix state - disclosure should be kept with patched fix state",
			packageVersion: "1.0.0", // vulnerable since 1.0.0 < 2.0.0
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown, // important! the disclosure doesn't have good fix info
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix, // important! we want the disclosure to reflect this property
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "advisory with unknown fix state - disclosure should be kept",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat), // important!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{ // ultimately, this advisory does not apply...
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 3.0.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown, // important!
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 2.0.0", version.RpmFormat), // from the disclosure
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "empty fix versions are filtered out",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"", "1.5.0", ""}, // important!
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0"},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "constraint satisfaction error - advisory skipped",
			packageVersion: "W:1.2.3-456", // intentionally invalid epoch
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateFixed,
								Versions: []string{"1.5.0"},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{},
		},
		{
			name:           "no advisory overlay, disclosure has nil constraint - remove disclosure",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: nil, // important! we're never vulnerable!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{ // does not apply
					ID:              "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{},
					Details:         []match.Detail{},
				},
			},
			want: []result.Result{},
		},
		{
			name:           "no advisory overlay, disclosure has empty constraint - keep disclosure",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("", version.RpmFormat), // important! we're always vulnerable
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{ // does not apply
					ID:              "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{},
					Details:         []match.Detail{},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("", version.RpmFormat), // important! shows "none (rpm)"
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name:           "no advisory overlay, disclosure does not apply - remove all",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 0.9", version.RpmFormat), // important! we're not vulnerable!
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{ // does not apply
					ID:              "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{},
					Details:         []match.Detail{},
				},
			},
			want: []result.Result{},
		},
		{
			name:           "advisory with no fixes - disclosure is preserved",
			packageVersion: "1.0.0",
			disclosures: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference: vulnerability.Reference{ID: "CVE-2021-1"},
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateUnknown,
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			advisoryOverlay: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix,
								Versions: []string{"1.5.0"}, // important: this is a wont-fix advisory so this should not be incorporated (an inconsistent advisory)
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
			want: []result.Result{
				{
					ID: "CVE-2021-1",
					Vulnerabilities: []vulnerability.Vulnerability{
						{
							Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
							Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
							Fix: vulnerability.Fix{
								State:    vulnerability.FixStateWontFix, // wont-fix state is preserved
								Versions: []string{},
							},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v *version.Version
			v = version.NewVersion(tt.packageVersion, version.RpmFormat)
			if v.Validate() != nil {
				v = nil
			}

			resolver := resolveDisclosures(v)

			got := resolver(tt.disclosures, tt.advisoryOverlay)

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(version.Version{}),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("resolveDisclosures() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFindEUSMatches(t *testing.T) {
	tests := []struct {
		name              string
		searchPkg         pkg.Package
		disclosureResults result.Set
		resolutionResults result.Set
		want              []match.Match
		wantErr           require.ErrorAssertionFunc
	}{
		{
			name: "successful EUS match with fix",
			searchPkg: pkg.Package{
				ID:      pkg.ID("test-pkg-id"),
				Name:    "test-pkg",
				Version: "1.0.0",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.RedHat,
					Version: "9.4",
					Channel: "eus",
				},
			},
			disclosureResults: result.Set{
				"CVE-2021-1": []result.Result{
					{
						ID: "CVE-2021-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "CVE-2021-1"},
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateUnknown,
									Versions: []string{},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
			},
			resolutionResults: result.Set{
				"CVE-2021-1": []result.Result{
					{
						ID: "CVE-2021-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
								Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateFixed,
									Versions: []string{"1.5.0"},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: "CVE-2021-1"},
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateFixed,
							Versions: []string{"1.5.0"},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.RedHat,
							Version: "9.4",
							Channel: "eus",
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name: "no disclosures found",
			searchPkg: pkg.Package{
				ID:      pkg.ID("test-pkg-id"),
				Name:    "test-pkg",
				Version: "1.0.0",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.RedHat,
					Version: "9.4",
					Channel: "eus",
				},
			},
			disclosureResults: result.Set{},
			resolutionResults: result.Set{},
			want:              nil,
		},
		{
			name: "valid disclosures found but no resolutions",
			searchPkg: pkg.Package{
				ID:      pkg.ID("test-pkg-id"),
				Name:    "test-pkg",
				Version: "1.0.0",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.RedHat,
					Version: "9.4",
					Channel: "eus",
				},
			},
			disclosureResults: result.Set{
				"CVE-2021-1": []result.Result{
					{
						ID: "CVE-2021-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
								Constraint: version.MustGetConstraint("", version.RpmFormat), // no constraint, so we assume it's always vulnerable
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateUnknown,
									Versions: []string{},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
			},
			resolutionResults: result.Set{},
			want: []match.Match{ // keep the original disclosure as a match
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
						Constraint: version.MustGetConstraint("", version.RpmFormat),
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateUnknown,
							Versions: []string{},
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.RedHat,
							Version: "9.4",
							Channel: "eus",
						},
					},
				},
			},
		},
		{
			name: "vulnerability resolved by EUS advisory",
			searchPkg: pkg.Package{
				ID:      pkg.ID("test-pkg-id"),
				Name:    "test-pkg",
				Version: "2.0.0",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.RedHat,
					Version: "9.4",
					Channel: "eus",
				},
			},
			disclosureResults: result.Set{
				"CVE-2021-1": []result.Result{
					{
						ID: "CVE-2021-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "CVE-2021-1"},
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateUnknown,
									Versions: []string{},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
			},
			resolutionResults: result.Set{
				"CVE-2021-1": []result.Result{
					{
						ID: "CVE-2021-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
								Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateFixed,
									Versions: []string{"1.5.0"},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: []match.Match{}, // vulnerability is resolved because package version 2.0.0 > 1.5.0
		},
		{
			name: "multiple valid disclosures with mixed resolutions",
			searchPkg: pkg.Package{
				ID:      pkg.ID("test-pkg-id"),
				Name:    "test-pkg",
				Version: "1.0.0",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.RedHat,
					Version: "9.4",
					Channel: "eus",
				},
			},
			disclosureResults: result.Set{
				"CVE-2021-1": []result.Result{
					{
						ID: "CVE-2021-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
								Constraint: version.MustGetConstraint("", version.RpmFormat),
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateUnknown,
									Versions: []string{},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
				"CVE-2021-2": []result.Result{
					{
						ID: "CVE-2021-2",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:  vulnerability.Reference{ID: "CVE-2021-2"},
								Constraint: version.MustGetConstraint("", version.RpmFormat),
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateUnknown,
									Versions: []string{},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
				"CVE-2021-3": []result.Result{
					{
						ID: "CVE-2021-3",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:  vulnerability.Reference{ID: "CVE-2021-2"},
								Constraint: nil, // no constraint, so we assume we're never vulnerable to this
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateUnknown,
									Versions: []string{},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
			},
			resolutionResults: result.Set{
				"CVE-2021-1": []result.Result{
					{
						ID: "CVE-2021-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference:  vulnerability.Reference{ID: "CVE-2021-1"},
								Constraint: version.MustGetConstraint("< 1.5.0", version.RpmFormat),
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateFixed,
									Versions: []string{"1.5.0"},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
			},
			want: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: "CVE-2021-1"},
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateFixed,
							Versions: []string{"1.5.0"},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.RedHat,
							Version: "9.4",
							Channel: "eus",
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: "CVE-2021-2"},
						Fix: vulnerability.Fix{
							State:    vulnerability.FixStateUnknown,
							Versions: []string{},
						},
					},
					Package: pkg.Package{
						ID:      pkg.ID("test-pkg-id"),
						Name:    "test-pkg",
						Version: "1.0.0",
						Type:    syftPkg.RpmPkg,
						Distro: &distro.Distro{
							Type:    distro.RedHat,
							Version: "9.4",
							Channel: "eus",
						},
					},
					Details: []match.Detail{{Type: match.ExactDirectMatch}},
				},
			},
		},
		{
			name: "error fetching disclosures",
			searchPkg: pkg.Package{
				ID:      pkg.ID("test-pkg-id"),
				Name:    "test-pkg",
				Version: "1.0.0",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.RedHat,
					Version: "9.4",
					Channel: "eus",
				},
			},
			disclosureResults: result.Set{},
			resolutionResults: result.Set{},
			want:              nil,
			wantErr:           require.Error,
		},
		{
			name: "error fetching resolutions",
			searchPkg: pkg.Package{
				ID:      pkg.ID("test-pkg-id"),
				Name:    "test-pkg",
				Version: "1.0.0",
				Type:    syftPkg.RpmPkg,
				Distro: &distro.Distro{
					Type:    distro.RedHat,
					Version: "9.4",
					Channel: "eus",
				},
			},
			disclosureResults: result.Set{
				"CVE-2021-1": []result.Result{
					{
						ID: "CVE-2021-1",
						Vulnerabilities: []vulnerability.Vulnerability{
							{
								Reference: vulnerability.Reference{ID: "CVE-2021-1"},
								Fix: vulnerability.Fix{
									State:    vulnerability.FixStateUnknown,
									Versions: []string{},
								},
							},
						},
						Details: []match.Detail{{Type: match.ExactDirectMatch}},
					},
				},
			},
			resolutionResults: result.Set{},
			want:              nil,
			wantErr:           require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			mockProvider := newMockResultProvider()
			mockProvider.setDisclosureResults(tt.disclosureResults)
			mockProvider.setResolutionResults(tt.resolutionResults)

			if tt.name == "error fetching disclosures" {
				mockProvider.setDisclosureError(errors.New("disclosure error"))
			}
			if tt.name == "error fetching resolutions" {
				mockProvider.setResolutionError(errors.New("resolution error"))
			}

			matcher := &Matcher{}

			got, err := matcher.findEUSMatches(mockProvider, tt.searchPkg)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			// need stable results for comparison
			sort.Sort(match.ByElements(got))

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(version.Version{}),
				cmpopts.IgnoreUnexported(distro.Distro{}),
				cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
				cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
				cmpopts.EquateEmpty(),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("findEUSMatches() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func strRef(s string) *string {
	return &s
}

type mockResultProvider struct {
	disclosureResults result.Set
	resolutionResults result.Set
	disclosureError   error
	resolutionError   error
	callCount         int
}

func newMockResultProvider() *mockResultProvider {
	return &mockResultProvider{
		disclosureResults: make(result.Set),
		resolutionResults: make(result.Set),
	}
}

func (m *mockResultProvider) setDisclosureResults(results result.Set) {
	m.disclosureResults = results
}

func (m *mockResultProvider) setResolutionResults(results result.Set) {
	m.resolutionResults = results
}

func (m *mockResultProvider) setDisclosureError(err error) {
	m.disclosureError = err
}

func (m *mockResultProvider) setResolutionError(err error) {
	m.resolutionError = err
}

func (m *mockResultProvider) FindResults(criteria ...vulnerability.Criteria) (result.Set, error) {
	m.callCount++

	// heuristic: first call is for disclosures (base distro), second is for resolutions (base + eus distro)
	if m.callCount == 1 {
		if m.disclosureError != nil {
			return result.Set{}, m.disclosureError
		}
		return m.disclosureResults, nil
	}

	if m.resolutionError != nil {
		return result.Set{}, m.resolutionError
	}
	return m.resolutionResults, nil
}
