package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSearchRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		row     SearchRule
		wantErr string
	}{
		{
			name:    "no substitution",
			row:     SearchRule{MatchDistroName: "debian", MatchPackageName: "foo"},
			wantErr: "must have at least one substitution",
		},
		{
			name:    "replacement package name without a name pattern",
			row:     SearchRule{ReplacementPackageName: "$1", MatchPackageVersion: `.*\.rf.*`},
			wantErr: "must have a package name pattern",
		},
		{
			name:    "channel substitution without a distro name",
			row:     SearchRule{MatchPackageVersion: `.*\.rf.*`, ReplacementChannel: ptr("rf")},
			wantErr: "must have a distro name to match",
		},
		{
			name:    "substitution without package predicates",
			row:     SearchRule{MatchDistroName: "debian", ReplacementChannel: ptr("rf")},
			wantErr: "must have at least one package predicate",
		},
		{
			name:    "invalid pattern",
			row:     SearchRule{MatchDistroName: "debian", MatchPackageVersion: `(`, ReplacementChannel: ptr("rf")},
			wantErr: "invalid pattern",
		},
		{
			name: "policy-only rule may omit package predicates",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine", IncludeBaseDistro: ptr(false)},
		},
		{
			name: "distro name substitution without a distro predicate is legal (echo shape)",
			row:  SearchRule{MatchEcosystem: "deb", MatchPackageVersion: `.*[.-]echo.*`, ReplacementDistroName: ptr("echo")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.row.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestKnownSearchRules_AllValid(t *testing.T) {
	rules := newSearchRuleIndex(KnownSearchRules())
	assert.Len(t, rules.rules, len(KnownSearchRules()), "every built-in rule must compile")
}

// resolveQueries runs criteria through the rules the way FindVulnerabilities does, returning the
// queries that would actually be run.
func resolveQueries(t *testing.T, rules *searchRuleIndex, criteria []vulnerability.Criteria) []*searchQuery {
	t.Helper()
	queries, err := newSearchQuery(criteria, rules)
	require.NoError(t, err)
	return queries
}

// distrosOfSets renders the OS specifiers of each resolved query as `<name> <version>[+<channel>]`
// (nil for a query that searches data stored without an OS), so tests can assert on the search
// routing rather than on specifier internals. OSSpecifier.String omits the channel, which is the one
// thing these tests are about.
func distrosOfSets(queries []*searchQuery) [][]string {
	var out [][]string
	for _, q := range queries {
		var distros []string
		for _, s := range q.osSpecs {
			if s == nil || *s == *NoOSSpecified {
				continue
			}
			rendered := s.Name + " " + s.version()
			if s.Channel != "" {
				rendered += "+" + s.Channel
			}
			distros = append(distros, rendered)
		}
		out = append(out, distros)
	}
	return out
}

func namesOfSets(queries []*searchQuery) []string {
	var out []string
	for _, q := range queries {
		out = append(out, q.packageName())
	}
	return out
}

func TestApplySearchRules_RapidfortDistroQueries(t *testing.T) {
	defaults := newSearchRuleIndex(KnownSearchRules())
	rfRedhat := distro.New(distro.RapidFortRedHat, "9", "")
	rfUbuntu := distro.New(distro.RapidFortUbuntu, "20.04", "")

	tests := []struct {
		name        string
		d           *distro.Distro
		pkgName     string
		pkgVersion  string
		format      version.Format
		wantDistros [][]string
	}{
		{
			name:        "fc dist tag adds the fedora stream channel alongside the channel-less rows",
			d:           rfRedhat,
			pkgName:     "curl",
			pkgVersion:  "7.78.0-3.fc43",
			format:      version.RpmFormat,
			wantDistros: [][]string{{"rapidfort-redhat 9", "rapidfort-redhat 9+fc43"}},
		},
		{
			name:        "rf marker outranks the fc dist tag by priority",
			d:           rfRedhat,
			pkgName:     "curl",
			pkgVersion:  "1:12.6.0-2.fc31.rf.1",
			format:      version.RpmFormat,
			wantDistros: [][]string{{"rapidfort-redhat 9", "rapidfort-redhat 9+rf"}},
		},
		{
			name:        "el dist tag is the native stream (no rule fires)",
			d:           rfRedhat,
			pkgName:     "curl",
			pkgVersion:  "0:7.76.1-19.el9_2",
			format:      version.RpmFormat,
			wantDistros: [][]string{{"rapidfort-redhat 9"}},
		},
		{
			name:        "rf- name prefix is the fallback for unmarked versions",
			d:           rfRedhat,
			pkgName:     "rf-scanner",
			pkgVersion:  "1.2.3-4",
			format:      version.RpmFormat,
			wantDistros: [][]string{{"rapidfort-redhat 9", "rapidfort-redhat 9+rf"}},
		},
		{
			name:        "rf- name with an fc-tagged version routes by the higher-priority version rule",
			d:           rfRedhat,
			pkgName:     "rf-curl",
			pkgVersion:  "7.78.0-3.fc43",
			format:      version.RpmFormat,
			wantDistros: [][]string{{"rapidfort-redhat 9", "rapidfort-redhat 9+fc43"}},
		},
		{
			name:        "rf- name with an el-tagged version stays on the native stream",
			d:           rfRedhat,
			pkgName:     "rf-wget",
			pkgVersion:  "1.20.3-1.el9",
			format:      version.RpmFormat,
			wantDistros: [][]string{{"rapidfort-redhat 9"}},
		},
		{
			name:        "rfubu dpkg marker adds the rf channel alongside the channel-less rows",
			d:           rfUbuntu,
			pkgName:     "tar",
			pkgVersion:  "1.30+dfsg-7rfubu.1",
			format:      version.DebFormat,
			wantDistros: [][]string{{"rapidfort-ubuntu 20.04", "rapidfort-ubuntu 20.04+rf"}},
		},
		{
			name:        "plain ubuntu distro is untouched by rapidfort rules",
			d:           distro.New(distro.Ubuntu, "20.04", ""),
			pkgName:     "tar",
			pkgVersion:  "1.30+dfsg-7rfubu.1",
			format:      version.DebFormat,
			wantDistros: [][]string{{"ubuntu 20.04"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria := []vulnerability.Criteria{
				search.ByPackageName(tt.pkgName),
				search.ByDistro(*tt.d),
				search.WithVersion(*version.New(tt.pkgVersion, tt.format)),
			}
			got := resolveQueries(t, defaults, criteria)
			assert.Equal(t, tt.wantDistros, distrosOfSets(got))
		})
	}
}

func TestApplySearchRules_VersionCriteriaAlsoRoutes(t *testing.T) {
	// the unaffected/NAK queries convey the version through the constraining criteria
	// (search.ByVersion) rather than the non-constraining hint; both must route
	defaults := newSearchRuleIndex(KnownSearchRules())
	criteria := []vulnerability.Criteria{
		search.ByPackageName("curl"),
		search.ByDistro(*distro.New(distro.RapidFortRedHat, "9", "")),
		search.ByVersion(*version.New("7.78.0-3.fc43", version.RpmFormat)),
	}
	got := resolveQueries(t, defaults, criteria)
	assert.Equal(t, [][]string{{"rapidfort-redhat 9", "rapidfort-redhat 9+fc43"}}, distrosOfSets(got))
}

func TestApplySearchRules_VersionlessDistroQueryIsUnrouted(t *testing.T) {
	// matching occurs on the criteria provided: a distro query that conveys no package version
	// cannot be routed by version markers and stays on the channel-less rows
	defaults := newSearchRuleIndex(KnownSearchRules())
	criteria := []vulnerability.Criteria{
		search.ByPackageName("curl"),
		search.ByDistro(*distro.New(distro.RapidFortRedHat, "9", "")),
	}
	got := resolveQueries(t, defaults, criteria)
	assert.Equal(t, [][]string{{"rapidfort-redhat 9"}}, distrosOfSets(got))
}

func TestApplySearchRules_EchoEcosystemQueries(t *testing.T) {
	defaults := newSearchRuleIndex(KnownSearchRules())

	t.Run("echo-marked deb version unions the echo OS identity into an ecosystem query", func(t *testing.T) {
		criteria := []vulnerability.Criteria{
			search.ByEcosystem("", "deb"),
			search.ByPackageName("openssl"),
			search.ByVersion(*version.New("1.1.1n-0+deb11u4.echo1", version.DebFormat)),
		}
		got := resolveQueries(t, defaults, criteria)
		// the original (OS-less) search is kept, and the echo OS identity is searched as an
		// additional query — the two cannot share one query (specific OS vs "no OS" specifier)
		assert.Equal(t, [][]string{nil, {"echo "}}, distrosOfSets(got))
	})

	t.Run("unmarked deb version leaves the ecosystem query untouched", func(t *testing.T) {
		criteria := []vulnerability.Criteria{
			search.ByEcosystem("", "deb"),
			search.ByPackageName("openssl"),
			search.ByVersion(*version.New("1.1.1n-0+deb11u4", version.DebFormat)),
		}
		got := resolveQueries(t, defaults, criteria)
		assert.Equal(t, [][]string{nil}, distrosOfSets(got))
	})

	t.Run("echo rule does not fire on distro queries (no ecosystem criteria provided)", func(t *testing.T) {
		criteria := []vulnerability.Criteria{
			search.ByPackageName("openssl"),
			search.ByDistro(*distro.New(distro.Debian, "11", "")),
			search.WithVersion(*version.New("1.1.1n-0+deb11u4.echo1", version.DebFormat)),
		}
		got := resolveQueries(t, defaults, criteria)
		assert.Equal(t, [][]string{{"debian 11"}}, distrosOfSets(got))
	})
}

func TestApplySearchRules_Priority(t *testing.T) {
	d := distro.New(distro.RapidFortRedHat, "9", "")
	criteria := func() []vulnerability.Criteria {
		return []vulnerability.Criteria{
			search.ByPackageName("curl"),
			search.ByDistro(*d),
			search.WithVersion(*version.New("7.78.0-3.fc43", version.RpmFormat)),
		}
	}

	t.Run("only the highest priority rules apply", func(t *testing.T) {
		rules := newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.fc\d+.*`, ReplacementChannel: ptr("low"), IncludeBaseDistro: ptr(false), Priority: 1},
			{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.fc\d+.*`, ReplacementChannel: ptr("high"), IncludeBaseDistro: ptr(false), Priority: 2},
		})
		got := resolveQueries(t, rules, criteria())
		assert.Equal(t, [][]string{{"rapidfort-redhat 9+high"}}, distrosOfSets(got))
	})

	t.Run("rules tied at the winning priority all apply", func(t *testing.T) {
		rules := newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.fc\d+.*`, ReplacementChannel: ptr("a"), IncludeBaseDistro: ptr(false), Priority: 2},
			{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.fc\d+.*`, ReplacementChannel: ptr("b"), IncludeBaseDistro: ptr(false), Priority: 2},
			{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.fc\d+.*`, ReplacementChannel: ptr("c"), IncludeBaseDistro: ptr(false), Priority: 1},
		})
		got := resolveQueries(t, rules, criteria())
		assert.Equal(t, [][]string{{"rapidfort-redhat 9+a", "rapidfort-redhat 9+b"}}, distrosOfSets(got))
	})

	t.Run("an OS data policy applies alongside the winning substitution", func(t *testing.T) {
		// a policy rule substitutes nothing, so it is not competing with the channel rule and is
		// not ranked against it: the channel still wins the routing, and the policy is not lost
		rules := newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.fc\d+.*`, ReplacementChannel: ptr("fc43"), Priority: 2},
			{MatchDistroName: "rapidfort-redhat", IncludeBaseDistro: ptr(false)},
		})
		got := resolveQueries(t, rules, criteria())
		assert.Equal(t, [][]string{{"rapidfort-redhat 9", "rapidfort-redhat 9+fc43"}}, distrosOfSets(got))
	})

	t.Run("a higher priority distro rule suppresses a lower priority name fanout", func(t *testing.T) {
		rules := newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.fc\d+.*`, ReplacementChannel: ptr("high"), IncludeBaseDistro: ptr(false), Priority: 2},
			{MatchDistroName: "rapidfort-redhat", MatchPackageName: `(.+)`, ReplacementPackageName: "vendor-$1", Priority: 1},
		})
		got := resolveQueries(t, rules, criteria())
		assert.Equal(t, []string{"curl"}, namesOfSets(got))
	})
}

func TestApplySearchRules_RuleIncludingTheBaseDistroKeepsIt(t *testing.T) {
	// a rule whose data reports fixes but not disclosures (IncludeBaseDistro unset, so "include")
	// is unioned into the query: the queried OS rows are searched alongside the overlay, rather
	// than replaced by it
	rules := newSearchRuleIndex([]SearchRule{
		{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.fc\d+.*`, ReplacementChannel: ptr("fc43")},
	})
	criteria := []vulnerability.Criteria{
		search.ByPackageName("curl"),
		search.ByDistro(*distro.New(distro.RapidFortRedHat, "9", "")),
		search.WithVersion(*version.New("7.78.0-3.fc43", version.RpmFormat)),
	}
	got := resolveQueries(t, rules, criteria)
	assert.Equal(t, [][]string{{"rapidfort-redhat 9", "rapidfort-redhat 9+fc43"}}, distrosOfSets(got))
}

func TestApplySearchRules_NameFanout(t *testing.T) {
	rules := newSearchRuleIndex([]SearchRule{
		{MatchEcosystem: "apk", MatchPackageName: `vendor-(.+)`, ReplacementPackageName: "$1"},
	})

	criteria := []vulnerability.Criteria{
		search.ByEcosystem("", "apk"),
		search.ByPackageName("vendor-libssl3"),
	}
	got := resolveQueries(t, rules, criteria)
	assert.Equal(t, []string{"vendor-libssl3", "libssl3"}, namesOfSets(got))
}

func TestApplySearchRules_NoRulesPassthrough(t *testing.T) {
	criteria := []vulnerability.Criteria{
		search.ByPackageName("curl"),
		search.ByDistro(*distro.New(distro.Debian, "11", "")),
	}
	got := resolveQueries(t, nil, criteria)
	require.Len(t, got, 1)
	assert.Equal(t, [][]string{{"debian 11"}}, distrosOfSets(got))
	assert.Equal(t, []string{"curl"}, namesOfSets(got))
}

func TestVulnerabilityProvider_SearchRules(t *testing.T) {
	vp := vulnerabilityProvider{searchRules: newSearchRuleIndex(KnownSearchRules())}

	apkPkg := func(d *distro.Distro) pkg.Package {
		return pkg.Package{Name: "curl", Version: "8.5.0-r0", Type: syftPkg.ApkPkg, Distro: d}
	}

	// rapidfort-alpine's OS-scoped data policy applies to every package of that distro
	assert.Equal(t,
		[]vulnerability.SearchRule{{IncludeBaseDistro: ptr(false)}},
		vp.SearchRules(apkPkg(distro.New(distro.RapidFortAlpine, "3.18", ""))))

	// plain alpine has no rule at all: its secDB reports fixes only, so the base search and the
	// matchers' upstream fallback both stand
	assert.Nil(t, vp.SearchRules(apkPkg(distro.New(distro.Alpine, "3.18", ""))))
	assert.Nil(t, vp.SearchRules(apkPkg(nil)))

	t.Run("rules that speak for individual packages apply too", func(t *testing.T) {
		// unlike a criteria set — which carries only what its query shape provides — a package
		// carries name, version, ecosystem and distro at once, so the rapidfort release-stream
		// rules are visible here alongside OS-scoped policies
		// the release-stream rules state no preference: their channels add to the channel-less rows
		// rather than standing in for them, so nothing here suppresses a matcher's own searches
		p := pkg.Package{Name: "curl", Version: "7.78.0-3.fc43", Type: syftPkg.RpmPkg, Distro: distro.New(distro.RapidFortRedHat, "9", "")}
		assert.Equal(t, []vulnerability.SearchRule{{IncludeBaseDistro: nil}}, vp.SearchRules(p))

		// a native-stream (elN) package matches no rule: it is searched in the channel-less rows
		p.Version = "7.78.0-3.el9"
		assert.Nil(t, vp.SearchRules(p))
	})

	t.Run("an OS data policy is reported alongside a higher priority stream rule", func(t *testing.T) {
		// what makes "never fall back to the upstream data" hold for an OS: a package routed to a
		// stream channel by a higher-priority rule keeps its OS's data policy, so the fold in
		// matcher/internal.IncludeBaseDistro still sees the false
		vp := vulnerabilityProvider{searchRules: newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-alpine", MatchPackageVersion: `.*-rf.*`, ReplacementChannel: ptr("rf"), Priority: 30},
			{MatchDistroName: "rapidfort-alpine", IncludeBaseDistro: ptr(false)},
		})}
		p := apkPkg(distro.New(distro.RapidFortAlpine, "3.18", ""))
		p.Version = "8.5.0-r0-rf.1"
		assert.Equal(t,
			[]vulnerability.SearchRule{{IncludeBaseDistro: nil}, {IncludeBaseDistro: ptr(false)}},
			vp.SearchRules(p))
	})

	t.Run("only the highest priority rules are reported", func(t *testing.T) {
		vp := vulnerabilityProvider{searchRules: newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-alpine", MatchPackageName: `curl`, ReplacementChannel: ptr("a"), IncludeBaseDistro: ptr(false), Priority: 2},
			{MatchDistroName: "rapidfort-alpine", MatchPackageName: `curl`, ReplacementChannel: ptr("b"), IncludeBaseDistro: ptr(true), Priority: 1},
		})}
		assert.Equal(t,
			[]vulnerability.SearchRule{{IncludeBaseDistro: ptr(false)}},
			vp.SearchRules(apkPkg(distro.New(distro.RapidFortAlpine, "3.18", ""))))
	})

	t.Run("rules tied at the winning priority are all reported", func(t *testing.T) {
		// disagreements are the caller's to fold (see matcher/internal.IncludeBaseDistro), so both
		// policies come back as stated
		vp := vulnerabilityProvider{searchRules: newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-alpine", IncludeBaseDistro: ptr(false)},
			{MatchDistroName: "rapidfort-alpine", IncludeBaseDistro: ptr(true)},
		})}
		assert.Equal(t,
			[]vulnerability.SearchRule{{IncludeBaseDistro: ptr(false)}, {IncludeBaseDistro: ptr(true)}},
			vp.SearchRules(apkPkg(distro.New(distro.RapidFortAlpine, "3.18", ""))))
	})
}

func TestFilterSearchRulesForClient(t *testing.T) {
	clientVersion := version.New("6.1.0", version.SemanticFormat)
	rows := []SearchRule{
		{MatchDistroName: "a", MatchPackageName: "x", ReplacementChannel: ptr("c")},
		{MatchDistroName: "b", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: "< 6.0.0"},
		{MatchDistroName: "c", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: ">= 6.0.0"},
		// an unparsable constraint fails open so a bad row never disables data
		{MatchDistroName: "d", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: "not-a-constraint"},
	}

	got := filterSearchRulesForClient(rows, clientVersion)
	var names []string
	for _, r := range got {
		names = append(names, r.MatchDistroName)
	}
	assert.Equal(t, []string{"a", "c", "d"}, names)
}
