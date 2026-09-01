package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSearchRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		row     SearchRule
		wantErr string
	}{
		{
			name:    "no predicate at all",
			row:     SearchRule{ReplacementDistroName: ptr("echo")},
			wantErr: "must have at least one predicate",
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
			// a rule that substitutes nothing states that this distro's own data is the whole
			// picture for its packages, so it may be scoped to the distro alone
			name: "a rule that substitutes nothing may omit package predicates",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine"},
		},
		{
			name: "an ecosystem-scoped rule may omit package predicates too",
			row:  SearchRule{MatchEcosystem: "apk"},
		},
		{
			name: "a rule that substitutes nothing may still name the packages it speaks for",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine", MatchPackageName: "curl"},
		},
		{
			// an empty (but non-NULL) OS name is the NVD records, which rewrites no search: it only
			// says those records still count for the package, so it may be scoped to the distro
			// alone like any other statement
			name: "a rule naming the NVD records may omit package predicates",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine", ReplacementDistroName: ptr("")},
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

func TestVulnerabilityProvider_SearchRules(t *testing.T) {
	vp := vulnerabilityProvider{searchRules: newSearchRuleIndex(KnownSearchRules())}

	apkPkg := func(d *distro.Distro) pkg.Package {
		return pkg.Package{Name: "curl", Version: "8.5.0-r0", Type: syftPkg.ApkPkg, Distro: d}
	}

	rfAlpine := apkPkg(distro.New(distro.RapidFortAlpine, "3.18", ""))

	// rapidfort-alpine's rule speaks for every package of that distro
	got := vp.SearchRules(rfAlpine)
	require.Len(t, got, 1)
	assert.Equal(t, "rapidfort-alpine", got[0].MatchDistroName)
	assert.False(t, got[0].hasSubstitution(), "the rule states only that it speaks for the package")

	// plain alpine has no rule at all: its secDB reports fixes only, so the base search and the
	// matchers' upstream fallback both stand
	assert.Nil(t, vp.SearchRules(apkPkg(distro.New(distro.Alpine, "3.18", ""))))
	assert.Nil(t, vp.SearchRules(apkPkg(nil)))

	t.Run("rules that speak for individual packages apply too", func(t *testing.T) {
		// unlike a criteria set — which carries only what its query shape provides — a package
		// carries name, version, ecosystem and distro at once, so the rapidfort release-stream
		// rules are visible here alongside OS-scoped rules
		p := pkg.Package{Name: "curl", Version: "7.78.0-3.fc43", Type: syftPkg.RpmPkg, Distro: distro.New(distro.RapidFortRedHat, "9", "")}
		got := vp.SearchRules(p)
		require.Len(t, got, 1)
		assert.Equal(t, "rapidfort-redhat", got[0].MatchDistroName)
		assert.NotNil(t, got[0].ReplacementChannel)

		// a native-stream (elN) package matches no rule: it is searched in the channel-less rows
		p.Version = "7.78.0-3.el9"
		assert.Nil(t, vp.SearchRules(p))
	})

	t.Run("a rule that substitutes nothing is reported alongside a higher priority stream rule", func(t *testing.T) {
		// a package routed to a stream channel by a higher-priority rule keeps the statement that
		// its vendor's data is the whole picture: such a rule is outside the priority contest, so
		// both rows come back
		vp := vulnerabilityProvider{searchRules: newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-alpine", MatchPackageVersion: `.*-rf.*`, ReplacementChannel: ptr("rf"), Priority: 30},
			{MatchDistroName: "rapidfort-alpine"},
		})}
		p := rfAlpine
		p.Version = "8.5.0-r0-rf.1"
		got := vp.SearchRules(p)
		require.Len(t, got, 2)
		assert.Equal(t, ptr("rf"), got[0].ReplacementChannel)
		assert.False(t, got[1].hasSubstitution())
	})

	t.Run("only the highest priority rules are reported", func(t *testing.T) {
		vp := vulnerabilityProvider{searchRules: newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-alpine", MatchPackageName: `curl`, ReplacementChannel: ptr("a"), Priority: 2},
			{MatchDistroName: "rapidfort-alpine", MatchPackageName: `curl`, ReplacementChannel: ptr("b"), Priority: 1},
		})}
		got := vp.SearchRules(rfAlpine)
		require.Len(t, got, 1)
		assert.Equal(t, ptr("a"), got[0].ReplacementChannel)
	})

	t.Run("rules tied at the winning priority are all reported", func(t *testing.T) {
		// what several rules mean together is the caller's to fold, so both come back as stated,
		// in the order they were read
		vp := vulnerabilityProvider{searchRules: newSearchRuleIndex([]SearchRule{
			{MatchDistroName: "rapidfort-alpine", MatchPackageName: `curl`, ReplacementChannel: ptr("a"), Priority: 2},
			{MatchDistroName: "rapidfort-alpine", MatchPackageName: `curl`, ReplacementPackageName: "rf-$0", Priority: 2},
		})}
		got := vp.SearchRules(rfAlpine)
		require.Len(t, got, 2)
		assert.Equal(t, ptr("a"), got[0].ReplacementChannel)
		assert.Equal(t, "rf-$0", got[1].ReplacementPackageName)
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
