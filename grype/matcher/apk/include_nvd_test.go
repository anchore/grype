package apk

import (
	"testing"

	"github.com/stretchr/testify/assert"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
)

// ruleProvider is a vulnerability provider that exposes a fixed set of search rules for every
// package, so these cases can state the rules directly rather than through a fixture DB.
type ruleProvider struct {
	vulnerability.Provider
	rules []v6.SearchRule
}

func (p ruleProvider) SearchRules(pkg.Package) []v6.SearchRule {
	return p.rules
}

func TestIncludeNVD(t *testing.T) {
	nvd := "" // a non-NULL but empty replacement OS name is the CPE-indexed (NVD) records
	rf := "rapidfort-alpine"

	tests := []struct {
		name  string
		rules []v6.SearchRule
		want  bool
	}{
		{
			name: "no rule speaks for the package, so the disclosure fallback stands",
			want: true,
		},
		{
			// alpine secDB reports fixes without disclosures; a vendor curating both says so by
			// carrying a rule at all
			name:  "a rule speaks for the package, so its vendor's data is the whole picture",
			rules: []v6.SearchRule{{MatchDistroName: rf}},
			want:  false,
		},
		{
			name:  "a rule naming NVD asks for those records back",
			rules: []v6.SearchRule{{MatchDistroName: rf, ReplacementDistroName: &nvd}},
			want:  true,
		},
		{
			name: "one rule naming NVD answers for the set",
			rules: []v6.SearchRule{
				{MatchDistroName: rf, MatchPackageVersion: `.*-rf.*`, ReplacementChannel: strRef("rf")},
				{MatchDistroName: rf, ReplacementDistroName: &nvd},
			},
			want: true,
		},
		{
			name:  "an OS substitution that is not NVD says nothing about it",
			rules: []v6.SearchRule{{MatchDistroName: rf, MatchPackageName: `.*`, ReplacementDistroName: strRef("alpine")}},
			want:  false,
		},
	}

	p := pkg.Package{Name: "curl", Version: "8.5.0-r0"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := ruleProvider{Provider: mock.VulnerabilityProvider(), rules: tt.rules}
			assert.Equal(t, tt.want, includeNVD(vp, p))
		})
	}

	t.Run("a provider exposing no rules at all keeps the fallback", func(t *testing.T) {
		assert.True(t, includeNVD(mock.VulnerabilityProvider(), p))
	})
}

func strRef(s string) *string {
	return &s
}
