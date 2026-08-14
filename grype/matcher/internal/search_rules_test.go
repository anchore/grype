package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
)

// mockSearchRuleProvider wraps mock.VulnerabilityProvider and adds SearchRuleProvider support
type mockSearchRuleProvider struct {
	vulnerability.Provider
	rules []vulnerability.SearchRule
}

func (m *mockSearchRuleProvider) SearchRules(_ pkg.Package) []vulnerability.SearchRule {
	return m.rules
}

func TestIncludeBaseDistro(t *testing.T) {
	ptr := func(b bool) *bool { return &b }

	tests := []struct {
		name  string
		rules []vulnerability.SearchRule
		want  bool
	}{
		{
			name:  "no rules apply to the package",
			rules: nil,
			want:  true,
		},
		{
			name:  "a rule with no preference leaves the base search in place",
			rules: []vulnerability.SearchRule{{}},
			want:  true,
		},
		{
			name:  "the rule's data is the complete picture",
			rules: []vulnerability.SearchRule{{IncludeBaseDistro: ptr(false)}},
			want:  false,
		},
		{
			name:  "a rule asking for the base search keeps it",
			rules: []vulnerability.SearchRule{{IncludeBaseDistro: ptr(true)}},
			want:  true,
		},
		{
			// one rule reporting its records as fixes-only is reason enough to keep searching, which
			// is what makes the fold independent of the order rules come back in
			name:  "true wins when rules disagree",
			rules: []vulnerability.SearchRule{{IncludeBaseDistro: ptr(false)}, {IncludeBaseDistro: ptr(true)}},
			want:  true,
		},
		{
			name:  "true still wins in the other order",
			rules: []vulnerability.SearchRule{{IncludeBaseDistro: ptr(true)}, {IncludeBaseDistro: ptr(false)}},
			want:  true,
		},
		{
			name:  "a rule with no preference does not override one that has it",
			rules: []vulnerability.SearchRule{{}, {IncludeBaseDistro: ptr(false)}},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockSearchRuleProvider{Provider: mock.VulnerabilityProvider(), rules: tt.rules}
			assert.Equal(t, tt.want, IncludeBaseDistro(provider, pkg.Package{Name: "curl"}))
		})
	}
}

func TestIncludeBaseDistro_ProviderWithoutSearchRules(t *testing.T) {
	// a provider that exposes no search rules searches everything, which is the historical behavior
	assert.True(t, IncludeBaseDistro(mock.VulnerabilityProvider(), pkg.Package{Name: "curl"}))
}
