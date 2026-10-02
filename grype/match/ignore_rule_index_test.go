package match

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// applyIgnoreRulesUnindexed is the implementation of ApplyIgnoreRules before the rules were indexed: every
// rule is evaluated against every match. It is the reference the indexed implementation must agree with.
func applyIgnoreRulesUnindexed(matches Matches, rules []IgnoreRule) (Matches, []IgnoredMatch) {
	matched, ignored := ApplyIgnoreFilters(matches.Sorted(), rules...)
	return NewMatches(matched...), ignored
}

// applyExplicitIgnoreRulesUnindexed mirrors ApplyExplicitIgnoreRules, including the rule list built from the
// provider (one lookup per match, so a vulnerability ID shared by several matches contributes its rules more
// than once), but applies the rules with the unindexed reference implementation.
func applyExplicitIgnoreRulesUnindexed(provider ExclusionProvider, matches Matches) (Matches, []IgnoredMatch) {
	rules := append([]IgnoreRule{}, explicitIgnoreRules...)
	for _, m := range matches.Sorted() {
		r, err := provider.IgnoreRules(m.Vulnerability.ID)
		if err != nil {
			continue
		}
		rules = append(rules, r...)
	}
	return applyIgnoreRulesUnindexed(matches, rules)
}

func TestIgnoreRuleIndex_PreservesRuleOrder(t *testing.T) {
	m := Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-1", Namespace: "debian:distro:debian:12"},
			RelatedVulnerabilities: []vulnerability.Reference{
				{ID: "CVE-ALIAS"},
			},
		},
		Package: pkg.Package{ID: "p1", Name: "linux-libc-dev", Type: syftPkg.DebPkg},
	}

	// indexed (vulnerability, no aliases) and unindexed rules interleaved, with a duplicate, the way
	// ApplyExplicitIgnoreRules builds its list when several matches share a vulnerability ID
	rules := []IgnoreRule{
		{Vulnerability: "CVE-1", Reason: "indexed 0"},
		{Package: IgnoreRulePackage{Name: "linux-.*"}, Reason: "unindexed 1"},
		{Vulnerability: "CVE-2", Reason: "other vulnerability 2"},
		{Vulnerability: "CVE-ALIAS", IncludeAliases: true, Reason: "alias 3"},
		{Vulnerability: "CVE-1", Namespace: "debian:distro:debian:12", Reason: "indexed 4"},
		{Vulnerability: "CVE-ALIAS", Reason: "alias without include-aliases 5"},
		{Namespace: "debian:distro:debian:12", Reason: "unindexed 6"},
		{Vulnerability: "CVE-1", Reason: "indexed 0"},
		{Vulnerability: "CVE-1", VexStatus: "not_affected", Reason: "vex 8"},
		{Reason: "no criteria 9"},
	}

	got := newIgnoreRuleIndex(rules).IgnoreMatch(m)

	var reasons []string
	for _, r := range got {
		reasons = append(reasons, r.Reason)
	}
	assert.Equal(t, []string{"indexed 0", "unindexed 1", "alias 3", "indexed 4", "unindexed 6", "indexed 0"}, reasons)
}

func TestIgnoreRuleIndex_NoRules(t *testing.T) {
	m := Match{Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-1"}}}
	assert.Nil(t, newIgnoreRuleIndex(nil).IgnoreMatch(m))
}

func TestApplyIgnoreRules_EquivalentToUnindexed(t *testing.T) {
	for seed := uint64(0); seed < 200; seed++ {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
			matches := randomMatches(rng, 1+rng.IntN(60))
			rules := randomIgnoreRules(rng, rng.IntN(80))

			wantMatches, wantIgnored := applyIgnoreRulesUnindexed(matches, rules)
			gotMatches, gotIgnored := ApplyIgnoreRules(matches, rules)

			require.Equal(t, wantMatches.Sorted(), gotMatches.Sorted())
			require.Equal(t, wantIgnored, gotIgnored)
		})
	}
}

func TestApplyExplicitIgnoreRules_EquivalentToUnindexed(t *testing.T) {
	for seed := uint64(0); seed < 200; seed++ {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, seed^0x2545f4914f6cdd1d))
			provider := &mockExclusionProvider{data: map[string][]IgnoreRule{}}
			for _, id := range randomVulnerabilityIDs {
				provider.data[id] = randomIgnoreRules(rng, rng.IntN(6))
			}
			// matches on the explicitly ignored log4j packages exercise the built-in rules too
			matches := randomMatches(rng, 1+rng.IntN(60))

			wantMatches, wantIgnored := applyExplicitIgnoreRulesUnindexed(provider, matches)
			gotMatches, gotIgnored := ApplyExplicitIgnoreRules(provider, matches)

			require.Equal(t, wantMatches.Sorted(), gotMatches.Sorted())
			require.Equal(t, wantIgnored, gotIgnored)
		})
	}
}

var (
	randomVulnerabilityIDs = []string{"CVE-2021-44228", "CVE-2023-45853", "CVE-1", "CVE-2", "GHSA-xxxx-yyyy-zzzz"}
	randomNamespaces       = []string{"debian:distro:debian:12", "nvd:cpe", "github:language:java"}
	randomPackageNames     = []string{"linux-libc-dev", "log4j-api", "zlib1g", "libc6", "linux-headers-6.1"}
	randomRuleNames        = []string{"linux-libc-dev", "log4j-api", "zlib1g", "linux.*", "lib(c6|z)", "linux(-.*)?-headers-.*", "[invalid"}
	randomVersions         = []string{"1.0", "2.0"}
	randomTypes            = []syftPkg.Type{syftPkg.DebPkg, syftPkg.JavaPkg, syftPkg.GemPkg}
	randomLanguages        = []syftPkg.Language{"", syftPkg.Java, syftPkg.Ruby}
	randomLocations        = []string{"/usr/lib/a", "/opt/b/c.jar"}
	randomRuleLocations    = []string{"/usr/lib/a", "/usr/**", "/opt/**/*.jar", "/nowhere"}
	randomUpstreams        = []string{"linux", "glibc", "zlib"}
	randomRuleUpstreams    = []string{"linux", "linux.*", "glibc", "z.*"}
	randomFixStates        = []vulnerability.FixState{"", vulnerability.FixStateFixed, vulnerability.FixStateNotFixed, vulnerability.FixStateWontFix, vulnerability.FixStateUnknown}
	randomMatchTypes       = []Type{ExactDirectMatch, ExactIndirectMatch, CPEMatch}
)

func pick[T any](rng *rand.Rand, from []T) T {
	return from[rng.IntN(len(from))]
}

func randomPackages(rng *rand.Rand, n int) []pkg.Package {
	var out []pkg.Package
	for i := 0; i < n; i++ {
		var upstreams []pkg.UpstreamPackage
		if rng.IntN(2) == 0 {
			upstreams = append(upstreams, pkg.UpstreamPackage{Name: pick(rng, randomUpstreams)})
		}
		out = append(out, pkg.Package{
			ID:        pkg.ID(fmt.Sprintf("pkg-%d", i)),
			Name:      pick(rng, randomPackageNames),
			Version:   pick(rng, randomVersions),
			Type:      pick(rng, randomTypes),
			Language:  pick(rng, randomLanguages),
			Locations: file.NewLocationSet(file.NewLocation(pick(rng, randomLocations))),
			Upstreams: upstreams,
		})
	}
	return out
}

// randomMatches returns up to n matches, each with a distinct fingerprint so the collection does not
// merge any of them; packages are shared between matches, as within one ApplyExplicitIgnoreRules call
func randomMatches(rng *rand.Rand, n int) Matches {
	packages := randomPackages(rng, 1+rng.IntN(4))
	seen := map[Fingerprint]bool{}
	var out []Match
	for i := 0; i < n; i++ {
		var related []vulnerability.Reference
		for j := rng.IntN(3); j > 0; j-- {
			related = append(related, vulnerability.Reference{ID: pick(rng, randomVulnerabilityIDs)})
		}
		m := Match{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        pick(rng, randomVulnerabilityIDs),
					Namespace: pick(rng, randomNamespaces),
				},
				// a distinct fix version gives a total order: Matches.Sorted() leaves ties in map order
				Fix:                    vulnerability.Fix{State: pick(rng, randomFixStates), Versions: []string{fmt.Sprintf("%03d", i)}},
				RelatedVulnerabilities: related,
			},
			Package: pick(rng, packages),
			Details: Details{{Type: pick(rng, randomMatchTypes)}},
		}
		if seen[m.Fingerprint()] {
			continue
		}
		seen[m.Fingerprint()] = true
		out = append(out, m)
	}
	return NewMatches(out...)
}

func randomIgnoreRules(rng *rand.Rand, n int) []IgnoreRule {
	var out []IgnoreRule
	for i := 0; i < n; i++ {
		// repeat an earlier rule now and then, as ApplyExplicitIgnoreRules does for a shared vulnerability ID
		if len(out) > 0 && rng.IntN(8) == 0 {
			out = append(out, pick(rng, out))
			continue
		}
		var r IgnoreRule
		maybe := func(p int) bool { return rng.IntN(100) < p }
		if maybe(70) {
			r.Vulnerability = pick(rng, randomVulnerabilityIDs)
		}
		if maybe(25) {
			r.IncludeAliases = true
		}
		if maybe(25) {
			r.Namespace = pick(rng, randomNamespaces)
		}
		if maybe(25) {
			r.FixState = string(pick(rng, randomFixStates))
		}
		if maybe(40) {
			r.Package.Name = pick(rng, randomRuleNames)
		}
		if maybe(15) {
			r.Package.Version = pick(rng, randomVersions)
		}
		if maybe(15) {
			r.Package.Language = string(pick(rng, randomLanguages))
		}
		if maybe(25) {
			r.Package.Type = string(pick(rng, randomTypes))
		}
		if maybe(15) {
			r.Package.Location = pick(rng, randomRuleLocations)
		}
		if maybe(15) {
			r.Package.UpstreamName = pick(rng, randomRuleUpstreams)
		}
		if maybe(15) {
			r.MatchType = pick(rng, randomMatchTypes)
		}
		if maybe(5) {
			r.VexStatus = "not_affected"
		}
		r.Reason = fmt.Sprintf("rule %d", i)
		out = append(out, r)
	}
	return out
}

// exclusionShapedInput builds one package's matches against a provider with rulesPerVulnerability
// exclusion rules for each vulnerability, the shape of linux-libc-dev against a large match-exclusions DB.
func exclusionShapedInput(numMatches, rulesPerVulnerability int) (ExclusionProvider, Matches) {
	provider := &mockExclusionProvider{data: map[string][]IgnoreRule{}}
	p := pkg.Package{
		ID:        "linux-libc-dev",
		Name:      "linux-libc-dev",
		Version:   "6.1.0",
		Type:      syftPkg.DebPkg,
		Locations: file.NewLocationSet(file.NewLocation("/var/lib/dpkg/status")),
		Upstreams: []pkg.UpstreamPackage{{Name: "linux"}},
	}
	var matches []Match
	for i := 0; i < numMatches; i++ {
		id := fmt.Sprintf("CVE-2024-%05d", i)
		for j := 0; j < rulesPerVulnerability; j++ {
			provider.data[id] = append(provider.data[id], IgnoreRule{
				Vulnerability: id,
				Namespace:     fmt.Sprintf("ubuntu:distro:ubuntu:%d.04", 18+2*j),
				Package:       IgnoreRulePackage{Name: "linux", Type: string(syftPkg.DebPkg)},
			})
		}
		matches = append(matches, Match{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: id, Namespace: "debian:distro:debian:12"},
			},
			Package: p,
			Details: Details{{Type: ExactIndirectMatch}},
		})
	}
	return provider, NewMatches(matches...)
}

func BenchmarkApplyExplicitIgnoreRules(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		provider, matches := exclusionShapedInput(n, 2)
		b.Run(fmt.Sprintf("matches=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ApplyExplicitIgnoreRules(provider, matches)
			}
		})
	}
}
