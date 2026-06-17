package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherGolang_GoVulnDB drives ecosystem-name matching against Go vuln DB
// (vuln.go.dev) records, which arrive via the govulndb vunnel provider as
// OSV-shaped JSON with a "GO-" ID prefix. Fixtures cover the regular-module,
// stdlib multi-window, withdrawn, and custom_ranges (+incompatible) shapes; each
// case names the record it exercises.
func TestMatcherGolang_GoVulnDB(t *testing.T) {
	tests := []struct {
		name       string
		pkgName    string
		pkgVersion string
		expectID   string // empty means no match expected
	}{
		{
			name:       "gin-gonic below fixed version: GO-2020-0001 flags it",
			pkgName:    "github.com/gin-gonic/gin",
			pkgVersion: "v1.5.0",
			expectID:   "GO-2020-0001",
		},
		{
			name:       "gin-gonic at fixed version: no match",
			pkgName:    "github.com/gin-gonic/gin",
			pkgVersion: "v1.6.0",
		},
		{
			name:       "stdlib in first vulnerable window: GO-2022-0969 flags it",
			pkgName:    "stdlib",
			pkgVersion: "go1.18.0",
			expectID:   "GO-2022-0969",
		},
		{
			name:       "stdlib past first fix, before second window: no match",
			pkgName:    "stdlib",
			pkgVersion: "go1.18.6",
		},
		{
			name:       "stdlib in second vulnerable window: GO-2022-0969 flags it",
			pkgName:    "stdlib",
			pkgVersion: "go1.19.0",
			expectID:   "GO-2022-0969",
		},
		{
			// GO-2024-2519: grafana ships v6+ tags without a /vN path, so go.dev
			// couldn't map "6.0.0 before 7.2.1" — it emitted an unbounded
			// standard range ([{introduced: "0"}]) and put the real window in
			// custom_ranges. v11.6.15 is past the fix and must not match.
			name:       "grafana past real fix against +incompatible GO-2024-2519: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v11.6.15",
		},
		{
			// Inside custom_ranges (6.0.0→7.2.1): genuinely affected. Guards
			// against a fix that drops the entry instead of reading custom_ranges.
			name:       "grafana within real GO-2024-2519 window: flagged via custom_ranges",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v6.5.0",
			expectID:   "GO-2024-2519",
		},
		{
			// GO-2024-2629 (CVE-2024-1442): five disjoint custom_ranges windows
			// (8.5.0→9.5.7 … 10.3.0→10.3.4). v11.6.15 is the SBOM version
			// (grafana-fips-11-syft.json), past every window → no match.
			name:       "grafana v11.6.15 (real SBOM version) past all GO-2024-2629 windows: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v11.6.15",
		},
		{
			// Inside 10.2.0→10.2.5: affected. Proves multi-window custom_ranges
			// evaluate end-to-end, not just emit.
			name:       "grafana inside a GO-2024-2629 window: flagged",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v10.2.3",
			expectID:   "GO-2024-2629",
		},
		{
			// Gap between windows (>10.0.12, <10.1.0): no match.
			name:       "grafana between GO-2024-2629 windows: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v10.0.13",
		},
		{
			// GO-2025-4153 (CVE-2025-41115): the standard range is a fix-less
			// pseudo-version (">= v1.9.2-pre"), unbounded above; the real windows
			// live in custom_ranges (< a Nov-2025 pseudo, 12.0.0→12.0.7 …
			// 12.2.0→12.2.2). v11.6.15 satisfies the open-ended range but no real
			// window — the strategy drops the open-ended range, so no match.
			name:       "grafana v11.6.15 against open-ended GO-2025-4153: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v11.6.15",
		},
		{
			// Inside custom_ranges 12.1.0→12.1.4: affected even after the
			// open-ended standard range is dropped.
			name:       "grafana inside a GO-2025-4153 custom window: flagged",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v12.1.2",
			expectID:   "GO-2025-4153",
		},
		{
			// Past every window (>12.2.2): no match. Guards the open-ended range
			// from creeping back.
			name:       "grafana v12.3.0 past all GO-2025-4153 windows: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v12.3.0",
		},
		{
			// GO-2026-4916 (CVE-2026-26233): standard ranges are bounded
			// +incompatible tag windows (…11.2.0-rc1→11.2.4…); custom_ranges holds
			// a disjoint pseudo-version window. The bounded standard windows must
			// survive the union — dropping them would be a false negative — so
			// v11.2.1 still matches.
			name:       "mattermost in bounded standard window survives GO-2026-4916 union: flagged",
			pkgName:    "github.com/mattermost/mattermost-server",
			pkgVersion: "v11.2.1+incompatible",
			expectID:   "GO-2026-4916",
		},
		{
			// Between bounded standard windows (>11.2.4, <11.3.0-rc1): no match.
			name:       "mattermost between GO-2026-4916 standard windows: no match",
			pkgName:    "github.com/mattermost/mattermost-server",
			pkgVersion: "v11.2.9+incompatible",
		},
		{
			// GO-2024-3240 (CVE-2024-10452): standard range is [{introduced: "0"}]
			// with no fix and no custom_ranges, so the transformer produces no
			// usable range. An affected package with zero ranges matches every
			// version ("none (unknown)" constraint); the strategy must skip it.
			// v12.5.0 is past every real grafana window in the fixture, so only a
			// match-all entry could match — the result must be empty. (The real
			// range, per the aliased GHSA-66c4-2g2v-54qw, is <= 10.4.0, covered by
			// the github provider.)
			name:       "grafana v12.5.0 against unbounded no-custom GO-2024-3240: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v12.5.0",
		},
		{
			// GO-2022-0617 is withdrawn but keeps an unbounded range
			// ([{introduced: "0"}]). The strategy marks it Status=Rejected and
			// the matcher's OnlyNonWithdrawnVulnerabilities filter drops it:
			// withdrawn → no finding.
			name:       "k8s.io/kubernetes against withdrawn GO-2022-0617: no match",
			pkgName:    "k8s.io/kubernetes",
			pkgVersion: "v1.20.0",
		},
	}

	dbtest.DBs(t, "govulndb-go").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewGolangMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.GoModulePkg).
					WithLanguage(syftPkg.Go).
					WithMetadata(pkg.GolangBinMetadata{}).
					Build()

				findings := db.Match(t, matcher, p)

				if tt.expectID == "" {
					findings.IsEmpty()
					return
				}

				findings.SelectMatch(tt.expectID).
					SelectDetailByType(match.ExactDirectMatch).
					AsEcosystemSearch()
			})
		}
	})
}
