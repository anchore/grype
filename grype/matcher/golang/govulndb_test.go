package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherGolang_GoVulnDB drives ecosystem-name matching against records
// from the Go vulnerability database (vuln.go.dev). Records arrive via the
// govulndb vunnel provider as OSV-shaped JSON with ID prefix "GO-".
//
// Three fixtures cover the dominant record shapes:
//   - GO-2020-0001: a regular module (github.com/gin-gonic/gin) with a single
//     SEMVER range "< 1.6.0". Exercises the affected-package emission path
//     for non-stdlib modules.
//   - GO-2022-0969: stdlib with a multi-window SEMVER range
//     (< 1.18.6 || >=1.19.0-0,< 1.19.1). Exercises the multi-window range
//     normalization and confirms the matcher's ecosystem-name search finds
//     stdlib records (separate from the existing NVD CPE path).
//   - GO-2022-0617: withdrawn k8s.io/kubernetes record. go.dev withdrew it
//     ("low severity issue with no fix available or planned; likely to cause
//     false positives") but the record retains its unbounded `affected`
//     range. Pins down that the strategy's withdrawn-handling translates
//     into a non-match at the matcher level — the user-visible behavior we
//     actually care about.
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
			// GO-2024-2519 (grafana) is the "+incompatible" false-positive
			// case. github.com/grafana/grafana ships v6+ tags but never moved
			// its module path to /vN, so go.dev could not map the source
			// advisory's "6.0.0 before 7.2.1" range onto Go module semver. It
			// emitted an *unbounded* standard SEMVER range ([{introduced: "0"}],
			// no fixed/last_affected event) and stashed the real range in
			// ecosystem_specific.custom_ranges (type ECOSYSTEM). The record's
			// own details note says so and warns this "is causing false-positive
			// reports from vulnerability scanners."
			//
			// The current transformer reads only the standard ranges, so
			// {introduced: "0"} alone yields an empty constraint that matches
			// *every* version. grafana v11.6.15 — five major versions past the
			// real fix — therefore gets flagged. This asserts the user-visible
			// fix: a version outside the real custom_ranges window must not
			// match.
			name:       "grafana past real fix against +incompatible GO-2024-2519: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v11.6.15",
		},
		{
			// The flip side of the +incompatible fix: a version *inside* the
			// custom_ranges window (6.0.0 → 7.2.1) is genuinely affected and
			// must still be flagged. This guards against an over-broad fix that
			// simply drops the affected entry — the constraint has to come from
			// custom_ranges, not disappear.
			name:       "grafana within real GO-2024-2519 window: flagged via custom_ranges",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v6.5.0",
			expectID:   "GO-2024-2519",
		},
		{
			// GO-2024-2629 is a real multi-window grafana record
			// (CVE-2024-1442): five disjoint custom_ranges windows
			// (8.5.0→9.5.7, 10.0.0→10.0.12, 10.1.0→10.1.8, 10.2.0→10.2.5,
			// 10.3.0→10.3.4). v11.6.15 is the exact version syft records for
			// github.com/grafana/grafana in sboms/grafana-fips-11-syft.json —
			// the real-world false positive. It sits past every window, so the
			// custom_ranges fallback must produce no match.
			name:       "grafana v11.6.15 (real SBOM version) past all GO-2024-2629 windows: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v11.6.15",
		},
		{
			// Inside the 10.2.0→10.2.5 window: genuinely affected, must match.
			// Proves the multi-window custom_ranges constraint is evaluated
			// end-to-end, not just emitted.
			name:       "grafana inside a GO-2024-2629 window: flagged",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v10.2.3",
			expectID:   "GO-2024-2629",
		},
		{
			// In the gap between windows: > 10.0.12 (fixed) and < 10.1.0
			// (next introduced). A version landing between two disjoint windows
			// must NOT match — this is what a single match-all constraint would
			// have wrongly flagged.
			name:       "grafana between GO-2024-2629 windows: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v10.0.13",
		},
		{
			// GO-2025-4153 (CVE-2025-41115) is the messy "open-ended standard
			// range" case. Its standard SEMVER range is a single fix-less
			// pseudo-version event ([{introduced: "1.9.2-0.20250310..."}]) — an
			// unbounded ">= v1.9.2-pre" constraint that matches every later
			// release — while the real affected set lives in custom_ranges
			// (< a Nov-2025 pseudo-version, plus 12.0.0→12.0.7, 12.1.0→12.1.4,
			// 12.2.0→12.2.2). v11.6.15 (the real SBOM version) satisfies the
			// open-ended standard range but is in no real window. The strategy
			// drops the open-ended standard range when custom_ranges is present,
			// so this must not match.
			name:       "grafana v11.6.15 against open-ended GO-2025-4153: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v11.6.15",
		},
		{
			// Inside the 12.1.0→12.1.4 custom_ranges window: genuinely affected,
			// must still be flagged after the open-ended standard range is
			// dropped.
			name:       "grafana inside a GO-2025-4153 custom window: flagged",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v12.1.2",
			expectID:   "GO-2025-4153",
		},
		{
			// Past every GO-2025-4153 window (> 12.2.2, and a release tag rather
			// than a pre-Nov-2025 pseudo-version): not affected. Guards against
			// the open-ended standard range sneaking back in.
			name:       "grafana v12.3.0 past all GO-2025-4153 windows: no match",
			pkgName:    "github.com/grafana/grafana",
			pkgVersion: "v12.3.0",
		},
		{
			// GO-2026-4916 (CVE-2026-26233) is the regression guard for the
			// *surgical* fix. Its standard ranges are bounded +incompatible tag
			// windows (10.11.0-rc1→10.11.12, 11.2.0-rc1→11.2.4, …) while
			// custom_ranges carries a disjoint pseudo-version window. Because the
			// standard windows are bounded (not open-ended), they must be kept —
			// dropping them in favor of custom_ranges would be a false negative.
			// A main-module mattermost at v11.2.1 sits inside a standard window
			// and must be flagged.
			name:       "mattermost in bounded standard window survives GO-2026-4916 union: flagged",
			pkgName:    "github.com/mattermost/mattermost-server",
			pkgVersion: "v11.2.1+incompatible",
			expectID:   "GO-2026-4916",
		},
		{
			// Between two bounded standard windows (> 11.2.4 fixed, < 11.3.0-rc1):
			// not affected. Confirms the kept standard windows stay bounded and
			// don't over-match.
			name:       "mattermost between GO-2026-4916 standard windows: no match",
			pkgName:    "github.com/mattermost/mattermost-server",
			pkgVersion: "v11.2.9+incompatible",
		},
		{
			// GO-2022-0617 has an unbounded vulnerable range
			// ([{introduced: "0"}] — no fixed/last_affected event), so if
			// the strategy emitted it as Status=Active, every version of
			// k8s.io/kubernetes would match. The OSV record carries a
			// `withdrawn` timestamp, which the strategy now translates to
			// Status=Rejected, and the matcher's
			// OnlyNonWithdrawnVulnerabilities filter drops it before
			// version evaluation. Asserting IsEmpty here is the only
			// guarantee that actually matters to users: withdrawn → no
			// finding.
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
