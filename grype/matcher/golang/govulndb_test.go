package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherGolang_GoVulnDB drives ecosystem-name matching against Go vuln DB
// (vuln.go.dev) records via the govulndb vunnel provider. The transformer emits
// the "stdlib" pseudo-module and the golang.org/x/* extended standard libraries;
// general third-party modules are dropped to avoid the false-positive load from
// module-path/range mismatches. This test covers the "stdlib" pseudo-module; the
// golang.org/x/* path is covered by TestMatcherGolang_GoVulnDB_GolangOrgX. The
// general third-party cases (gin, grafana, mattermost, docker/cli, k8s) were
// removed because those packages no longer produce matches; transformer-level
// behavior for custom_ranges, withdrawn status, etc. remains covered by the unit
// tests in the osv transformer package.
func TestMatcherGolang_GoVulnDB(t *testing.T) {
	// GO-2023-1840 declares stdlib vulnerable for everything below 1.19.10 (plus
	// a later [1.20.0, 1.20.5) window). The sub-1.19.10 cases below use a version
	// under 1.19.10, so 1840 matches each one on top of whatever GO-2022-0969
	// window it falls in.
	const stdlibBelow11910 = "GO-2023-1840"

	tests := []struct {
		name       string
		pkgName    string
		pkgVersion string
		expectIDs  []string // empty means no match expected
	}{
		{
			// GO-2022-0969 first window (< 1.18.6); also under GO-2023-1840's < 1.19.10.
			name:       "stdlib in first vulnerable window: GO-2022-0969 flags it",
			pkgName:    "stdlib",
			pkgVersion: "go1.18.0",
			expectIDs:  []string{"GO-2022-0969", stdlibBelow11910},
		},
		{
			// Past GO-2022-0969's first fix (1.18.6) but still below 1.19.10.
			name:       "stdlib past GO-2022-0969 first fix but still below GO-2023-1840 fix: only 1840 flags it",
			pkgName:    "stdlib",
			pkgVersion: "go1.18.6",
			expectIDs:  []string{stdlibBelow11910},
		},
		{
			// GO-2022-0969 second window ([1.19.0, 1.19.1)); still under 1.19.10.
			name:       "stdlib in second vulnerable window: GO-2022-0969 flags it",
			pkgName:    "stdlib",
			pkgVersion: "go1.19.0",
			expectIDs:  []string{"GO-2022-0969", stdlibBelow11910},
		},
		{
			// Past every stdlib window in the fixture: no match. Guards against
			// over-matching stdlib once non-stdlib records are out of the picture.
			name:       "stdlib past all fixed versions: no match",
			pkgName:    "stdlib",
			pkgVersion: "go1.25.0",
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

				if len(tt.expectIDs) == 0 {
					findings.IsEmpty()
					return
				}

				for _, id := range tt.expectIDs {
					findings.SelectMatch(id).
						SelectDetailByType(match.ExactDirectMatch).
						AsEcosystemSearch()
				}
			})
		}
	})
}

// TestMatcherGolang_GoVulnDB_GolangOrgX covers the golang.org/x/* extended
// standard libraries, which the transformer now emits alongside stdlib (they are
// versioned by the Go team and absent from GHSA, so they avoid the false-positive
// load that keeps general third-party Go modules out). GO-2022-0969 also lists
// golang.org/x/net as affected below the pseudo-version
// 0.0.0-20220906165146-f3363e06e74c, so a golang.org/x/net package under that fix
// must match and one at/after it must not.
func TestMatcherGolang_GoVulnDB_GolangOrgX(t *testing.T) {
	tests := []struct {
		name       string
		pkgName    string
		pkgVersion string
		expectIDs  []string // empty means no match expected
	}{
		{
			// pseudo-version older than GO-2022-0969's fix (a Feb 2022 commit
			// predates the Sep 2022 fix pseudo-version), so it is vulnerable.
			name:       "golang.org/x/net before fix pseudo-version: GO-2022-0969 flags it",
			pkgName:    "golang.org/x/net",
			pkgVersion: "v0.0.0-20220225172249-27dd8689420f",
			expectIDs:  []string{"GO-2022-0969"},
		},
		{
			// a tagged release well past the fix pseudo-version: no match.
			name:       "golang.org/x/net past fix: no match",
			pkgName:    "golang.org/x/net",
			pkgVersion: "v0.17.0",
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

				if len(tt.expectIDs) == 0 {
					findings.IsEmpty()
					return
				}

				for _, id := range tt.expectIDs {
					findings.SelectMatch(id).
						SelectDetailByType(match.ExactDirectMatch).
						AsEcosystemSearch()
				}
			})
		}
	})
}
