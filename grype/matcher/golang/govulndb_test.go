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
// Two fixtures cover the dominant record shapes:
//   - GO-2020-0001: a regular module (github.com/gin-gonic/gin) with a single
//     SEMVER range "< 1.6.0". Exercises the affected-package emission path
//     for non-stdlib modules.
//   - GO-2022-0969: stdlib with a multi-window SEMVER range
//     (< 1.18.6 || >=1.19.0-0,< 1.19.1). Exercises the multi-window range
//     normalization and confirms the matcher's ecosystem-name search finds
//     stdlib records (separate from the existing NVD CPE path).
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
