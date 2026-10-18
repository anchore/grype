package apk

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The chainguard-split-state fixture mirrors prometheus-3.7 / CVE-2026-39828 in the feed: one
// package, one CVE, two CGAs for two bundled binaries. One says "detection" (triage unfinished,
// fix state left unknown), the other "fix_not_planned" (wont-fix). Once both are named after the
// CVE they collapse into one finding, and that finding must not be easier to ignore than the
// "detection" record was on its own: `--ignore-states wont-fix` would drop it entirely.
func TestMatcherApk_SplitComponentStatusDoesNotPromoteToWontFix(t *testing.T) {
	dbtest.DBs(t, "chainguard-split-state").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		p := dbtest.NewPackage("splitpkg", "1.0.0-r0", syftPkg.ApkPkg).
			WithDistro(dbtest.ChainguardRolling).
			WithArchitecture("x86_64").
			Build()

		findings := db.Match(t, &matcher, p)

		findings.SelectMatch("CVE-2026-39901").
			SelectDetailByType(match.ExactDirectMatch).
			AsDistroSearch()
		for _, m := range findings.Matches() {
			require.NotEqual(t, vulnerability.FixStateWontFix, m.Vulnerability.Fix.State,
				"one CGA is still in triage, so the merged finding must not be ignorable as wont-fix")
		}
	})
}
