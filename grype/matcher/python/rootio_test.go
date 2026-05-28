package python

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherPython_RootIO drives rootio matching for PyPI packages
// through a DB that mixes rootio NAK records and the matching GHSA
// disclosures keyed under the bare PyPI name.
//
// Two real-world packages cover the scenarios:
//   - apache-airflow-providers-google (CVE-2023-25691 / GHSA-8g23-2q5p-8866):
//     GHSA flags any version < 8.10.0 as vulnerable; rootio backports a fix
//     at 8.1.0+root.io.1. Below the rootio fix the bare-name fanout finds
//     the GHSA disclosure; at the rootio fix the NAK suppresses it.
//   - langgraph-checkpoint (CVE-2025-64439 / GHSA-wwqv-p2pp-99h5): GHSA
//     range < 3.0.0; rootio fix at 2.1.0+root.io.1.
//
// Matches surface under the GHSA primary ID with the CVE as alias. NAK
// suppression emits one IgnoreRule per alias on the rootio record —
// rootio's own ID, the CVE, and the GHSA — under reason
// "UnaffectedPackageEntry".
func TestMatcherPython_RootIO(t *testing.T) {
	tests := []struct {
		name              string
		pkgName           string
		pkgVersion        string
		expectGHSA        string     // primary match ID; empty means no match
		expectType        match.Type // ignored when expectGHSA is empty
		expectSuppressIDs []string   // IgnoreRule IDs when the NAK fires
	}{
		{
			// apache-airflow-providers-google: rootio fix 8.1.0+root.io.1.
			// At 8.0.0 the package is below rootio fix; the GHSA flags it.
			name:       "rootio-apache-airflow-providers-google below rootio fix: GHSA flags it",
			pkgName:    "rootio-apache-airflow-providers-google",
			pkgVersion: "8.0.0",
			expectGHSA: "GHSA-8g23-2q5p-8866",
			expectType: match.ExactDirectMatch,
		},
		{
			// At the rootio fix the NAK suppresses the GHSA. The rootio
			// version is still inside GHSA's range (8.1.0+root.io.1 <
			// 8.10.0), so the NAK is what's doing the work.
			name:       "rootio-apache-airflow-providers-google at rootio fix: NAK suppresses",
			pkgName:    "rootio-apache-airflow-providers-google",
			pkgVersion: "8.1.0+root.io.1",
			// IgnoreRule fans out across the rootio NAK's own aliases:
			// the rootio record ID and the upstream CVE. The GHSA ID
			// lives on the upstream disclosure, not on the rootio NAK,
			// so it isn't in the alias unwind for this ignore.
			expectSuppressIDs: []string{
				"ROOT-APP-PYPI-CVE-2023-25691",
				"CVE-2023-25691",
			},
		},
		{
			name:       "rootio-langgraph-checkpoint below rootio fix: GHSA flags it",
			pkgName:    "rootio-langgraph-checkpoint",
			pkgVersion: "2.0.0",
			expectGHSA: "GHSA-wwqv-p2pp-99h5",
			expectType: match.ExactDirectMatch,
		},
		{
			name:       "rootio-langgraph-checkpoint at rootio fix: NAK suppresses",
			pkgName:    "rootio-langgraph-checkpoint",
			pkgVersion: "2.1.0+root.io.1",
			expectSuppressIDs: []string{
				"ROOT-APP-PYPI-CVE-2025-64439",
				"CVE-2025-64439",
			},
		},
		{
			// A regular (non-rootio) langgraph-checkpoint at a vulnerable
			// version matches the GHSA disclosure directly.
			name:       "regular langgraph-checkpoint vulnerable: direct GHSA match",
			pkgName:    "langgraph-checkpoint",
			pkgVersion: "2.0.0",
			expectGHSA: "GHSA-wwqv-p2pp-99h5",
			expectType: match.ExactDirectMatch,
		},
		{
			// Past the GHSA fix range, the regular package is clean and
			// the rootio NAK keyed under the rootio-prefixed name never
			// reaches a non-rootio scan.
			name:       "regular langgraph-checkpoint past upstream fix: no match",
			pkgName:    "langgraph-checkpoint",
			pkgVersion: "3.0.0",
		},
		{
			name:       "unrelated package: nothing",
			pkgName:    "requests",
			pkgVersion: "2.31.0",
		},
	}

	dbtest.DBs(t, "rootio-pypi").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewPythonMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.PythonPkg).
					WithLanguage(syftPkg.Python).
					Build()

				findings := db.Match(t, matcher, p)

				if tt.expectGHSA == "" && len(tt.expectSuppressIDs) == 0 {
					findings.IsEmpty()
					return
				}

				if tt.expectGHSA != "" {
					findings.SelectMatch(tt.expectGHSA).
						SelectDetailByType(tt.expectType).
						AsEcosystemSearch()
				}

				if len(tt.expectSuppressIDs) > 0 {
					ignores := findings.Ignores()
					for _, id := range tt.expectSuppressIDs {
						ignores.SelectIgnoreRule("UnaffectedPackageEntry", id).
							ForPackage(tt.pkgName, tt.pkgVersion).
							IncludesAliases()
					}
				}
			})
		}
	})
}
