package opam

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcher exercises ecosystem matching of opam (OCaml)
// packages against real OSEC-* records from the OCaml security advisories, as
// written by the vunnel "ocamlsec" provider:
//
//   - OSEC-2017-01: ocaml {>= "4.04" & < "4.04.2"}, range [4.04.0, 4.04.2)
//   - OSEC-2026-01: ocaml {< "4.14.3" | >= "5" & < "5.4.1"}, ranges < 4.14.3 and [5.0.0, 5.4.1)
//   - OSEC-2026-28: GIT ranges only, so nothing in the DB to match
//
// The versions exercise the opam version ordering, e.g. "~" pre-releases sort
// before the release ("5.4.1~rc1" < "5.4.1", "5.0.0~alpha1" < "5.0.0").
func TestMatcher(t *testing.T) {
	tests := []struct {
		name     string
		pkgName  string
		version  string
		expected []string // expected OSEC-* IDs; empty asserts no matches
	}{
		{
			name:     "ocaml 4.04.1 is in both ranges",
			pkgName:  "ocaml",
			version:  "4.04.1",
			expected: []string{"OSEC-2017-01", "OSEC-2026-01"},
		},
		{
			name:     "ocaml 4.04.2 is fixed for OSEC-2017-01",
			pkgName:  "ocaml",
			version:  "4.04.2",
			expected: []string{"OSEC-2026-01"},
		},
		{
			name:    "ocaml 4.14.3 is fixed",
			pkgName: "ocaml",
			version: "4.14.3",
		},
		{
			name:    "ocaml 5.0.0~alpha1 is before the second range of OSEC-2026-01",
			pkgName: "ocaml",
			version: "5.0.0~alpha1",
		},
		{
			name:     "ocaml 5.0.0 is in the second range of OSEC-2026-01",
			pkgName:  "ocaml",
			version:  "5.0.0",
			expected: []string{"OSEC-2026-01"},
		},
		{
			name:     "ocaml 5.4.1~rc1 is before the fix",
			pkgName:  "ocaml",
			version:  "5.4.1~rc1",
			expected: []string{"OSEC-2026-01"},
		},
		{
			name:    "ocaml 5.4.1 is fixed",
			pkgName: "ocaml",
			version: "5.4.1",
		},
		{
			// not an opam version (an unreplaced build template), so no range can be evaluated
			name:    "ocaml with an invalid version doesn't match",
			pkgName: "ocaml",
			version: "%%VERSION%%",
		},
		{
			name:    "other packages don't match",
			pkgName: "lwt",
			version: "4.04.1",
		},
	}

	dbtest.DBs(t, "ocaml").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewOpamMatcher(MatcherConfig{})
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := dbtest.NewPackage(tt.pkgName, tt.version, syftPkg.OpamPkg).
					WithLanguage(syftPkg.OCaml).
					Build()

				findings := db.Match(t, matcher, p)
				if len(tt.expected) == 0 {
					findings.IsEmpty()
					return
				}
				for _, id := range tt.expected {
					findings.SelectMatch(id).
						SelectDetailByType(match.ExactDirectMatch).
						AsEcosystemSearch()
				}
			})
		}
	})
}

func TestMatcher_Fix(t *testing.T) {
	dbtest.DBs(t, "ocaml").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewOpamMatcher(MatcherConfig{})
		p := dbtest.NewPackage("ocaml", "5.3.0", syftPkg.OpamPkg).
			WithLanguage(syftPkg.OCaml).
			Build()

		db.Match(t, matcher, p).
			SelectMatch("OSEC-2026-01").
			InNamespace("ocamlsec:language:ocaml").
			// both ranges of the record are reported, with the fix of each
			HasFix(vulnerability.FixStateFixed, "4.14.3", "5.4.1").
			SelectDetailByType(match.ExactDirectMatch).
			AsEcosystemSearch("<4.14.3||>=5.0.0,<5.4.1 (opam)")
	})
}

func TestMatcher_Type(t *testing.T) {
	m := NewOpamMatcher(MatcherConfig{})
	assert.Equal(t, []syftPkg.Type{syftPkg.OpamPkg}, m.PackageTypes())
	assert.Equal(t, match.OpamMatcher, m.Type())
}

// TestMatcher_Cases covers record shapes the current advisories don't use and CPE
// matching, against the ocaml-cases fixture:
//
//   - OSEC-2017-01: ocaml >= 4.04.0, < 4.04.2 (alias CVE-2017-9772)
//   - OSEC-2026-05: withdrawn, so it never matches
//   - OSEC-2026-18: no fix yet (a lone introduced:0), so every version matches
//   - CVE-2017-9772 (NVD): cpe:2.3:a:ocaml:ocaml:4.04.0 and 4.04.1
func TestMatcher_Cases(t *testing.T) {
	dbtest.DBs(t, "ocaml-cases").Run(func(t *testing.T, db *dbtest.DB) {
		t.Run("unfixed advisory matches every version, withdrawn one never", func(t *testing.T) {
			p := dbtest.NewPackage("ocaml", "5.3.0", syftPkg.OpamPkg).WithLanguage(syftPkg.OCaml).Build()

			db.Match(t, NewOpamMatcher(MatcherConfig{}), p).
				SelectMatch("OSEC-2026-18").
				HasNoFixVersions().
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
		})

		t.Run("no CPE matching by default", func(t *testing.T) {
			p := dbtest.NewPackage("ocaml", "4.04.1", syftPkg.OpamPkg).
				WithLanguage(syftPkg.OCaml).
				WithCPE("cpe:2.3:a:ocaml:ocaml:4.04.1:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, NewOpamMatcher(MatcherConfig{}), p)
			findings.SelectMatch("OSEC-2017-01").
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
			findings.SelectMatch("OSEC-2026-18").
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
		})

		t.Run("CPE matching with using-cpes", func(t *testing.T) {
			p := dbtest.NewPackage("ocaml", "4.04.1", syftPkg.OpamPkg).
				WithLanguage(syftPkg.OCaml).
				WithCPE("cpe:2.3:a:ocaml:ocaml:4.04.1:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, NewOpamMatcher(MatcherConfig{UseCPEs: true}), p)
			findings.SelectMatch("OSEC-2017-01").
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
			findings.SelectMatch("OSEC-2026-18").
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
			findings.SelectMatch("CVE-2017-9772").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})
	})
}
