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

// TestMatcher_NoVersion checks that a package without a version (e.g. a
// project's own <name>.opam file without a version field) isn't matched:
// without a version it would match every vulnerability of its name.
func TestMatcher_NoVersion(t *testing.T) {
	dbtest.DBs(t, "ocaml").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewOpamMatcher(MatcherConfig{})
		for _, v := range []string{"", " "} {
			p := dbtest.NewPackage("ocaml", v, syftPkg.OpamPkg).
				WithLanguage(syftPkg.OCaml).
				Build()

			db.Match(t, matcher, p).IsEmpty()
		}
	})
}

func TestMatcher_Type(t *testing.T) {
	m := NewOpamMatcher(MatcherConfig{})
	assert.Equal(t, []syftPkg.Type{syftPkg.OpamPkg}, m.PackageTypes())
	assert.Equal(t, match.OpamMatcher, m.Type())
}
