package stock

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherStock_CPAN drives the whole grype-side Perl path against a real database built
// from the CPANSA records vunnel's `cpan` provider emits: OSV record -> CPANSA transformer ->
// v6 database -> matcher. The transformer tests stop at the entry and the version tests stop
// at the comparator, so this is the only place the pieces are checked together.
//
// CPAN packages have no dedicated matcher; they fall through to stock, which searches by
// ecosystem and package name. What makes them interesting is entirely in the data:
//
//   - Perl version ordering. 4.09 > 4.10 is wrong everywhere else and right here, and perl
//     writes its own version three different ways (5.22.1, 5.022001, v5.22.1) which all have
//     to resolve to the same point on a range.
//   - Advisories with no CVE at all. CPANSA ids are the primary key; a pipeline that assumes
//     a CVE exists loses roughly two thirds of the database.
//   - One id carrying many disjoint version windows, because upstream files one entry per
//     slice of the affected range.
//   - Distribution names, not module names, and case sensitively.
func TestMatcherStock_CPAN(t *testing.T) { //nolint:funlen // table-driven CPAN version and naming cases
	tests := []struct {
		name       string
		pkgName    string
		pkgVersion string
		expect     []string
	}{
		{
			// ordinary bounded range carrying a CVE alias, plus the later Mojolicious advisory
			name: "Mojolicious below both fixes", pkgName: "Mojolicious", pkgVersion: "9.10",
			expect: []string{"CPANSA-Mojolicious-2021-01", "CPANSA-Mojolicious-2022-03"},
		},
		{
			// the fixed bound is exclusive, so 9.11 clears the 2021 advisory exactly
			name: "Mojolicious at the 2021 fix", pkgName: "Mojolicious", pkgVersion: "9.11",
			expect: []string{"CPANSA-Mojolicious-2022-03"},
		},
		{
			// CPANSA-Mojolicious-2022-03 has `cves: []` and is only ever reachable under its
			// CPANSA id
			name: "advisory with no CVE at all", pkgName: "Mojolicious", pkgVersion: "9.30",
			expect: []string{"CPANSA-Mojolicious-2022-03"},
		},
		{
			name: "Mojolicious above every fix", pkgName: "Mojolicious", pkgVersion: "9.31",
		},
		{
			// the perl interpreter is an ordinary CPAN distribution to CPANSA. CPANSA writes
			// perl's release history in decimal form and its advisories in dotted form, so
			// these two rows are the same version and both have to land the same way. A string
			// compare finds neither; a semver compare finds the wrong set.
			//
			// CPANSA-perl-2026-57432 rides along on every perl row below: its lowest window is
			// open at the bottom (0 -> 5.040005), so every perl the fixture knows about is
			// inside it.
			name: "perl interpreter, decimal form", pkgName: "perl", pkgVersion: "5.022001",
			expect: []string{"CPANSA-ExtUtils-ParseXS-2016-1238", "CPANSA-perl-2015-8608", "CPANSA-perl-2016-6185", "CPANSA-perl-2026-57432"},
		},
		{
			name: "perl interpreter, dotted form", pkgName: "perl", pkgVersion: "5.22.1",
			expect: []string{"CPANSA-ExtUtils-ParseXS-2016-1238", "CPANSA-perl-2015-8608", "CPANSA-perl-2016-6185", "CPANSA-perl-2026-57432"},
		},
		{
			// CPANSA starts CVE-2016-6185 at 5.22.0 where NVD starts it at 5.23.0. That is a
			// data disagreement between the two sources, not a matching bug.
			name: "perl interpreter at the 2016-6185 fix", pkgName: "perl", pkgVersion: "5.024000",
			expect: []string{"CPANSA-ExtUtils-ParseXS-2016-1238", "CPANSA-perl-2026-57432"},
		},
		{
			// CPANSA-perl-2015-8608 carries two disjoint affected windows upstream, but its
			// fixed_versions of ">=5.22.2" subtracts the whole second one. That is what
			// CPAN::Audit itself computes, so the emitted record has a single 0 -> 5.022002
			// window and a 5.23.x perl is genuinely not affected by it.
			name: "perl 5.023001 sits outside the 2015-8608 window", pkgName: "perl", pkgVersion: "5.023001",
			expect: []string{"CPANSA-ExtUtils-ParseXS-2016-1238", "CPANSA-perl-2016-6185", "CPANSA-perl-2026-57432"},
		},
		{
			// 65 upstream entries under one id, unioned into three windows. One advisory, not 65.
			name: "one id, many windows: inside the first", pkgName: "DBD-SQLite", pkgVersion: "1.20_01",
			expect: []string{"CPANSA-DBD-SQLite-2018-8740-sqlite"},
		},
		{
			// the `=1.05` entry, a form upstream's own range regex fails to match
			name: "one id, many windows: the single-equals entry", pkgName: "DBD-SQLite", pkgVersion: "1.05",
			expect: []string{"CPANSA-DBD-SQLite-2018-8740-sqlite"},
		},
		{
			// an underscore version is an ordinary CPAN version, not a semver pre-release, and
			// 1.59_01 is the exclusive upper bound of the last window
			name: "one id, many windows: at the alpha upper bound", pkgName: "DBD-SQLite", pkgVersion: "1.59_01",
		},
		{
			name: "one id, many windows: in the gap between two", pkgName: "DBD-SQLite", pkgVersion: "1.35",
		},
		{
			// NVD records CVE-2011-0633 under vendor `gisle_aas` with versions enumerated one
			// CPE at a time, so the CPE path cannot reach it. CPANSA expresses it as a range.
			name: "libwww-perl the CPE path misses", pkgName: "libwww-perl", pkgVersion: "5.836",
			expect: []string{"CPANSA-libwww-perl-2011-01", "CPANSA-libwww-perl-2017-01", "CPANSA-libwww-perl-2026-8368"},
		},
		{
			name: "libwww-perl as debian bookworm ships it", pkgName: "libwww-perl", pkgVersion: "6.68",
			expect: []string{"CPANSA-libwww-perl-2026-8368"},
		},
		{
			// 4.09 is v4.90.0 and 4.10 is v4.100.0 under perl rules, so 4.09 really is the
			// lower version. Every other ecosystem grype knows orders these the other way.
			name: "decimal ordering at a real boundary", pkgName: "CGI-Session", pkgVersion: "4.09",
			expect: []string{"CPANSA-CGI-Session-2006-01", "CPANSA-CGI-Session-2006-1279", "CPANSA-CGI-Session-2026-56016"},
		},
		{
			name: "decimal ordering, one past the boundary", pkgName: "CGI-Session", pkgVersion: "4.10",
			expect: []string{"CPANSA-CGI-Session-2006-01", "CPANSA-CGI-Session-2026-56016"},
		},
		{
			// CPAN distribution names are case sensitive, and this does NOT hold: the v6
			// package name index is declared `collate:NOCASE` for every ecosystem
			// (grype/db/v6/models.go), so the lookup folds case before the cpan strategy ever
			// sees it. Registering no name normalizer for `cpan` is necessary but not
			// sufficient. Pinned here as the real behavior so a change to it is deliberate.
			name:    "wrong case still matches, because v6 name lookup is NOCASE",
			pkgName: "mojolicious", pkgVersion: "9.10",
			expect: []string{"CPANSA-Mojolicious-2021-01", "CPANSA-Mojolicious-2022-03"},
		},
		{
			// LWP is libwww-perl's main module, and a CPAN.pm install lands at
			// auto/LWP/.packlist, so LWP is the only name syft has to report. The advisory
			// data carries an alias for exactly this case; see
			// TestMatcherStock_CPAN_MainModuleAlias.
			name: "main module name matches through the alias", pkgName: "LWP", pkgVersion: "5.836",
			expect: []string{"CPANSA-libwww-perl-2011-01", "CPANSA-libwww-perl-2017-01", "CPANSA-libwww-perl-2026-8368"},
		},
	}

	dbtest.DBs(t, "cpansa").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewStockMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := newCpanPackage(tt.pkgName, tt.pkgVersion)

				// SkipCompleteness: these rows assert the whole result set by id rather than
				// drilling into each match's details, which is what the completeness check
				// wants to see.
				findings := db.Match(t, matcher, p).SkipCompleteness()
				if len(tt.expect) == 0 {
					findings.IsEmpty()
					return
				}
				findings.OnlyHasVulnerabilities(tt.expect...)
			})
		}
	})
}

// TestMatcherStock_CPAN_FromImageSBOM closes the loop TestMatcherStock_CPAN leaves open. Those
// rows hand-build grype packages, so they assert what syft is *assumed* to report: the name, the
// version string, the `cpan` type and the `perl` language are all typed in by the test. This one
// starts from a real syft SBOM of the `cpan-fixture` image instead, so the same database is driven
// by whatever the cataloger actually emits.
//
// That covers the seam between the two, which nothing else does:
//
//   - distributions, not modules. `libwww-perl` installs `LWP.pm`, and an SBOM that named the
//     module would match nothing here while looking perfectly healthy.
//   - the perl interpreter arrives as a `cpan` package from the binary classifier rather than a
//     `binary` one, which is what makes its 46 CPANSA advisories reachable at all.
//   - the version strings are the ones on disk (`5.836`, `4.09`, `v1.1.4`), not ones chosen to
//     exercise a comparator.
//
// The fixture is `syft scan cpan-fixture:latest -o syft-json` filtered to the `cpan` artifacts and
// the relationships among them. The image's 158 deb packages and the whole file catalog are
// dropped: no CPANSA advisory can reach them, and they were 97% of the bytes.
func TestMatcherStock_CPAN_FromImageSBOM(t *testing.T) {
	// every finding the image is expected to produce against the cpansa fixture database. The 47
	// other cpan packages in the SBOM must produce nothing; CPANSA covers 388 of CPAN's ~44,000
	// distributions, so that is the normal outcome and not a broken matcher.
	expected := map[string][]string{
		"CGI-Session@4.09": {
			"CPANSA-CGI-Session-2006-01",
			"CPANSA-CGI-Session-2006-1279",
			"CPANSA-CGI-Session-2026-56016",
		},
		"Mojolicious@9.10": {
			"CPANSA-Mojolicious-2021-01",
			"CPANSA-Mojolicious-2022-03",
		},
		"libwww-perl@5.836": {
			"CPANSA-libwww-perl-2011-01",
			"CPANSA-libwww-perl-2017-01",
			"CPANSA-libwww-perl-2026-8368",
		},
		// the interpreter, all the way through. Identity and matching used to be split across two
		// tests: this one proved perl arrives as a cpan package, and TestMatcherStock_CPAN proved a
		// perl version could match, but only for a hand-typed 5.022001. Nothing drove the real
		// binary-classifier output against a real advisory until CPANSA-perl-2026-57432 (still open
		// below 5.40.5) was added to the fixture, which the shipped 5.40.4 is inside.
		"perl@5.40.4": {
			"CPANSA-perl-2026-57432",
		},
	}

	cpanPkgs := cpanPackagesFromImageSBOM(t)

	names := make(map[string]struct{}, len(cpanPkgs))
	for _, p := range cpanPkgs {
		names[p.Name] = struct{}{}
	}
	// the two guards worth keeping on the syft side of the seam. `libwww-perl` was installed with
	// cpanm, which writes an install.json, so syft has the real distribution name and must use it
	// rather than falling back to the packlist path. The advisory-side alias covers installs where
	// only the packlist exists (TestMatcherStock_CPAN_MainModuleAlias); it is a safety net, not a
	// licence for syft to report module names. A missing `perl` means the interpreter went back to
	// being a `binary` package.
	require.NotContains(t, names, "LWP")
	require.Contains(t, names, "perl")

	dbtest.DBs(t, "cpansa").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewStockMatcher(MatcherConfig{})

		for _, p := range cpanPkgs {
			key := p.Name + "@" + p.Version
			t.Run(key, func(t *testing.T) {
				findings := db.Match(t, matcher, p).SkipCompleteness()
				if expect, ok := expected[key]; ok {
					findings.OnlyHasVulnerabilities(expect...)
					return
				}
				findings.IsEmpty()
			})
		}
	})
}

// TestMatcherStock_CPAN_CPANSAAndNVDOnTheSameCVE pins what happens when both halves of the stock
// matcher reach the same underlying vulnerability for the same cpan package.
//
// The fixture database carries CPANSA-perl-2026-57432 under the `cpan` provider and NVD's
// CVE-2026-57432 (which the CPANSA record lists as its only alias) under `nvd`. Both cover the
// interpreter the `cpan-fixture` image ships: the CPANSA record's lowest window is open below
// 5.40.5, and NVD's single CPE is `cpe:2.3:a:perl:perl:*` up to and including 5.43.10. The package
// is the real SBOM one, so the CPE the NVD path matches on is the one the nvd-cpe-dictionary
// assigned perl, not one typed in here.
//
// The result is two findings, not one, and that is the real behavior rather than the desired one.
// Deduplication is keyed on vulnerability ID, namespace and package (grype/match/fingerprint.go),
// and `CPANSA-perl-2026-57432` in `cpan` is not `CVE-2026-57432` in `nvd:cpe` on any of the three.
// Collapsing the two requires normalizeByCVE (grype/vulnerability_matcher.go), which only runs
// under `--by-cve` and sits above every matcher. So the duplicate is structural to CPANSA using its
// own ids: all 46 of perl's CPANSA advisories carry a CVE alias, and each one is a second row on any
// perl that NVD also covers.
func TestMatcherStock_CPAN_CPANSAAndNVDOnTheSameCVE(t *testing.T) {
	var perl pkg.Package
	for _, p := range cpanPackagesFromImageSBOM(t) {
		if p.Name == "perl" {
			perl = p
		}
	}
	require.Equal(t, "5.40.4", perl.Version)
	require.NotEmpty(t, perl.CPEs, "the CPE path cannot fire without a CPE on the package")

	dbtest.DBs(t, "cpansa").Run(func(t *testing.T, db *dbtest.DB) {
		// UseCPEs is what grype runs the stock matcher with in production
		// (grype/vulnerability_matcher.go), and it is the only way the nvd rows are reachable
		matcher := NewStockMatcher(MatcherConfig{UseCPEs: true})

		matches, ignores, err := matcher.Match(db, perl)
		require.NoError(t, err)
		require.Empty(t, ignores)

		// the matcher only concatenates its two result sets; deduplication happens when they land
		// in match.Matches, so assert on the far side of that rather than on the raw slice
		deduped := match.NewMatches(matches...)
		require.Equal(t, len(matches), deduped.Count(), "matches merged unexpectedly")

		findings := dbtest.AssertFindings(t, deduped.Sorted(), perl)
		findings.SelectMatch("CPANSA-perl-2026-57432").
			// the same CVE the other finding is keyed by, which is what makes these duplicates
			HasRelatedVulnerabilities("CVE-2026-57432").
			SelectDetailByEcosystem("perl")
		findings.SelectMatch("CVE-2026-57432").
			SelectDetailByCPE("cpe:2.3:a:perl:perl:5.40.4:*:*:*:*:*:*:*").
			FoundCPEs("cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*")
	})
}

// TestMatcherStock_CPAN_MainModuleAlias covers the naming problem that can make a whole
// distribution's advisories unreachable, and the deliberately narrow fix for it.
//
// A CPAN.pm install of libwww-perl lands at `auto/LWP/.packlist`, because the packlist path is
// built from the builder's NAME and libwww-perl's Makefile.PL overrides that to `LWP`. CPAN.pm
// writes no install.json, so a packlist is all syft has to go on and the package is reported as
// `LWP`. CPANSA keys every advisory by distribution, so `LWP` matches nothing, and libwww-perl's
// advisories are unreachable on exactly the install layout that produces the name.
//
// The advisory data carries the fix rather than syft: each advisory gets an extra affected package
// named for the distribution's `main_module` with `::` replaced by `-`, carrying the same resolved
// ranges. That is sound only because every version syft emits for a cpan package is a distribution
// version, so `LWP@5.836` really does mean libwww-perl 5.836.
//
// What this pins:
//
//   - the alias is reachable, at the same constraint as the distribution it came from.
//   - it is the data doing the work. No name resolver is registered for `cpan`, so nothing on
//     grype's side could turn `LWP` into `libwww-perl`.
//   - it is `main_module` only. Aliasing every entry of CPANSA's module2dist table instead would
//     emit names no installer ever writes (`LWP-UserAgent`, or `URI-Escape` for the URI
//     distribution), multiplying records and widening the name-collision surface without covering
//     one additional real install.
//   - it adds nothing when the main module round-trips, which is the common case. Only 15 of
//     CPANSA's 409 distributions dash out to a different name.
func TestMatcherStock_CPAN_MainModuleAlias(t *testing.T) { //nolint:funlen // one row per advisory in the fixture
	// every advisory in the fixture, and the exact set of cpan package names it is filed against.
	// Asserting the whole set rather than probing for `LWP` is what pins the narrowing: aliasing
	// the module table would show up here as extra names on Mojolicious, DBD-SQLite and perl.
	//
	// The two empty entries are advisories the transformer drops whole because every affected
	// entry resolved to no ranges, alias included.
	affectedNames := map[string][]string{
		// main module `CGI::Session` dashes back to the distribution name, so no alias
		"CPANSA-CGI-Session-2006-01":          {"CGI-Session"},
		"CPANSA-CGI-Session-2006-1279":        {"CGI-Session"},
		"CPANSA-CGI-Session-2026-56016":       {"CGI-Session"},
		"CPANSA-Data-FormValidator-2011-2201": {"Data-FormValidator"},
		"CPANSA-DBD-SQLite-2018-8740-sqlite":  {"DBD-SQLite"},
		// two distributions on one id, and neither is an alias of the other
		"CPANSA-ExtUtils-ParseXS-2016-1238": {"ExtUtils-ParseXS", "perl"},
		"CPANSA-libwww-perl-1995-01":        nil,
		"CPANSA-libwww-perl-2001-01":        {"libwww-perl", "LWP"},
		"CPANSA-libwww-perl-2010-01":        {"libwww-perl", "LWP"},
		"CPANSA-libwww-perl-2011-01":        {"libwww-perl", "LWP"},
		"CPANSA-libwww-perl-2017-01":        {"libwww-perl", "LWP"},
		"CPANSA-libwww-perl-2026-8368":      {"libwww-perl", "LWP"},
		// main module is identical to the distribution name
		"CPANSA-Mojolicious-2021-01": {"Mojolicious"},
		"CPANSA-Mojolicious-2022-03": {"Mojolicious"},
		// perl's own main module is `perl`, so it round-trips. An earlier survey of this using
		// MetaCPAN's main_module as a stand-in reported perl aliasing to `less`; CPANSA's own
		// field, which is the one being read, says otherwise.
		"CPANSA-perl-2015-8608":  {"perl"},
		"CPANSA-perl-2016-6185":  {"perl"},
		"CPANSA-perl-2026-57432": {"perl"},
		// empty main_module, so nothing is guessed
		"CPANSA-urxvt-bgdsl-2022-4170": nil,
	}

	dbtest.DBs(t, "cpansa").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewStockMatcher(MatcherConfig{})

		t.Run("only main modules are aliased", func(t *testing.T) {
			for id, want := range affectedNames {
				vulns, err := db.FindVulnerabilities(search.ByID(id))
				require.NoError(t, err)

				var got []string
				for _, v := range vulns {
					got = append(got, v.PackageName)
				}
				assert.ElementsMatch(t, want, got, "unexpected affected packages for %s", id)
			}
		})

		t.Run("the alias carries the distribution's ranges", func(t *testing.T) {
			for id, names := range affectedNames {
				if !slices.Contains(names, "LWP") {
					continue
				}
				vulns, err := db.FindVulnerabilities(search.ByID(id))
				require.NoError(t, err)
				require.Len(t, vulns, 2, "%s should carry the distribution and its alias", id)

				constraints := make(map[string]string, len(vulns))
				for _, v := range vulns {
					constraints[v.PackageName] = v.Constraint.String()
				}
				// identical, not merely overlapping: the alias is the same advisory seen under a
				// second name, so any divergence here is a provider bug
				assert.Equal(t, constraints["libwww-perl"], constraints["LWP"], "ranges diverged on %s", id)
			}
		})

		t.Run("the packlist name matches, without any name rewriting", func(t *testing.T) {
			alias := newCpanPackage("LWP", "5.836")

			// no resolver is registered for `cpan` in grype/db/v6/name, so the name searched for
			// is the one syft reported. If this ever grows a second entry the match below stops
			// saying anything about the alias.
			require.Equal(t, []string{"LWP"}, db.PackageSearchNames(alias))

			expect := []string{"CPANSA-libwww-perl-2011-01", "CPANSA-libwww-perl-2017-01", "CPANSA-libwww-perl-2026-8368"}
			db.Match(t, matcher, alias).SkipCompleteness().OnlyHasVulnerabilities(expect...)
			db.Match(t, matcher, newCpanPackage("libwww-perl", "5.836")).SkipCompleteness().OnlyHasVulnerabilities(expect...)

			// the alias is bounded the same way the distribution is, so it clears the fixes at
			// the same versions rather than reporting forever
			db.Match(t, matcher, newCpanPackage("LWP", "6.83")).SkipCompleteness().IsEmpty()
		})

		t.Run("other modules of an affected distribution find nothing", func(t *testing.T) {
			// both are modules libwww-perl provides, so both are entries in CPANSA's module2dist
			// table, and neither is a name a CPAN client ever writes to disk
			for _, name := range []string{"LWP-UserAgent", "LWP-Simple"} {
				db.Match(t, matcher, newCpanPackage(name, "5.836")).SkipCompleteness().IsEmpty()
			}
		})
	})
}

// newCpanPackage builds the grype package syft reports for an installed CPAN distribution.
func newCpanPackage(name, version string) pkg.Package {
	// TODO: use syftPkg.CpanPkg / syftPkg.Perl once the syft release carrying them is vendored
	return dbtest.NewPackage(name, version, syftPkg.Type("cpan")).
		WithLanguage(syftPkg.Language("perl")).
		Build()
}

// cpanPackagesFromImageSBOM returns the cpan packages of the `cpan-fixture` image SBOM as grype's
// own package provider hands them to a matcher, so callers get whatever the syft cataloger emitted
// rather than a hand-built approximation of it.
func cpanPackagesFromImageSBOM(t *testing.T) []pkg.Package {
	t.Helper()

	pkgs, _, _, err := pkg.Provide("sbom:testdata/cpan-fixture-sbom.json", pkg.ProviderConfig{})
	require.NoError(t, err)

	var cpanPkgs []pkg.Package
	for _, p := range pkgs {
		// TODO: use syftPkg.CpanPkg / syftPkg.Perl once the syft release carrying them is vendored
		if p.Type != syftPkg.Type("cpan") {
			continue
		}
		require.Equal(t, syftPkg.Language("perl"), p.Language, "%s lost its language crossing into grype", p.Name)
		cpanPkgs = append(cpanPkgs, p)
	}
	require.NotEmpty(t, cpanPkgs)

	return cpanPkgs
}
