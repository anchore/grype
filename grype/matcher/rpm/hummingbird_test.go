package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The hummingbird CSAF VEX provider discloses at binary-RPM granularity. Real advisories
// commonly list both the source RPM (e.g. `glibc.src`) and a sibling binary of the same
// name (`glibc`) plus other binaries (`glibc-common`) under the hummingbird platform. Two
// build-time changes keep this from polluting upstream-indirected matches:
//
//  1. The csafvex transformer drops a src product when a same-named binary is also in the
//     advisory's known_affected ∪ fixed for the same platform.
//  2. Every emitted RPM-typed entry is tagged with rpmarch ("src" / "binary-no-arch-specified"
//     / a literal arch). The RPM matcher's upstream-search path adds
//     internal.SourceOrUnspecifiedArch() so any non-src tagged entry is excluded — direct
//     matches still hit because that path doesn't apply the criterion.
//
// These tests exercise the end-to-end build → match flow against a real fixture
// (cve-2026-5928) extracted from the local hummingbird vunnel cache.

// TestHummingbirdMatching_BinaryDirectHit verifies that a binary RPM listed verbatim in a
// hummingbird advisory's known_affected (`glibc`) still produces a direct match — the
// rpmarch=binary-no-arch-specified tag does NOT block direct lookups.
func TestHummingbirdMatching_BinaryDirectHit(t *testing.T) {
	dbtest.DBs(t, "hummingbird").
		SelectOnly("cve-2026-5928").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("glibc", "2.42-11.1.hum1", syftPkg.RpmPkg).
				WithDistro(dbtest.Hummingbird1).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2026-5928").
				InNamespace("hummingbird:distro:hummingbird:1").
				SelectDetailByDistro("hummingbird", "1").
				HasMatchType(match.ExactDirectMatch)
		})
}

// TestHummingbirdMatching_SiblingBinaryUpstreamFiltered is the regression test for the
// reported FP: glibc-minimal-langpack is built from glibc.src but is NOT named in the
// advisory. Without our changes, grype's upstream search (name=glibc, derived from the
// package's `upstream` field) would hit the binary `glibc` row in the DB and emit an
// indirect match. With rpmarch tagging + SourceOrUnspecifiedArch, the upstream search
// excludes the binary row, and there's no glibc-minimal-langpack entry to direct-match,
// so no match is produced.
func TestHummingbirdMatching_SiblingBinaryUpstreamFiltered(t *testing.T) {
	dbtest.DBs(t, "hummingbird").
		SelectOnly("cve-2026-5928").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("glibc-minimal-langpack", "2.42-11.1.hum1", syftPkg.RpmPkg).
				WithDistro(dbtest.Hummingbird1).
				WithUpstream("glibc", "2.42-11.1.hum1").
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// TestHummingbirdMatching_GlibcCommonDirectOnly verifies that glibc-common — which IS in
// the advisory at binary granularity AND has upstream=glibc — produces exactly one match
// via the direct path. The upstream search (name=glibc) is filtered out by the new
// criterion, so glibc-common doesn't get double-reported with both direct and indirect
// match details.
func TestHummingbirdMatching_GlibcCommonDirectOnly(t *testing.T) {
	dbtest.DBs(t, "hummingbird").
		SelectOnly("cve-2026-5928").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("glibc-common", "2.42-11.1.hum1", syftPkg.RpmPkg).
				WithDistro(dbtest.Hummingbird1).
				WithUpstream("glibc", "2.42-11.1.hum1").
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2026-5928").
				SelectDetailByDistro("hummingbird", "1").
				HasMatchType(match.ExactDirectMatch)
		})
}

// TestHummingbirdMatching_PerlBDirectFix is the perl-flavored counterpart to the glibc-
// common test. CVE-2018-18311 is a "fixed" advisory: hummingbird lists the entire perl-*
// binary fan-out (perl, perl-B, perl-Errno, ...) at binary granularity with explicit fix
// versions, and no hummingbird-1 src product. Real perl-B RPMs carry upstream=perl in
// their RPM metadata, so without the upstream-arch filter scanning a vulnerable perl-B
// would also pick up an indirect match against the binary `perl` entry (different fix
// version, doubled-up match details). With the filter in place, only the direct match on
// perl-B's own entry survives.
func TestHummingbirdMatching_PerlBDirectFix(t *testing.T) {
	dbtest.DBs(t, "hummingbird").
		SelectOnly("cve-2018-18311").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// perl-B fix is 1.89-524.1.hum1; scan a slightly older build so the version
			// constraint actually fires. upstream=perl at a perl version below the perl
			// binary's own fix (5.42.2-524.1.hum1) — without the filter the upstream
			// search would indirect-match via the perl entry.
			p := dbtest.NewPackage("perl-B", "1.85-524.1.hum1", syftPkg.RpmPkg).
				WithDistro(dbtest.Hummingbird1).
				WithUpstream("perl", "5.42.0-524.1.hum1").
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2018-18311").
				InNamespace("hummingbird:distro:hummingbird:1").
				SelectDetailByDistro("hummingbird", "1").
				HasMatchType(match.ExactDirectMatch)
		})
}
